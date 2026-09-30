# ai-env — build/test driver for the classic tool and the MicroVM bridge.
# Style: DFST/monitoring/Makefile (`make help` lists targets from `## comments`).
.PHONY: help build check-bins test test-aws test-aws-readonly s4-smoke perf-wrapper install vm-build vm-run check-features check-deps check-msrv coverage fmt fmt-diff clippy lint lint-negative gates acceptance clean \
        claude-pin image-stage-scan image-zip image-build-local image-run-local test-docker check-base-image s3-preflight

SHELL        := /bin/bash
# The switches that delete, rotate, write, pick a version, skip a gate or widen a live run (YES, KEEP, VERSION, ROTATE,
# WRITE, CONFIRM, RECORD_PROBE, FOLLOW, EXPECT_BUILD_FAILURE, SLOW, PROBES) count only when given on the make command line (`make image-prune YES=1`;
# a sub-make inherits them): the same name exported in the environment is ignored. $(call cmdline,NAME) is the value, or empty.
cmdline       = $(if $(filter command line,$(origin $(1))),$($(1)))
STACK        ?= dev
TOOLCHAIN    ?= 1.98.1
# ai-env-age declares rust-version = "1.88"; keep in sync with crates/ai-env-age/Cargo.toml.
MSRV_OLD     ?= 1.88
PKG          := ai-env-cli
TARGET       ?= aarch64-unknown-linux-gnu
# AL2023 ships glibc 2.34; cargo-lambda's arm64 build targets an older glibc (2.30 observed).
GLIBC_MAX    ?= 2.34
# cargo-lambda below this embeds a cargo-zigbuild that cannot link aarch64 on rustc >= 1.9x.
CARGO_LAMBDA_MIN ?= 1.9.2
# The cargo-lambda binary to use. Empty (the default): vm-build picks the first one on PATH
# or in ~/.cargo/bin that meets CARGO_LAMBDA_MIN (a Homebrew 1.9.1 earlier on PATH is skipped).
CARGO_LAMBDA ?=
LLVM_BIN     ?= /opt/homebrew/opt/llvm/bin
# The image's base container: the FROM line of image/Dockerfile is the single source (digest-pinned).
BASE_IMAGE   := $(shell sed -n 's/^FROM[[:space:]]*//p' image/Dockerfile | head -1)
CARGO        := cargo +$(TOOLCHAIN)
# Where `make install` puts the two bins (cargo install --root); same default as cargo's own.
INSTALL_ROOT ?= $(or $(CARGO_INSTALL_ROOT),$(CARGO_HOME),$(HOME)/.cargo)
# Only these files may touch the TLS/WS dialing API (grep guard in `lint`).
TLS_ALLOW    ?= src/bridge/(tls|transport)\.rs
# S3: the one region (the MicroVM API answers 403 elsewhere); never taken from the environment.
override REGION := eu-central-1
# The operator CLI the image and infra targets call (default features, built on demand). Honoured only from the make
# command line: a shell that sourced or dotenv-loaded an encrypted .env carries AI_ENV=1 (its marker line), and
# recipes never see the variable.
ifneq ($(origin AI_ENV),command line)
AI_ENV       := $(CARGO) run -q -p $(PKG) --bin ai-env --
endif
unexport AI_ENV
# Image sources (tests point IMAGE_DIR at a planted copy) and build outputs.
IMAGE_DIR    ?= image
IMAGE_OUT    ?= target/image
IMAGE_JSON   := $(IMAGE_OUT)/image.json
# The one image parameter file (D19) the Pulumi program reads: the image name and the managed base image come from
# it (never the environment); a value it does not yield is empty, and the targets using it fail loudly.
IMAGE_CONFIG := infra/image-config.json
IMAGE_NAME   := $(shell sed -n 's/.*"imageName": *"\([^"]*\)".*/\1/p' $(IMAGE_CONFIG))
BASE_NAME    := $(shell sed -n 's/.*"baseImage":.*"name": *"\([^"]*\)".*/\1/p' $(IMAGE_CONFIG))
BASE_VERSION := $(shell sed -n 's/.*"baseImage":.*"version": *"\([^"]*\)".*/\1/p' $(IMAGE_CONFIG))
BASE_CHECK    = test -n "$(BASE_NAME)" -a -n "$(BASE_VERSION)"
BASE_MISSING := baseImage.name or baseImage.version missing from $(IMAGE_CONFIG)
# $(MAKE) inside a long shell line makes GNU make run that line even under -n; an
# indirect reference keeps `make -n s3-preflight` (and `make -n deploy`) a dry parse.
SUBMAKE       = $(MAKE)
STAGE        := $(IMAGE_OUT)/stage
IMAGE_ZIP    := $(IMAGE_OUT)/image.zip
# `make test-docker` writes the zip's sha256 here; `make deploy` refuses any other zip.
DOCKER_STAMP := $(IMAGE_OUT)/test-docker.ok
LOCAL_IMAGE  ?= ai-env-agent:local
# s3-preflight P3: free disk inside the Docker VM (KiB) for the image build (the ~240 MB claude download, the layers,
# the build cache).
DOCKER_FREE_MIN_KB ?= 4194304
# Claude Code release signing key (gpg). With gpg and this key in its keyring, claude-pin requires manifest.json.sig
# and a valid signature whose primary key is this fingerprint; without either it pins with a NOT verified warning.
CLAUDE_GPG_FPR ?= 31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE
CLAUDE_RELEASES := https://downloads.claude.ai/claude-code-releases

help: ## Show this help
	@grep -h -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-16s\033[0m %s\n", $$1, $$2}'

build: ## Build ai-env (+ ai-env-claude) in all four feature sets: default, none, shim, bridge
	$(CARGO) build -p $(PKG)
	$(CARGO) build -p $(PKG) --no-default-features
	$(CARGO) build -p $(PKG) --no-default-features --features shim
	$(CARGO) build -p $(PKG) --no-default-features --features bridge
	@test -x target/debug/ai-env && test -x target/debug/ai-env-claude && echo "build: ok (both bins)"

check-bins: ## T0.1/T0.1b: shim-only and no-feature builds yield ai-env only; explicit --bin ai-env-claude is refused without bridge
	CARGO_TARGET_DIR=target/matrix/shim $(CARGO) build -p $(PKG) --no-default-features --features shim
	@test -x target/matrix/shim/debug/ai-env && test ! -e target/matrix/shim/debug/ai-env-claude
	CARGO_TARGET_DIR=target/matrix/none $(CARGO) build -p $(PKG) --no-default-features
	@test -x target/matrix/none/debug/ai-env && test ! -e target/matrix/none/debug/ai-env-claude
	@target/matrix/none/debug/ai-env vm --help >/dev/null 2>&1;   test $$? -eq 2 || { echo "expected exit 2 for 'vm' without bridge"; exit 1; }
	@target/matrix/none/debug/ai-env shim --help >/dev/null 2>&1; test $$? -eq 2 || { echo "expected exit 2 for 'shim' without shim"; exit 1; }
	@target/matrix/none/debug/ai-env wrapper --help >/dev/null 2>&1; test $$? -eq 2 || { echo "expected exit 2 for 'wrapper' without bridge"; exit 1; }
	@target/matrix/none/debug/ai-env session --help >/dev/null 2>&1; test $$? -eq 2 || { echo "expected exit 2 for 'session' without bridge"; exit 1; }
	@target/matrix/none/debug/ai-env infra --help >/dev/null 2>&1; test $$? -eq 2 || { echo "expected exit 2 for 'infra' without bridge"; exit 1; }
	@target/matrix/none/debug/ai-env creds --help >/dev/null 2>&1; test $$? -eq 2 || { echo "expected exit 2 for 'creds' without bridge"; exit 1; }
	@target/matrix/none/debug/ai-env lab --help >/dev/null 2>&1;   test $$? -eq 2 || { echo "expected exit 2 for 'lab' without bridge"; exit 1; }
	@out=$$($(CARGO) build -p $(PKG) --bin ai-env-claude --no-default-features --features shim 2>&1); rc=$$?; \
	  test $$rc -ne 0 || { echo "ai-env-claude built without bridge"; exit 1; }; \
	  grep -qF 'target `ai-env-claude` in package `ai-env-cli` requires the features: `bridge`' <<<"$$out" || { echo "$$out"; exit 1; }
	@echo "check-bins: ok"

test: ## Unit + integration tests in all four feature sets
	$(CARGO) test --workspace
	$(CARGO) test -p $(PKG) --no-default-features
	$(CARGO) test -p $(PKG) --no-default-features --features shim
	$(CARGO) test -p $(PKG) --no-default-features --features bridge

# Live targets never run against a fake: every lab knob of the developer's shell is dropped.
LAB_UNSET    := env -u AI_ENV_BRIDGE_LAB_FAKE_API -u AI_ENV_BRIDGE_LAB_FAKE_API_UNSEAL -u AI_ENV_BRIDGE_LAB_BACKOFF_MS

# --nocapture: the live tests are measurements (statuses, x-aws-proxy-error, timings) printed to stderr, which
# cargo hides for passing tests; one thread keeps each test's lines together.
test-aws: ## Live AWS/TLS tests (#[ignore]d; AI_ENV_AWS_TESTS=1; needs credentials; region is pinned in code), measurements shown. SLOW=1 adds the 6-minute token-expiry test; PROBES=1 re-records the live S4 probes
	$(LAB_UNSET) AI_ENV_AWS_TESTS=1 $(if $(filter 1,$(call cmdline,SLOW)),AI_ENV_AWS_SLOW=1) $(CARGO) test -p $(PKG) --features bridge --test aws -- --ignored --test-threads=1 --nocapture
	@$(if $(filter 1,$(call cmdline,PROBES)),rc=0; for p in payload-size no-traffic-before-run snapshot-uniqueness idle-policy-limits; do \
	  $(LAB_UNSET) $(AI_ENV) lab run $$p || { echo "test-aws: probe $$p did not record its expected verdict"; rc=1; }; done; exit $$rc,true)

test-aws-readonly: ## Part A live checks, read-only (this identity, eu-central-1): TLS to the MicroVM proxy, managed images, ListMicrovms, GetMicrovm of an unknown id
	$(LAB_UNSET) AI_ENV_AWS_TESTS=1 $(CARGO) test -p $(PKG) --features bridge --test aws -- --ignored readonly_ --test-threads=1 --nocapture

s4-smoke: ## T4.1 gate: three `ai-env vm smoke --max-duration 900 --json` passes (live, one Touch ID each); records appended to target/s4/smoke.jsonl
	@mkdir -p target/s4
	@for i in 1 2 3; do \
	  out=$$($(LAB_UNSET) $(AI_ENV) vm smoke --max-duration 900 --json) || { echo "$$out"; echo "s4-smoke: pass $$i failed"; exit 1; }; \
	  printf '%s\n' "$$out" >> target/s4/smoke.jsonl; \
	  grep -q '"backend":"sdk"' <<<"$$out" || { echo "$$out"; echo "s4-smoke: pass $$i did not use the SDK backend"; exit 1; }; \
	  echo "s4-smoke: pass $$i ok"; \
	done; echo "s4-smoke: 3/3 ok (target/s4/smoke.jsonl)"

perf-wrapper: ## T1.2 overhead: ai-env-claude (release) vs a bare exec of the fake, 100 interleaved runs, median delta <= 10 ms
	AI_ENV_PERF_TESTS=1 $(CARGO) test --release -p $(PKG) --features bridge --test wrapper -- --ignored overhead --nocapture --test-threads=1

install: ## cargo install both bins (ai-env + ai-env-claude) into $(INSTALL_ROOT)/bin with the committed Cargo.lock; asserts one version
	$(CARGO) install --path crates/$(PKG) --locked --root "$(INSTALL_ROOT)"
	@a=$$("$(INSTALL_ROOT)/bin/ai-env" --version); b=$$("$(INSTALL_ROOT)/bin/ai-env-claude" --version); echo "$$a / $$b"; \
	  test "$${a##* }" = "$${b##* }" || { echo "install: version skew between the two bins"; exit 1; }
	@case ":$$PATH:" in *":$(INSTALL_ROOT)/bin:"*) ;; *) echo "note: $(INSTALL_ROOT)/bin is not on PATH";; esac

# --lambda-dir: cargo-lambda otherwise writes under the cargo target directory (CARGO_TARGET_DIR when set), and the cp
# below would take a stale bootstrap; the old one is removed first, so a build that writes nothing fails at the cp.
vm-build: ## Cross-build the VM shim binary with cargo-lambda (--arm64, shim feature only) -> image/ai-env; assert glibc <= $(GLIBC_MAX) and no getentropy
	@set -eu; cl="$(CARGO_LAMBDA)"; \
	  ver() { "$$1" lambda --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1; }; \
	  ok() { v=$$(ver "$$1"); test -n "$$v" && test "$$(printf '%s\n%s\n' "$(CARGO_LAMBDA_MIN)" "$$v" | sort -t. -k1,1n -k2,2n -k3,3n | head -1)" = "$(CARGO_LAMBDA_MIN)"; }; \
	  if [ -z "$$cl" ]; then \
	    for c in $$(which -a cargo-lambda 2>/dev/null) "$$HOME/.cargo/bin/cargo-lambda"; do if [ -x "$$c" ] && ok "$$c"; then cl="$$c"; break; fi; done; \
	    test -n "$$cl" || { echo "vm-build: no cargo-lambda >= $(CARGO_LAMBDA_MIN) on PATH or in ~/.cargo/bin; found:"; \
	      for c in $$(which -a cargo-lambda 2>/dev/null) "$$HOME/.cargo/bin/cargo-lambda"; do test -x "$$c" && echo "  $$c $$(ver "$$c")"; done; \
	      echo "  cargo install cargo-lambda --locked --version $(CARGO_LAMBDA_MIN)   (or: make vm-build CARGO_LAMBDA=/path/to/cargo-lambda)"; exit 1; }; \
	  else ok "$$cl" || { echo "vm-build: $$cl $$(ver "$$cl") < $(CARGO_LAMBDA_MIN): arm64 link fails on rustc 1.9x"; exit 1; }; fi; \
	  echo "vm-build: using $$cl $$(ver "$$cl")"; \
	  rustup +$(TOOLCHAIN) target list --installed | grep -qx '$(TARGET)' || { echo "missing target: rustup target add $(TARGET) --toolchain $(TOOLCHAIN)"; exit 1; }; \
	  test -x $(LLVM_BIN)/llvm-nm -a -x $(LLVM_BIN)/llvm-objdump || { echo "vm-build: $(LLVM_BIN)/llvm-nm or llvm-objdump missing (brew install llvm, or set LLVM_BIN)"; exit 1; }; \
	  rm -f target/lambda/ai-env/bootstrap; \
	  ulimit -n 10240; RUSTUP_TOOLCHAIN=$(TOOLCHAIN) "$$cl" lambda build --release --arm64 --lambda-dir target/lambda -p $(PKG) --bin ai-env --no-default-features --features shim
	mkdir -p image
	cp target/lambda/ai-env/bootstrap image/ai-env
	@file image/ai-env | grep -q 'ELF 64-bit.*aarch64' || { file image/ai-env; echo "vm-build: not an aarch64 ELF"; exit 1; }
	@max=$$($(LLVM_BIN)/llvm-objdump -T image/ai-env | grep -o 'GLIBC_2\.[0-9]*' | sort -u -t. -k2,2n | tail -1); \
	  echo "vm-build: max glibc symbol version $$max"; \
	  test "$${max#GLIBC_2.}" -le $(subst 2.,,$(GLIBC_MAX)) || { echo "vm-build: glibc ceiling exceeded ($$max > GLIBC_$(GLIBC_MAX))"; exit 1; }
	@n=$$($(LLVM_BIN)/llvm-nm -D image/ai-env | grep -cE ' getentropy(@|$$)' || true); \
	  echo "vm-build: getentropy references $$n"; \
	  test "$$n" -eq 0 || { echo "vm-build: $$n getentropy reference(s) — a glibc 2.25 symbol"; exit 1; }
	@ls -l image/ai-env

vm-run: ## Run the cross-built shim binary inside the AL2023 arm64 base image (docker) with ARGS, e.g. ARGS='--version'
	docker run --rm --platform linux/arm64 --entrypoint /b/ai-env -v "$(CURDIR)/image:/b:ro" $(BASE_IMAGE) $(ARGS)

check-features: ## T0.2b: no AWS/TLS crates in the shim graph; tungstenite/hyper/axum once; no ring on the Mac side
	$(CARGO) tree -p $(PKG) -e normal --no-default-features --features shim --target $(TARGET) --prefix none >/dev/null
	@out=$$($(CARGO) tree -p $(PKG) -e normal --no-default-features --features shim --target $(TARGET) --prefix none | sort -u | grep -E '^(aws-|rustls|reqwest|hyper-rustls|aws-lc|ring |webpki-roots|security-framework)'); \
	  test -z "$$out" || { echo "forbidden crates in the shim graph:"; echo "$$out"; exit 1; }
	@out=$$($(CARGO) tree -p $(PKG) -e normal -d --depth 0 | grep -E '^(tokio-tungstenite|tungstenite|hyper|axum) '); \
	  test -z "$$out" || { echo "duplicate crates:"; echo "$$out"; exit 1; }
	@out=$$($(CARGO) tree -p $(PKG) -e normal --prefix none | sort -u | grep -E '^ring '); \
	  test -z "$$out" || { echo "ring in the Mac graph (aws-lc-rs must be the only provider):"; echo "$$out"; exit 1; }
	@echo "check-features: ok"

check-deps: ## Unused-dependency scan (cargo machete); stage pins declared ahead of their code are allowlisted in crates/$(PKG)/Cargo.toml
	@command -v cargo-machete >/dev/null || { echo "cargo install cargo-machete --locked"; exit 1; }
	cargo machete crates/$(PKG)

check-msrv: ## T0.2: ai-env-age builds on $(MSRV_OLD); ai-env-cli refuses (requires rustc 1.94.1); everything builds on $(TOOLCHAIN)
	@rustup run $(MSRV_OLD) rustc --version >/dev/null 2>&1 || { echo "toolchain $(MSRV_OLD) not installed: rustup toolchain install $(MSRV_OLD)"; exit 1; }
	cargo +$(MSRV_OLD) build -p ai-env-age
	@out=$$(cargo +$(MSRV_OLD) build -p $(PKG) 2>&1); rc=$$?; \
	  test $$rc -ne 0 || { echo "ai-env-cli unexpectedly builds on $(MSRV_OLD)"; exit 1; }; \
	  grep -q 'ai-env-cli@0.1.0 requires rustc 1.94.1' <<<"$$out" || { echo "$$out"; echo "expected the MSRV refusal"; exit 1; }; \
	  echo "check-msrv: ai-env-cli correctly refused on $(MSRV_OLD)"
	$(CARGO) build --workspace --all-targets
	@head -3 Cargo.lock | grep -q '^version = 4$$' || { echo "Cargo.lock version changed; cargo $(MSRV_OLD) may not read it"; exit 1; }

coverage: ## Line coverage of src/wire (S0 exit criterion: >= 90 % per file); needs cargo-llvm-cov
	@command -v cargo-llvm-cov >/dev/null || { echo "cargo install cargo-llvm-cov --locked && rustup component add llvm-tools-preview --toolchain $(TOOLCHAIN)"; exit 1; }
	$(CARGO) llvm-cov -p $(PKG) --features bridge,shim --summary-only --ignore-filename-regex 'src/(bridge|shim|cli|edit|bin|[^/]+\.rs$$)'

fmt: ## ADVISORY rustfmt check (house style is wider than rustfmt; see rustfmt.toml) — never a gate
	@if $(CARGO) fmt --all -- --check >/dev/null 2>&1; then echo "fmt: clean"; else echo "fmt: advisory diffs present ('make fmt-diff' to view); not a gate"; fi

fmt-diff: ## Show the advisory rustfmt diff
	-$(CARGO) fmt --all -- --check

clippy: ## clippy -D warnings in every cfg world (bridge+shim, shim-only, shim-only --target $(TARGET), bridge-only, no-feature) + ai-env-age
	$(CARGO) clippy -p $(PKG) --all-targets --features bridge,shim -- -D warnings
	$(CARGO) clippy -p $(PKG) --all-targets --no-default-features --features shim -- -D warnings
	@rustup +$(TOOLCHAIN) target list --installed | grep -qx '$(TARGET)' || { echo "missing target: rustup target add $(TARGET) --toolchain $(TOOLCHAIN)"; exit 1; }
	$(CARGO) clippy -p $(PKG) --lib --bins --no-default-features --features shim --target $(TARGET) -- -D warnings
	$(CARGO) clippy -p $(PKG) --all-targets --no-default-features --features bridge -- -D warnings
	$(CARGO) clippy -p $(PKG) --all-targets --no-default-features -- -D warnings
	$(CARGO) clippy -p ai-env-age --all-targets -- -D warnings

lint: clippy lint-negative ## clippy + grep guards clippy cannot express (Connector::Plain; TLS/WS dialing confined to $(TLS_ALLOW); every tests/*.rs declared)
	@bad=$$(grep -rn 'Connector::Plain' crates/$(PKG)/src || true); test -z "$$bad" || { echo "$$bad"; echo "lint: Connector::Plain is forbidden"; exit 1; }
	@bad=$$(grep -rlE 'connect_async|client_async_tls|Connector::Rustls|use_preconfigured_tls|ClientConfig::builder|aws_smithy_http_client' crates/$(PKG)/src | grep -vE '$(TLS_ALLOW)' || true); \
	  test -z "$$bad" || { echo "$$bad"; echo "lint: TLS/WS/SDK-HTTP dialing must live in $(TLS_ALLOW)"; exit 1; }
	@for f in crates/$(PKG)/tests/*.rs; do n=$$(basename "$$f" .rs); \
	  grep -qE "^name *= *\"$$n\"" crates/$(PKG)/Cargo.toml || { echo "lint: $$f has no [[test]] name = \"$$n\" entry (autotests = false: it would silently never run)"; exit 1; }; done
	@echo "lint: ok"

lint-negative: ## T0.5: clippy must REJECT examples/tls_lint_negative.rs with one diagnostic per clippy.toml disallowed-methods entry (proves every path still resolves)
	@out=$$($(CARGO) clippy -p $(PKG) --example tls_lint_negative --features lint-negative -- -D warnings 2>&1); rc=$$?; \
	  test $$rc -ne 0 || { echo "$$out"; echo "lint-negative: clippy accepted the disallowed methods — clippy.toml paths are stale"; exit 1; }; \
	  paths=$$(sed -n '/^disallowed-methods/,/^\]/p' clippy.toml | grep -oE 'path *= *"[^"]+"' | sed -E 's/.*"([^"]+)"/\1/'); \
	  n=0; for p in $$paths; do n=$$((n+1)); \
	    grep -qF 'use of a disallowed method `'"$$p"'`' <<<"$$out" || { echo "$$out"; echo "lint-negative: no disallowed-method diagnostic for $$p (stale path in clippy.toml or missing call in the example)"; exit 1; }; done; \
	  test "$$n" -ge 7 || { echo "lint-negative: only $$n disallowed-methods entries parsed from clippy.toml"; exit 1; }; \
	  got=$$(grep -c 'use of a disallowed method' <<<"$$out"); \
	  test "$$got" -eq "$$n" || { echo "$$out"; echo "lint-negative: $$got diagnostics for $$n clippy.toml entries (the example must call each exactly once)"; exit 1; }; \
	  echo "lint-negative: ok (clippy rejected all $$n disallowed methods by full path)"

# ---- S3 image: pin, stage, scan, zip, local build, Docker tests ---------------------

# Fails closed once gpg holds the release key: the .sig is then required, and gpg's machine-readable status (captured,
# never piped into an early-exiting grep under pipefail) must carry GOODSIG and a VALIDSIG whose last field, the
# primary-key fingerprint (a subkey signature names its subkey in the first), is CLAUDE_GPG_FPR: a good signature
# by any other key in the keyring does not count. `infra pin --expect-version` refuses a manifest of another version.
claude-pin: ## Pin Claude Code CLAUDE_VERSION=<v> into image/claude.lock from its release manifest (gpg-verified, fail-closed, when the release key is in the keyring)
	@test -n "$(CLAUDE_VERSION)" || { echo "usage: make claude-pin CLAUDE_VERSION=<version>   (ai-env infra pin --check-bundle shows the installed bundle)"; exit 2; }
	@set -euo pipefail; d="$(IMAGE_OUT)/claude-pin/$(CLAUDE_VERSION)"; mkdir -p "$$d"; rm -f "$$d/manifest.json" "$$d/manifest.json.sig"; \
	  curl --proto '=https' --tlsv1.2 -fsSL -o "$$d/manifest.json" "$(CLAUDE_RELEASES)/$(CLAUDE_VERSION)/manifest.json"; \
	  if command -v gpg >/dev/null && gpg --list-keys "$(CLAUDE_GPG_FPR)" >/dev/null 2>&1; then \
	    curl --proto '=https' --tlsv1.2 -fsSL -o "$$d/manifest.json.sig" "$(CLAUDE_RELEASES)/$(CLAUDE_VERSION)/manifest.json.sig" \
	      || { echo "claude-pin: cannot download manifest.json.sig, required with the release key in the keyring; lock not written"; exit 1; }; \
	    st=$$(gpg --status-fd 1 --verify "$$d/manifest.json.sig" "$$d/manifest.json" || true); \
	    awk -v f="$(CLAUDE_GPG_FPR)" '$$1 == "[GNUPG:]" && $$2 == "NEWSIG" { g = 0 } $$1 == "[GNUPG:]" && $$2 == "GOODSIG" { g = 1 } $$1 == "[GNUPG:]" && $$2 == "VALIDSIG" && g && toupper($$NF) == toupper(f) { ok = 1 } END { exit !ok }' <<<"$$st" \
	      || { echo "claude-pin: manifest.json.sig is not a good signature by the release key $(CLAUDE_GPG_FPR) (gpg above); lock not written"; exit 1; }; \
	    echo "claude-pin: manifest signature verified ($(CLAUDE_GPG_FPR))"; \
	  else echo "claude-pin: signature NOT verified (gpg missing or the release key $(CLAUDE_GPG_FPR) not in its keyring: import it to verify)"; fi; \
	  $(AI_ENV) infra pin --manifest "$$d/manifest.json" --lock "$(IMAGE_DIR)/claude.lock" --expect-version "$(CLAUDE_VERSION)"

# The tree is staged into $(STAGE).tmp and becomes $(STAGE) only after a clean scan: any failure leaves no $(STAGE)
# (image-build-local refuses) and removes the unscanned copy. A symlink anywhere under $(IMAGE_DIR) stops it before
# anything is copied: a linked directory would pull files from outside under their MANIFEST names (find runs from
# inside the directory, so IMAGE_DIR itself may be a link).
image-stage-scan: ## Stage $(IMAGE_DIR) per its MANIFEST (unlisted files and symlinks stop the build), scan it (exit 9 on any finding), then publish it as $(STAGE)
	@set -euo pipefail; src="$(IMAGE_DIR)"; final="$(STAGE)"; stage="$(STAGE).tmp"; listed="$$stage.listed"; \
	  rm -rf "$$final" "$$stage" "$$listed"; trap 'rm -rf "$$stage" "$$listed"' EXIT; \
	  test -f "$$src/MANIFEST" || { echo "image-stage-scan: $$src/MANIFEST missing"; exit 1; }; \
	  links=$$(cd "$$src" && find . -mindepth 1 -type l | sed 's|^\./||' | LC_ALL=C sort); \
	  test -z "$$links" || { echo "image-stage-scan: symlinks in $$src (copy the files in instead):"; echo "$$links" | sed 's/^/  /'; exit 1; }; \
	  mkdir -p "$$stage"; : > "$$listed"; \
	  while read -r kind path mode rest; do \
	    case "$$kind" in ''|\#*) continue;; esac; \
	    case "$$path" in ''|/*|*..*) echo "image-stage-scan: unsafe path '$$path' in MANIFEST"; exit 1;; esac; \
	    case "$$mode" in 0[0-7][0-7][0-7]) ;; *) echo "image-stage-scan: bad mode '$$mode' for $$path"; exit 1;; esac; \
	    echo "$$path" >> "$$listed"; \
	    if [ "$$kind" = dir ]; then mkdir -p "$$stage/$$path"; chmod "$$mode" "$$stage/$$path"; \
	    elif [ "$$kind" = file ]; then \
	      if [ ! -f "$$src/$$path" ] || [ -L "$$src/$$path" ]; then echo "image-stage-scan: $$src/$$path is missing or not a regular file"; [ "$$path" = ai-env ] && echo "  run: make vm-build"; exit 1; fi; \
	      mkdir -p "$$stage/$$(dirname "$$path")"; cp "$$src/$$path" "$$stage/$$path"; chmod "$$mode" "$$stage/$$path"; \
	    else echo "image-stage-scan: unknown kind '$$kind' in MANIFEST"; exit 1; fi; \
	  done < "$$src/MANIFEST"; \
	  extra=$$( (cd "$$src" && find . -mindepth 1 ! -type d ! -name .DS_Store ! -path ./MANIFEST) | sed 's|^\./||' | LC_ALL=C sort | { grep -vxF -f "$$listed" || test $$? -eq 1; }) || { echo "image-stage-scan: cannot compare $$src with its MANIFEST"; exit 1; }; \
	  rm -f "$$listed"; \
	  test -z "$$extra" || { echo "image-stage-scan: not in $$src/MANIFEST (add it after review, or remove it):"; echo "$$extra" | sed 's/^/  /'; exit 1; }; \
	  echo "image-stage-scan: staged $$src into $$stage"; \
	  $(AI_ENV) infra scan "$$stage" --profile image; \
	  mv "$$stage" "$$final"; echo "image-stage-scan: scanned clean, published as $$final"

image-zip: ## vm-build, stage + scan, then a deterministic $(IMAGE_ZIP) and $(IMAGE_JSON) (sha256, S3 key, versions)
	$(MAKE) vm-build
	$(MAKE) image-stage-scan
	@set -euo pipefail; stage="$(STAGE)"; mkdir -p "$(IMAGE_OUT)"; \
	  zip_abs="$$(cd "$(IMAGE_OUT)" && pwd)/$$(basename "$(IMAGE_ZIP)")"; rm -f "$$zip_abs"; \
	  find "$$stage" -exec env TZ=UTC touch -h -t 198001010000 {} +; \
	  (cd "$$stage" && find . -mindepth 1 | sed 's|^\./||' | LC_ALL=C sort | TZ=UTC zip -X -q "$$zip_abs" -@); \
	  sha=$$(shasum -a 256 "$$zip_abs" | cut -d' ' -f1); \
	  claude=$$(sed -n 's/^CLAUDE_VERSION=//p' "$$stage/claude.lock"); \
	  shim=$$($(AI_ENV) --version | awk '{print $$NF}'); \
	  printf '{"zip":"%s","sha256":"%s","key":"ai-env/image-%s.zip","claudeVersion":"%s","shimVersion":"%s"}\n' "$(IMAGE_ZIP)" "$$sha" "$${sha:0:16}" "$$claude" "$$shim" > "$(IMAGE_JSON)"; \
	  ls -l "$$zip_abs"; cat "$(IMAGE_JSON)"

# The build context is a fresh copy with current mtimes: the stage carries the zip's fixed 1980 mtimes, and
# BuildKit's context sync skips a file whose size and mtime are unchanged, so a same-length edit (a new
# claude.lock) would silently reuse the previous content. Layer caching stays content-based.
image-build-local: ## docker build the staged context (as the platform would) into $(LOCAL_IMAGE); downloads the pinned claude
	@test -f "$(STAGE)/Dockerfile" || { echo "image-build-local: run make image-zip first"; exit 1; }
	@set -e; ctx="$(IMAGE_OUT)/docker-context"; rm -rf "$$ctx"; cp -R "$(STAGE)" "$$ctx"; find "$$ctx" -exec touch {} +
	docker build --platform linux/arm64 -t $(LOCAL_IMAGE) "$(IMAGE_OUT)/docker-context"
	@docker image inspect -f 'image-build-local: $(LOCAL_IMAGE) {{.Size}} bytes' $(LOCAL_IMAGE)

image-run-local: ## Run $(LOCAL_IMAGE) with its ports on 127.0.0.1:18080 (app), :19000 (hooks), :19418 (code)
	docker run --rm -it --platform linux/arm64 --name ai-env-agent-local -p 127.0.0.1:18080:8080 -p 127.0.0.1:19000:9000 -p 127.0.0.1:19418:9418 $(LOCAL_IMAGE)

test-docker: ## T3.1: image-zip + image-build-local, then the opt-in Docker tests (L1 base image + shim, L2 local image); stamps the zip for deploy
	$(MAKE) image-zip
	$(MAKE) image-build-local
	AI_ENV_DOCKER_TESTS=1 AI_ENV_DOCKER_BASE='$(BASE_IMAGE)' AI_ENV_DOCKER_IMAGE='$(LOCAL_IMAGE)' AI_ENV_DOCKER_SHIM='$(CURDIR)/image/ai-env' \
	  $(CARGO) test -p $(PKG) --no-default-features --features shim --test shim_docker -- --ignored --test-threads=1
	@sha=$$(shasum -a 256 "$(IMAGE_ZIP)" | cut -d' ' -f1); echo "$$sha" > "$(DOCKER_STAMP)"; echo "test-docker: ok, stamped $$sha"

check-base-image: ## T3.5: the pinned managed base image (baseImage in $(IMAGE_CONFIG)) is AVAILABLE
	@$(BASE_CHECK) || { echo "check-base-image: $(BASE_MISSING)"; exit 1; }
	$(AI_ENV) infra base-image --name $(BASE_NAME) --version $(BASE_VERSION)

s3-preflight: ## S3 preconditions P1-P12 (PHASE=a: build + read-only checks; PHASE=b: also the deploy ones); one row each, exit 1 on any [NO ]
	@set -uo pipefail; phase="$(or $(PHASE),a)"; bad=0; \
	  row() { printf '%s %s\n' "$$1" "$$2"; [ "$$1" = "[NO ]" ] && bad=1; true; }; \
	  if out=$$($(SUBMAKE) -s --no-print-directory vm-build-pick 2>&1); then row "[ok ]" "P1 cargo-lambda: $$out"; else row "[NO ]" "P1 cargo-lambda: $$out"; fi; \
	  if rustup +$(TOOLCHAIN) target list --installed | grep -qx '$(TARGET)' && test -x $(LLVM_BIN)/llvm-nm; then row "[ok ]" "P2 $(TARGET) target, llvm tools"; else row "[NO ]" "P2 rustup target add $(TARGET) --toolchain $(TOOLCHAIN); brew install llvm"; fi; \
	  if v=$$(docker version --format '{{.Server.Version}} {{.Server.Arch}}' 2>/dev/null); then \
	    case "$${v##* }" in \
	    arm64|aarch64) \
	      free=$$(docker run --rm --network none --platform linux/arm64 --entrypoint df $(BASE_IMAGE) -Pk / 2>/dev/null | awk 'NR == 2 { print $$4 }'); \
	      case "$$free" in \
	      ''|*[!0-9]*) row "[NO ]" "P3 docker $$v: cannot measure the free disk inside the Docker VM (docker run $(BASE_IMAGE) df -Pk /)";; \
	      *) if [ "$$free" -ge $(DOCKER_FREE_MIN_KB) ]; then row "[ok ]" "P3 docker $$v, $$((free / 1024)) MiB free in the Docker VM"; \
	         else row "[NO ]" "P3 docker $$v: $$((free / 1024)) MiB free in the Docker VM, need $$(($(DOCKER_FREE_MIN_KB) / 1024)) (docker system prune)"; fi;; \
	      esac;; \
	    *) row "[NO ]" "P3 docker $$v: the server is not arm64 (the image build would be emulated)";; \
	    esac; \
	  else row "[NO ]" "P3 docker is not running"; fi; \
	  if node -e 'process.exit(+process.versions.node.split(".")[0] >= 20 ? 0 : 1)' 2>/dev/null && command -v npm >/dev/null && command -v zip >/dev/null; then row "[ok ]" "P4 node $$(node --version), npm, zip$$(command -v gpg >/dev/null && echo ', gpg' || echo ' (no gpg: claude-pin cannot verify signatures)')"; else row "[NO ]" "P4 node >= 20, npm and zip are required"; fi; \
	  claude=$$(sed -n 's/^CLAUDE_VERSION=//p' image/claude.lock); \
	  for u in "$(CLAUDE_RELEASES)/$$claude/manifest.json" https://public.ecr.aws/v2/ https://cdn.amazonlinux.com/al2023/core/mirrors/latest/aarch64/mirror.list; do \
	    code=$$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$$u" 2>/dev/null || echo 000); \
	    case "$$code" in 2*|3*|401) row "[ok ]" "P5 reachable ($$code) $$u";; *) row "[NO ]" "P5 unreachable ($$code) $$u";; esac; done; \
	  if [ "$$phase" = b ]; then \
	    if (cd infra && pulumi stack ls --json 2>/dev/null) | grep -q '"name": *"$(STACK)"'; then row "[ok ]" "P6 pulumi stack $(STACK) ($$(pulumi whoami -v 2>/dev/null | sed -n 's/^Backend URL: *//p'))"; else row "[NO ]" "P6 pulumi stack $(STACK) missing: cd infra && pulumi stack init $(STACK)"; fi; fi; \
	  if pulumi plugin ls --json 2>/dev/null | node -e 'const p=JSON.parse(require("fs").readFileSync(0,"utf8"));const has=(n,v)=>p.some(x=>x.name===n&&x.kind==="resource"&&x.version===v);process.exit(has("aws","7.10.0")&&has("aws-native","1.79.0")?0:1)'; then row "[ok ]" "P7 pulumi plugins aws 7.10.0, aws-native 1.79.0"; else row "[NO ]" "P7 pulumi plugin install resource aws 7.10.0; pulumi plugin install resource aws-native 1.79.0"; fi; \
	  if arn=$$(aws sts get-caller-identity --region $(REGION) --query Arn --output text 2>/dev/null); then row "[ok ]" "P8 deploy identity $${arn##*:}"; else row "[NO ]" "P8 no AWS credentials for the deploy identity"; fi; \
	  if [ "$$phase" = b ]; then \
	    if out=$$($(AI_ENV) creds aws-set --check 2>&1); then row "[ok ]" "P9 runtime-key preconditions"; else row "[-  ]" "P9 runtime-key preconditions not met yet (needed by make runtime-key, not by deploy)"; fi; fi; \
	  if out=$$($(AI_ENV) infra pin --check-bundle --lock image/claude.lock 2>&1); then row "[ok ]" "P10 $$(echo "$$out" | tail -1)"; else row "[NO ]" "P10 $$(echo "$$out" | tail -1)"; fi; \
	  if ! $(BASE_CHECK); then row "[NO ]" "P11 $(BASE_MISSING)"; \
	  elif out=$$($(AI_ENV) infra base-image --name $(BASE_NAME) --version $(BASE_VERSION) 2>&1); then row "[ok ]" "P11 $$(echo "$$out" | tail -1)"; else row "[NO ]" "P11 $$(echo "$$out" | tail -1)"; fi; \
	  if [ "$$phase" = b ]; then \
	    zsha=$$(test -f "$(IMAGE_ZIP)" && shasum -a 256 "$(IMAGE_ZIP)" | cut -d' ' -f1); \
	    if [ "$(call cmdline,EXPECT_BUILD_FAILURE)" = 1 ]; then row "[-  ]" "P12 NOT CHECKED: EXPECT_BUILD_FAILURE=1 on the command line (the T3.4 negative): this zip is deployed whether or not make test-docker passed for it"; \
	    elif [ -n "$$zsha" ] && [ "$$(cat "$(DOCKER_STAMP)" 2>/dev/null)" = "$$zsha" ]; then row "[ok ]" "P12 make test-docker passed for this zip"; else row "[NO ]" "P12 make test-docker has not passed for the current $(IMAGE_ZIP)"; fi; fi; \
	  exit $$bad

# Internal: print the cargo-lambda vm-build would use (s3-preflight P1).
vm-build-pick:
	@cl="$(CARGO_LAMBDA)"; ver() { "$$1" lambda --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1; }; \
	  ok() { v=$$(ver "$$1"); test -n "$$v" && test "$$(printf '%s\n%s\n' "$(CARGO_LAMBDA_MIN)" "$$v" | sort -t. -k1,1n -k2,2n -k3,3n | head -1)" = "$(CARGO_LAMBDA_MIN)"; }; \
	  if [ -z "$$cl" ]; then for c in $$(which -a cargo-lambda 2>/dev/null) "$$HOME/.cargo/bin/cargo-lambda"; do if [ -x "$$c" ] && ok "$$c"; then cl="$$c"; break; fi; done; fi; \
	  if [ -n "$$cl" ] && ok "$$cl"; then echo "$$cl $$(ver "$$cl")"; else echo "none >= $(CARGO_LAMBDA_MIN) (cargo install cargo-lambda --locked --version $(CARGO_LAMBDA_MIN))"; exit 1; fi

gates: ## Run the G1–G8 pre-code gates via `ai-env gates` (writes plans/gates.md); GATES_ARGS='--only G1,G3' re-measures a subset without writing
	$(CARGO) run -q -p $(PKG) --bin ai-env -- gates $(GATES_ARGS)

acceptance: ## Stage acceptance run (defined from stage S8 on)
	@echo "acceptance: not defined yet — see plans/v6-microvm-bridge.md §6"; exit 1

clean: ## Remove build artifacts (keeps image/ sources)
	cargo clean
	rm -f image/ai-env

# ---- S3 infra (Pulumi program, deploy, image lifecycle): infra/infra.mk ----
include infra/infra.mk
