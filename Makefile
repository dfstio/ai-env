# ai-env — build/test driver for the classic tool and the MicroVM bridge.
# Style: DFST/monitoring/Makefile (`make help` lists targets from `## comments`).
.PHONY: help build check-bins test test-aws install vm-build check-features check-msrv fmt fmt-diff clippy lint gates acceptance clean

SHELL        := /bin/bash
STACK        ?= dev
TOOLCHAIN    ?= 1.98.1
MSRV_OLD     ?= 1.90
PKG          := ai-env-cli
TARGET       ?= aarch64-unknown-linux-gnu
# AL2023 ships glibc 2.34; cargo-lambda's arm64 build targets an older glibc (2.30 observed).
GLIBC_MAX    ?= 2.34
# cargo-lambda below this embeds a cargo-zigbuild that cannot link aarch64 on rustc >= 1.9x.
CARGO_LAMBDA_MIN ?= 1.9.2
LLVM_BIN     ?= /opt/homebrew/opt/llvm/bin
BASE_IMAGE   ?= public.ecr.aws/lambda/microvms:al2023-minimal
CARGO        := cargo +$(TOOLCHAIN)
# Only these files may touch the TLS/WS dialing API (grep guard in `lint`).
TLS_ALLOW    ?= src/bridge/(tls|transport)\.rs

help: ## Show this help
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-16s\033[0m %s\n", $$1, $$2}'

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
	@out=$$($(CARGO) build -p $(PKG) --bin ai-env-claude --no-default-features --features shim 2>&1); rc=$$?; \
	  test $$rc -ne 0 || { echo "ai-env-claude built without bridge"; exit 1; }; \
	  grep -qF 'target `ai-env-claude` in package `ai-env-cli` requires the features: `bridge`' <<<"$$out" || { echo "$$out"; exit 1; }
	@echo "check-bins: ok"

test: ## Unit + integration tests in all four feature sets
	$(CARGO) test --workspace
	$(CARGO) test -p $(PKG) --no-default-features
	$(CARGO) test -p $(PKG) --no-default-features --features shim
	$(CARGO) test -p $(PKG) --no-default-features --features bridge

test-aws: ## Live AWS/TLS tests (#[ignore]d; AI_ENV_AWS_TESTS=1; needs credentials; region is pinned in code)
	AI_ENV_AWS_TESTS=1 $(CARGO) test -p $(PKG) --features bridge --test aws -- --ignored --test-threads=1

install: ## cargo install both bins (ai-env + ai-env-claude) with the committed Cargo.lock
	$(CARGO) install --path crates/$(PKG) --locked
	@ai-env --version && ai-env-claude --version

vm-build: ## Cross-build the VM shim binary with cargo-lambda (--arm64, shim feature only) -> image/ai-env; assert glibc <= $(GLIBC_MAX) and no getentropy
	@v=$$(cargo lambda --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1); \
	  test -n "$$v" || { echo "cargo-lambda not found: cargo install cargo-lambda --locked"; exit 1; }; \
	  low=$$(printf '%s\n%s\n' "$(CARGO_LAMBDA_MIN)" "$$v" | sort -t. -k1,1n -k2,2n -k3,3n | head -1); \
	  test "$$low" = "$(CARGO_LAMBDA_MIN)" || { echo "cargo-lambda $$v < $(CARGO_LAMBDA_MIN): arm64 link fails on rustc 1.9x — cargo install cargo-lambda --locked"; exit 1; }
	@rustup +$(TOOLCHAIN) target list --installed | grep -qx '$(TARGET)' || { echo "missing target: rustup target add $(TARGET) --toolchain $(TOOLCHAIN)"; exit 1; }
	ulimit -n 10240 && $(CARGO) lambda build --release --arm64 -p $(PKG) --bin ai-env --no-default-features --features shim
	mkdir -p image
	cp target/lambda/ai-env/bootstrap image/ai-env
	@file image/ai-env | grep -q 'ELF 64-bit.*aarch64' || { file image/ai-env; echo "vm-build: not an aarch64 ELF"; exit 1; }
	@max=$$($(LLVM_BIN)/llvm-objdump -T image/ai-env | grep -o 'GLIBC_2\.[0-9]*' | sort -u -t. -k2,2n | tail -1); \
	  echo "vm-build: max glibc symbol version $$max"; \
	  test "$${max#GLIBC_2.}" -le $(subst 2.,,$(GLIBC_MAX)) || { echo "vm-build: glibc ceiling exceeded ($$max > GLIBC_$(GLIBC_MAX))"; exit 1; }
	@n=$$($(LLVM_BIN)/llvm-nm -D image/ai-env | grep -c ' getentropy$$' || true); \
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

check-msrv: ## T0.2: ai-env-age builds on $(MSRV_OLD); ai-env-cli refuses (requires rustc 1.94.1); everything builds on $(TOOLCHAIN)
	cargo +$(MSRV_OLD) build -p ai-env-age
	@out=$$(cargo +$(MSRV_OLD) build -p $(PKG) 2>&1); rc=$$?; \
	  test $$rc -ne 0 || { echo "ai-env-cli unexpectedly builds on $(MSRV_OLD)"; exit 1; }; \
	  grep -q 'ai-env-cli@0.1.0 requires rustc 1.94.1' <<<"$$out" || { echo "$$out"; echo "expected the MSRV refusal"; exit 1; }; \
	  echo "check-msrv: ai-env-cli correctly refused on $(MSRV_OLD)"
	$(CARGO) build --workspace --all-targets
	@head -3 Cargo.lock | grep -q '^version = 4$$' || { echo "Cargo.lock version changed; cargo $(MSRV_OLD) may not read it"; exit 1; }

fmt: ## ADVISORY rustfmt check (house style is wider than rustfmt; see rustfmt.toml) — never a gate
	@if $(CARGO) fmt --all -- --check >/dev/null 2>&1; then echo "fmt: clean"; else echo "fmt: advisory diffs present ('make fmt-diff' to view); not a gate"; fi

fmt-diff: ## Show the advisory rustfmt diff
	-$(CARGO) fmt --all -- --check

clippy: ## clippy -D warnings in every cfg world (all-features, shim-only, bridge-only, no-feature) + ai-env-age
	$(CARGO) clippy -p $(PKG) --all-targets --all-features -- -D warnings
	$(CARGO) clippy -p $(PKG) --all-targets --no-default-features --features shim -- -D warnings
	$(CARGO) clippy -p $(PKG) --all-targets --no-default-features --features bridge -- -D warnings
	$(CARGO) clippy -p $(PKG) --all-targets --no-default-features -- -D warnings
	$(CARGO) clippy -p ai-env-age --all-targets -- -D warnings

lint: clippy ## clippy + grep guards clippy cannot express (Connector::Plain; TLS/WS dialing confined to $(TLS_ALLOW))
	@bad=$$(grep -rn 'Connector::Plain' crates/$(PKG)/src || true); test -z "$$bad" || { echo "$$bad"; echo "lint: Connector::Plain is forbidden"; exit 1; }
	@bad=$$(grep -rlE 'connect_async|client_async_tls|Connector::Rustls|use_preconfigured_tls|ClientConfig::builder' crates/$(PKG)/src | grep -vE '$(TLS_ALLOW)' || true); \
	  test -z "$$bad" || { echo "$$bad"; echo "lint: TLS/WS dialing must live in $(TLS_ALLOW)"; exit 1; }
	@echo "lint: ok"

gates: ## Run the G1–G8 pre-code gates via `ai-env gates` (writes plans/gates.md); GATES_ARGS='--only G1,G3'
	$(CARGO) run -q -p $(PKG) --bin ai-env -- gates $(GATES_ARGS)

acceptance: ## Stage acceptance run (defined from stage S8 on)
	@echo "acceptance: not defined yet — see plans/v6-microvm-bridge.md §6"; exit 1

clean: ## Remove build artifacts (keeps image/Dockerfile)
	cargo clean
	rm -f image/ai-env
