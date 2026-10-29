# ai-env — build/test driver for the classic tool and the MicroVM bridge.
# Style: DFST/monitoring/Makefile (`make help` lists targets from `## comments`).
.PHONY: help build check-bins test test-aws test-aws-readonly test-claude s4-smoke s5-smoke s6-smoke s7-smoke s8-smoke test-cursor doc-test test-egress test-egress-run test-proxy perf-wrapper install vm-build vm-run check-features check-deps check-msrv coverage fmt fmt-diff clippy lint lint-negative gates acceptance acceptance-run clean \
        claude-pin claude-admit-docker image-stage-scan image-zip image-build-local image-run-local test-docker check-base-image s3-preflight argv-fixtures

SHELL        := /bin/bash
# The switches that delete, rotate, write, pick a version, skip a gate, widen a live run or pick an identity (YES, KEEP,
# VERSION, ROTATE, WRITE, CONFIRM, RECORD_PROBE, FOLLOW, EXPECT_BUILD_FAILURE, SLOW, PROBES, SYSTEMD, CRED, S3, S10,
# S11, S12, WALL, CHAT, REFRESH, BREAKGLASS) count only when given on the make command line (`make image-prune YES=1`; a sub-make
# inherits them, one under `ai-env as` too): the same name exported in the environment is ignored. $(call cmdline,NAME)
# is the value, or empty.
cmdline       = $(if $(filter command line,$(origin $(1))),$($(1)))
# The single-letter switches of this make run: MAKEFLAGS' first word and its -x words, as GNU make 3.81 and 4.x write
# them (a variable assignment, a long option, and an option with an argument (-j -l -O -I) hold none). acceptance, and
# every tiered target and its X-run (NOT_UNDER_I_OR_P, infra/infra.mk), refuse -i and -p on them; TIER leaves its
# runner out in a dry run (-n, -q, -t: MAKE_DRY).
MAKE_SWITCHES = $(foreach w,$(firstword $(MAKEFLAGS)),$(if $(or $(findstring =,$(w)),$(filter --% -j% -l% -O% -I%,$(w))),,$(w))) $(filter-out --% -j% -l% -O% -I%,$(filter -%,$(MAKEFLAGS)))
MAKE_DRY      = $(strip $(findstring n,$(MAKE_SWITCHES))$(findstring q,$(MAKE_SWITCHES))$(findstring t,$(MAKE_SWITCHES)))
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
# A make started under `cargo run` (S11: `ai-env claude admit` run through $(AI_ENV), `cargo run` by default, starts make
# claude-admit-docker) inherits
# CARGO, the path cargo gives its children, and make exports a variable that came from the environment with this
# file's value: every recipe would get CARGO=`cargo +1.98.1`, which cargo-lambda runs as a program for its `cargo
# metadata` (cargo_metadata reads CARGO first), and none is called that (vm-build: "failed to start `cargo metadata`:
# No such file or directory", logs/test34.txt). Recipes use $(CARGO); their children find cargo on PATH.
unexport CARGO
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
# The aws CLI pages its output through less on a terminal (measured 1 Oct 2026: `make image-status` stopped in the
# pager); no recipe wants that.
export AWS_PAGER :=
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
# The Claude Code release key's primary fingerprint (S11): the vendored crates/ai-env-cli/certs/claude-code-release.gpg,
# which wire::pin::RELEASE_KEY_FPR and certs/README.md equal (a test ties the three). claude-pin and ai-env claude admit
# verify every release manifest with gpgv against that key alone, fail-closed.
CLAUDE_GPG_FPR ?= 31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE
CLAUDE_RELEASES := https://downloads.claude.ai/claude-code-releases

help: ## Show this help
	@grep -h -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-16s\033[0m %s\n", $$1, $$2}'

build: ## Build ai-env (+ ai-env-claude) in all four feature sets: default, none, shim, bridge
	$(CARGO) build -p $(PKG)
	$(CARGO) build -p $(PKG) --no-default-features
	$(CARGO) build -p $(PKG) --no-default-features --features shim
	$(CARGO) build -p $(PKG) --no-default-features --features bridge
	@d=$${CARGO_TARGET_DIR:-target}; test -x "$$d/debug/ai-env" && test -x "$$d/debug/ai-env-claude" && echo "build: ok (both bins)"

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
	@target/matrix/none/debug/ai-env egress --help >/dev/null 2>&1; test $$? -eq 2 || { echo "expected exit 2 for 'egress' without bridge"; exit 1; }
	@target/matrix/none/debug/ai-env proxy --help >/dev/null 2>&1;  test $$? -eq 2 || { echo "expected exit 2 for 'proxy' without bridge"; exit 1; }
	@target/matrix/none/debug/ai-env box --help >/dev/null 2>&1;    test $$? -eq 2 || { echo "expected exit 2 for 'box' without bridge"; exit 1; }
	@target/matrix/none/debug/ai-env shim-io --help >/dev/null 2>&1; test $$? -eq 2 || { echo "expected exit 2 for 'shim-io' without shim"; exit 1; }
	@target/matrix/shim/debug/ai-env box --help >/dev/null 2>&1;    test $$? -eq 2 || { echo "expected exit 2 for 'box' in the shim-only build"; exit 1; }
	@out=$$($(CARGO) build -p $(PKG) --bin ai-env-claude --no-default-features --features shim 2>&1); rc=$$?; \
	  test $$rc -ne 0 || { echo "ai-env-claude built without bridge"; exit 1; }; \
	  grep -qF 'target `ai-env-claude` in package `ai-env-cli` requires the features: `bridge`' <<<"$$out" || { echo "$$out"; exit 1; }
	@echo "check-bins: ok"

# S11: the integration tests hold more descriptors than macOS's default soft limit (256: `launchctl limit maxfiles`);
# each test line raises its shell's soft limit to 10240 when it is lower (never lowers it, never fails the line).
TEST_NOFILE = n=$$(ulimit -n); { [ "$$n" = unlimited ] || [ "$$n" -ge 10240 ]; } || ulimit -n 10240 2>/dev/null || true;

test: ## Unit + integration tests in all four feature sets; S11: the audit is strict (AI_ENV_AUDIT_STRICT=1: an unregistered event or key fails its write)
	$(TEST_NOFILE) AI_ENV_AUDIT_STRICT=1 $(CARGO) test --workspace
	$(TEST_NOFILE) AI_ENV_AUDIT_STRICT=1 $(CARGO) test -p $(PKG) --no-default-features
	$(TEST_NOFILE) AI_ENV_AUDIT_STRICT=1 $(CARGO) test -p $(PKG) --no-default-features --features shim
	$(TEST_NOFILE) AI_ENV_AUDIT_STRICT=1 $(CARGO) test -p $(PKG) --no-default-features --features bridge

# Live targets never run against a fake: every lab knob of the developer's shell is dropped (S5:
# AI_ENV_BRIDGE_LAB_FAKE_SHELL, the scripted shell of `ai-env egress check` under the fake backend; S7: the
# wrapper's synthetic oauth_token_refresh, and the unseal budget of its local-scratch and of every credentialed
# vm and lab command; S8: the remote session's transcript knob, a resume that uploads no transcript, and S2's pump
# knobs, which S8's live wrapper runs meet: s8-smoke, test-aws CRED=1, acceptance; S9: the fake S3's address and the
# code token's minutes; S10: the park's quiet; S11: the release's curl, gpgv and make of `ai-env claude admit`, and the
# S11 views' clock, last). tests/infra/image.rs holds the list to every AI_ENV_BRIDGE_LAB_* name the code and
# infra/scripts read. test-aws SLOW=1 then sets the code token's minutes again, for its test process: the re-mint
# test mints its tokens in that process, and the vm, box and session commands and the chats it runs drop every
# lab knob.
LAB_KNOBS    := AI_ENV_BRIDGE_LAB_FAKE_API AI_ENV_BRIDGE_LAB_FAKE_API_UNSEAL AI_ENV_BRIDGE_LAB_BACKOFF_MS AI_ENV_BRIDGE_LAB_FAKE_SHELL \
                AI_ENV_BRIDGE_LAB_AGENT_ADDR AI_ENV_BRIDGE_LAB_SYNTHETIC_OAUTH_MS AI_ENV_BRIDGE_LAB_UNSEAL_TIMEOUT_MS AI_ENV_BRIDGE_LAB_TRANSCRIPT AI_ENV_BRIDGE_LAB_EXIT \
                AI_ENV_BRIDGE_LAB_IGNORE_EOF AI_ENV_BRIDGE_LAB_STDOUT_NOISE AI_ENV_BRIDGE_LAB_DELAY_INIT_MS AI_ENV_BRIDGE_LAB_REPLAY_DEADLINE_MS AI_ENV_BRIDGE_LAB_OSASCRIPT \
                AI_ENV_BRIDGE_LAB_S3_ADDR AI_ENV_BRIDGE_LAB_CODE_TOKEN_MINUTES AI_ENV_BRIDGE_LAB_PARK_AFTER_MS \
                AI_ENV_BRIDGE_LAB_RELEASE_CURL AI_ENV_BRIDGE_LAB_GPGV AI_ENV_BRIDGE_LAB_ADMIT_MAKE AI_ENV_BRIDGE_LAB_NOW
LAB_UNSET    := env $(addprefix -u ,$(LAB_KNOBS))

# S10 (F12): `make test-aws S3=1 CHAT=dev` runs the S3 store's gib test alone (live_s3_gib_round_trip_timing) on a
# synthetic chat of the development chat's shape, AI_ENV_S3_CHAT=$(S3_CHAT_DEV): `main=<MiB>,subtree=<MiB>,files=<n>`,
# set at part B's P0 from that chat's file names and sizes only, never its content (the development chat itself is
# never staged, migrated, parked or reopened remote). Another CHAT, CHAT=dev without S3=1, and an empty or malformed
# S3_CHAT_DEV stop before the tests run: TEST_AWS_CHAT, the line after the keyless compile (D2: test-aws's first).
# S3_CHAT_DEV is this line's value or the command line's, never the environment's (:=): a stale export never picks the
# shape of a 1.5-hour live run.
S3_CHAT_DEV  :=
TEST_AWS_CHAT = chat='$(call cmdline,CHAT)'; shape='$(S3_CHAT_DEV)'; case "$$chat" in dev) ;; \
  *) echo "test-aws: CHAT=$$chat names no chat shape: make test-aws S3=1 CHAT=dev runs the gib test alone on the development chat's shape (S3_CHAT_DEV)"; exit 2 ;; esac; \
  test '$(call cmdline,S3)' = 1 || { echo "test-aws: CHAT=dev needs S3=1: make test-aws S3=1 CHAT=dev"; exit 2; }; \
  test -n "$$shape" || { echo "test-aws: S3_CHAT_DEV is empty: set it at part B's P0 to main=<MiB>,subtree=<MiB>,files=<n>, from the development chat's file names and sizes only (never its content), in this Makefile or on the command line"; exit 2; }; \
  printf '%s\n' "$$shape" | grep -Eqx 'main=[0-9]+,subtree=[0-9]+,files=[0-9]+' || { echo "test-aws: S3_CHAT_DEV=$$shape is not main=<MiB>,subtree=<MiB>,files=<n>"; exit 2; }
# S11 (C.5.4): `make test-aws S10=1 WALL=1` runs S10's three wall tests alone (AI_ENV_AWS_SLOW=1, no code token minutes);
# WALL other than 1, or WALL=1 without S10=1, stops after the keyless compile and before the tests (exit 2).
TEST_AWS_WALL = test '$(call cmdline,WALL)' = 1 || { echo "test-aws: WALL=$(call cmdline,WALL) is not 1: make test-aws S10=1 WALL=1 runs S10's three wall tests alone"; exit 2; }; \
  test '$(call cmdline,S10)' = 1 || { echo "test-aws: WALL=1 needs S10=1: make test-aws S10=1 WALL=1 runs S10's three wall tests alone"; exit 2; }

# --nocapture: the live tests are measurements (statuses, x-aws-proxy-error, timings) printed to stderr, which
# cargo hides for passing tests; one thread keeps each test's lines together. test-aws may run under a runner (its
# help: the suspension's Touch IDs are then the runner's), and test-aws-readonly as ai-env as ops: their tests are
# built first without any key in their environment (D18: a dependency's build script or proc macro never sees it), as
# test-egress's are, and so is the probes' operator CLI; the run then finds them built and keeps the key. S10: S10=1
# runs the live_s10_* tests alone (AI_ENV_S10_TESTS=1); with SLOW=1 it sets AI_ENV_AWS_SLOW=1 alone, for its three
# wall tests: the code token's minutes are S9's re-mint test's, which S10=1 leaves out. S10=1 WALL=1 runs those three
# alone, by their full names. S11: S11=1 runs the live_s11_* tests alone (AI_ENV_S11_TESTS=1), parts A's and C's under
# one filter, and sets no code token minutes (with SLOW=1 only the slow switch).
# S12: S12=1 runs the live_s12_* tests alone (AI_ENV_S12_TESTS=1), every part's under one filter, and sets no code token
# minutes (with SLOW=1 only the slow switch).
test-aws: ## Live AWS/TLS tests (#[ignore]d; AI_ENV_AWS_TESTS=1; needs credentials; region is pinned in code), measurements shown. SLOW=1 adds the 6-minute token-expiry test and the S6 65-minute rotation hold (live_agent_rotation); PROBES=1 re-records the live S4 probes; CRED=1 adds the S7 credential tests (live_credential_*: the setup-token delivered and answering OK, a garbage token refused with exit 5, no credential into an internet VM; Touch IDs: the test process's one, then one per credentialed command with a current combined.env, two for the garbage token's --credential-file: the runtime key, then the file) and S8's live wrapper tests (live_wrapper_*: chats of the real ai-env-claude in remote mode on target/s8 fixtures under [workspaces].roots, one Touch ID per chat and per vm or box command, and one per test for its chats' S3 objects, purged at its end by one session forget --purge of them all: 13 beside the test process's one (the planted secret's test has nothing to purge), 14 when the planted secret's dialog is answered before the seed's refusal closes it; SLOW=1 adds the API host's suspension test, four more: its chat, its purge, and the ops key's for the suspension and for its restore (one per egress suspend; two in all when the run is under ai-env as ops or as deployer); live_wrapper_smoke is skipped: make s8-smoke runs it). S9: the smart-HTTP tests run in the plain form (live_box_fetch_smart_http_matches_codeout, live_smart_http_wrong_port_token_403_twice, live_review_loop_and_tag_leak, live_vm_has_no_push_path: vpc VMs of fixtures under target/s8, one Touch ID per ai-env command); SLOW=1 adds the code token's re-mint after its expiry (live_smart_http_remints_after_expiry: SLOW=1 also sets AI_ENV_BRIDGE_LAB_CODE_TOKEN_MINUTES=2 for the test process, whose own MintingTokens mint its 9418 tokens: the vm, box and session commands and the chats it runs drop every lab knob); S3=1 runs the S3 store's live tests alone (live_s3_*: chats in remote mode after S9's cut-over, the setup-token sealed, each test's chats' objects purged from S3 at its end with one Touch ID more, one session forget --purge of them all; the 1 GiB round trip takes tens of minutes); S3=1 CHAT=dev runs that round trip alone (live_s3_gib_round_trip_timing, about 1.5 h) on a synthetic chat of the development chat's shape, AI_ENV_S3_CHAT=S3_CHAT_DEV (main=<MiB>,subtree=<MiB>,files=<n>, set at part B's P0 from the development chat's file names and sizes only, never its content); another CHAT, or one without S3=1 or a well-formed S3_CHAT_DEV, stops before the tests run. S10=1 runs S10's live tests alone (live_s10_*, AI_ENV_S10_TESTS=1: chats of the real ai-env-claude in remote mode on target/s8 fixtures, the setup-token sealed: a close and a reopen with the wrapper stopped as a closed lid, a VM terminated mid-turn and after an edit, a park at a permission prompt, then subagents and a move, and a live chat moved by session migrate; one Touch ID per chat and per vm or session command, one more per move to a new VM, and one per test for its chats' S3 objects: about 21 in all, the test process's own included); with SLOW=1 the three wall tests too (a wall migration between turns, a reopen near the wall, a reopen after it with the platform's wall recorded; about 45 minutes and 9 Touch IDs more, 3 each, about 30 in all: the others run too), AI_ENV_AWS_SLOW=1 alone. S11=1 runs S11's live tests alone (live_s11_*, AI_ENV_S11_TESTS=1: chats of the real ai-env-claude in remote mode on target/s8 fixtures, the setup-token sealed; part C's three about 14 Touch IDs, the test process's one included, and part A's unknown option, stager and claude_src tests theirs); S12=1 runs S12's live tests alone (live_s12_*, AI_ENV_S12_TESTS=1: part P's DeleteObjects probe and a 6000-object purge with the runtime key, no VM and no chat, 2 Touch IDs with the test process's one; part T's title round trip on a live VM, 2 more: its chat and its purge); S10=1 WALL=1 runs S10's three wall tests alone (AI_ENV_AWS_SLOW=1; about 10 Touch IDs and 45 minutes); WALL=1 without S10=1 stops before the tests run
	$(NO_KEY) $(LAB_UNSET) $(CARGO) test -p $(PKG) --features bridge --test aws --no-run
	@$(if $(call cmdline,CHAT),$(TEST_AWS_CHAT))
	@$(if $(call cmdline,WALL),$(TEST_AWS_WALL))
	$(LAB_UNSET) AI_ENV_AWS_TESTS=1 $(if $(filter 1,$(call cmdline,SLOW) $(call cmdline,WALL)),AI_ENV_AWS_SLOW=1$(if $(filter 1,$(call cmdline,S10) $(call cmdline,S11) $(call cmdline,S12)),, AI_ENV_BRIDGE_LAB_CODE_TOKEN_MINUTES=2)) $(if $(filter 1,$(call cmdline,S3)),AI_ENV_S3_TESTS=1 $(if $(filter dev,$(call cmdline,CHAT)),AI_ENV_S3_CHAT='$(S3_CHAT_DEV)' ))$(if $(filter 1,$(call cmdline,S10)),AI_ENV_S10_TESTS=1 )$(if $(filter 1,$(call cmdline,S11)),AI_ENV_S11_TESTS=1 )$(if $(filter 1,$(call cmdline,S12)),AI_ENV_S12_TESTS=1 )$(if $(filter 1,$(call cmdline,CRED)),AI_ENV_CREDENTIAL_TESTS=1) $(CARGO) test -p $(PKG) --features bridge --test aws -- --ignored --test-threads=1 --nocapture$(if $(filter 1,$(call cmdline,CRED)), --skip live_wrapper_smoke)$(if $(filter 1,$(call cmdline,S3)), $(if $(filter dev,$(call cmdline,CHAT)),live_s3_gib_round_trip_timing,live_s3_))$(if $(filter 1,$(call cmdline,S10)), $(if $(filter 1,$(call cmdline,WALL)),live_s10_wall_migration live_s10_reopen_near_wall live_s10_reopen_after_wall,live_s10_))$(if $(filter 1,$(call cmdline,S11)), live_s11_)$(if $(filter 1,$(call cmdline,S12)), live_s12_)
	@$(if $(filter 1,$(call cmdline,PROBES)),$(AI_ENV_BUILD) || exit $$?; rc=0; for p in payload-size no-traffic-before-run snapshot-uniqueness idle-policy-limits; do \
	  $(LAB_UNSET) $(AI_ENV) lab run $$p || { echo "test-aws: probe $$p did not record its expected verdict"; rc=1; }; done; exit $$rc,true)

test-claude: ## T7.2 (live, this Mac): the sealed setup-token drives the real claude: a stream-json session with a tool call, --resume, the Remote Control refusal, --bare not logged in (AI_ENV_CLAUDE_TESTS=1; one Touch ID; real model requests)
	$(LAB_UNSET) AI_ENV_CLAUDE_TESTS=1 $(CARGO) test -p $(PKG) --features bridge --test claude_live -- --ignored --test-threads=1 --nocapture

# S8. s8-smoke is T8.2's gate, tests/aws.rs live_wrapper_smoke: it prints "s8-smoke: pass N ok" per pass and
# "s8-smoke: 3/3 ok (PATH)" itself, and appends each pass's record (exit, close_ms, initialize_ms, turn_ms and the
# census end row's vm, vm_how, init_ms, legs, seed, fetch and credential) to target/s8/smoke.jsonl once the pass's
# turn answered and its close passed (exit 0 within 1.5 s, end:eof, pid_rewrite:ok), then judges its fetch and seed:
# a pass that fails before that leaves no record.
# test-cursor checks one Cursor step's evidence (tests/cursor_live.rs): STEP, SINCE and WORKSPACE count only on the
# make command line (SINCE is egress-logs' window too, 1h by default), and a missing or unknown STEP, or a missing or
# empty SINCE (S9: evidence of an earlier step never passes for this one; SINCE=all reads every row), stops before
# cargo. doc-test runs tests/readme.rs, the README's and SKILL.md's doc-test, which make test runs too.
s8-smoke: ## T8.2 gate: tests/aws.rs live_wrapper_smoke, three passes, each a chat of the real ai-env-claude in remote mode on the fixture target/s8/live-wrapper-smoke (made anew; [workspaces].roots must hold target/s8): the seed, one turn, its code-out fetched before the close, exit 0 within 1.5 s; one Touch ID each, plus the test process's own (its runtime key) and one for the three chats' S3 objects, purged at its end by one session forget --purge of them all: 5 in all; the test's VM terminated at its end; each pass's record appended to target/s8/smoke.jsonl once its close passed
	$(LAB_UNSET) AI_ENV_AWS_TESTS=1 AI_ENV_CREDENTIAL_TESTS=1 $(CARGO) test -p $(PKG) --features bridge --test aws -- --ignored --exact live_wrapper_smoke --nocapture --test-threads=1

test-cursor: ## S8 part B: one Cursor step's evidence (tests/cursor_live.rs; no VM, no Touch ID, no AWS: the census, the registry, the audit, the lab rows, the git refs): STEP=t8_3|t8_4|t8_5|t8_6|t8_7|t9_s3|t10_2|t10_3|t10_4|t10_5|t10_p|t11_3|t11_fresh (S9: the S3 store's chats; S10, in a target/s8 fixture window, never the development chat: t10_2 a close, a reopen and a lid's sleep, t10_3 a VM terminated mid-turn, t10_4 a wall migration or a reopen that moved first, t10_5 a park at a permission prompt, subagents and a move, t10_p the placeholder's picker reopen; S11, in a target/s8 fixture window: t11_3 the panel's suspend, resume and live migrate of the chat, actor=panel, the move's request the panel's nonce, the CLI's twins with the same keys, t11_fresh a chat on the window's own claude from the VM's cache, claude_src:cached, its claude: the row's ext), SINCE=TIME (required, RFC 3339 UTC: only rows from then on, the step's start taken with date -u +%Y-%m-%dT%H:%M:%SZ before the step; SINCE=all reads every row) and WORKSPACE=PATH (optional: the chats' workspace; default this checkout)
	@step='$(call cmdline,STEP)'; case "$$step" in t8_3|t8_4|t8_5|t8_6|t8_7) ;; \
	  t9_s3) ;; \
	  t10_2|t10_3|t10_4|t10_5|t10_p) ;; \
	  t11_3|t11_fresh) ;; \
	  '') echo "test-cursor: STEP is missing: make test-cursor STEP=t8_3 (or t8_4, t8_5, t8_6, t8_7) after that step in Cursor, or STEP=t9_s3 after S9's, or STEP=t10_2 (or t10_3, t10_4, t10_5, t10_p) after S10's, or STEP=t11_3 (or t11_fresh) after S11's"; exit 2 ;; \
	  *) echo "test-cursor: STEP=$$step names no step: one of t8_3, t8_4, t8_5, t8_6, t8_7, t9_s3, t10_2, t10_3, t10_4, t10_5, t10_p, t11_3, t11_fresh"; exit 2 ;; esac
	@test -n '$(call cmdline,SINCE)' || { echo "test-cursor: SINCE is missing: take the step's start (date -u +%Y-%m-%dT%H:%M:%SZ) before the step in Cursor, or pass SINCE=all to read every row"; exit 2; }
	$(LAB_UNSET) AI_ENV_CURSOR_TESTS=1 AI_ENV_CURSOR_STEP=$(call cmdline,STEP) $(if $(call cmdline,SINCE),AI_ENV_CURSOR_SINCE='$(call cmdline,SINCE)' )$(if $(call cmdline,WORKSPACE),AI_ENV_CURSOR_WORKSPACE='$(call cmdline,WORKSPACE)' )$(CARGO) test -p $(PKG) --features bridge --test cursor_live -- --ignored --nocapture --test-threads=1

# S9 (M7): the argv fixtures re-captured from the census (tests/route.rs capture_argv_fixtures_from_the_census, gated):
# for each fixture the newest census row of extension EXT whose argv has the fixture's shape; only argv and
# ext_version are rewritten, route, reason, session and sanitised stay hand-owned (the KAT stays a real check). EXT
# counts only on the command line; a missing, empty or malformed one stops before cargo. Reads the census, no AWS.
argv-fixtures: ## S9 (M7): rewrite argv and ext_version of tests/fixtures/argv/*.json from the census rows of extension EXT (EXT=N.N.N, required, such as 2.1.302: each fixture takes the newest row of its shape at that version; route, reason, session and sanitised stay hand-owned), printing the fixtures found, kept (wire::argv::KEPT_FIXTURES: shapes the extension makes no more, left as they are) and missing (a row of S9's census, its thinking budget masked, counts for none) (part B: B7, after the Cursor checklist)
	@ext='$(call cmdline,EXT)'; case "$$ext" in '') echo "argv-fixtures: EXT is missing: make argv-fixtures EXT=2.1.302 (the extension version whose census rows to take)"; exit 2 ;; esac; \
	  printf '%s\n' "$$ext" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+' || { echo "argv-fixtures: EXT=$$ext is not N.N.N (such as 2.1.302)"; exit 2; }
	$(LAB_UNSET) AI_ENV_ARGV_CAPTURE=1 AI_ENV_ARGV_EXT='$(call cmdline,EXT)' $(CARGO) test -p $(PKG) --features bridge --test route -- --ignored --exact capture_argv_fixtures_from_the_census --nocapture --test-threads=1

doc-test: ## The README's and SKILL.md's sh doc-test blocks in their dry forms (tests/readme.rs; also part of make test)
	$(CARGO) test -p $(PKG) --features bridge --test readme

test-aws-readonly: ## Part A live checks, read-only (this identity, eu-central-1): TLS to the MicroVM proxy, managed images, ListMicrovms, GetMicrovm of an unknown id
	$(NO_KEY) $(LAB_UNSET) $(CARGO) test -p $(PKG) --features bridge --test aws --no-run
	$(LAB_UNSET) AI_ENV_AWS_TESTS=1 $(CARGO) test -p $(PKG) --features bridge --test aws -- --ignored readonly_ --test-threads=1 --nocapture

s4-smoke: ## T4.1 gate: three `ai-env vm smoke --max-duration 900 --json` passes (live, one Touch ID each); records appended to target/s4/smoke.jsonl
	@mkdir -p target/s4
	@for i in 1 2 3; do \
	  out=$$($(LAB_UNSET) $(AI_ENV) vm smoke --max-duration 900 --json) || { echo "$$out"; echo "s4-smoke: pass $$i failed"; exit 1; }; \
	  printf '%s\n' "$$out" >> target/s4/smoke.jsonl; \
	  grep -q '"backend":"sdk"' <<<"$$out" || { echo "$$out"; echo "s4-smoke: pass $$i did not use the SDK backend"; exit 1; }; \
	  echo "s4-smoke: pass $$i ok"; \
	done; echo "s4-smoke: 3/3 ok (target/s4/smoke.jsonl)"

s5-smoke: ## T5.1 gate: three `ai-env vm smoke --egress vpc --max-duration 900 --json` passes (live, one Touch ID each; backend sdk and egress_ok true: the VM echoed exactly the connector); records appended to target/s5/smoke.jsonl
	@mkdir -p target/s5
	@for i in 1 2 3; do \
	  out=$$($(LAB_UNSET) $(AI_ENV) vm smoke --egress vpc --max-duration 900 --json) || { echo "$$out"; echo "s5-smoke: pass $$i failed"; exit 1; }; \
	  printf '%s\n' "$$out" >> target/s5/smoke.jsonl; \
	  grep -q '"backend":"sdk"' <<<"$$out" || { echo "$$out"; echo "s5-smoke: pass $$i did not use the SDK backend"; exit 1; }; \
	  grep -q '"egress_ok":true' <<<"$$out" || { echo "$$out"; echo "s5-smoke: pass $$i: egress_ok is not true (the VM did not echo exactly the connector)"; exit 1; }; \
	  echo "s5-smoke: pass $$i ok"; \
	done; echo "s5-smoke: 3/3 ok (target/s5/smoke.jsonl)"

s6-smoke: ## T6.7 gate: three `ai-env vm smoke --egress vpc --exec --max-duration 900 --json` passes (live, one Touch ID each; backend sdk, egress_ok and exec_ok true: claude --version is the image's pin, id -u is 1000, 401 through the proxy, 6 proxy variables); records appended to target/s6/smoke.jsonl
	@mkdir -p target/s6
	@for i in 1 2 3; do \
	  out=$$($(LAB_UNSET) $(AI_ENV) vm smoke --egress vpc --exec --max-duration 900 --json) || { echo "$$out"; echo "s6-smoke: pass $$i failed"; exit 1; }; \
	  printf '%s\n' "$$out" >> target/s6/smoke.jsonl; \
	  grep -q '"backend":"sdk"' <<<"$$out" || { echo "$$out"; echo "s6-smoke: pass $$i did not use the SDK backend"; exit 1; }; \
	  grep -q '"egress_ok":true' <<<"$$out" || { echo "$$out"; echo "s6-smoke: pass $$i: egress_ok is not true (the VM did not echo exactly the connector)"; exit 1; }; \
	  grep -q '"exec_ok":true' <<<"$$out" || { echo "$$out"; echo "s6-smoke: pass $$i: exec_ok is not true (claude --version, id -u, the proxy or its variables: see exec_* above)"; exit 1; }; \
	  echo "s6-smoke: pass $$i ok"; \
	done; echo "s6-smoke: 3/3 ok (target/s6/smoke.jsonl)"

s7-smoke: ## T7.4 gate: three `ai-env vm smoke --egress vpc --exec --with-credential --max-duration 900 --json` passes (live; one Touch ID each with a current combined.env): backend sdk, egress_ok, exec_ok and cred_ok true (claude -p 'Reply OK' answered OK through the endpoint and the proxy with the delivered setup-token); records appended to target/s7/smoke.jsonl
	@mkdir -p target/s7
	@for i in 1 2 3; do \
	  out=$$($(LAB_UNSET) $(AI_ENV) vm smoke --egress vpc --exec --with-credential --max-duration 900 --json) || { echo "$$out"; echo "s7-smoke: pass $$i failed"; exit 1; }; \
	  printf '%s\n' "$$out" >> target/s7/smoke.jsonl; \
	  grep -q '"backend":"sdk"' <<<"$$out" || { echo "$$out"; echo "s7-smoke: pass $$i did not use the SDK backend"; exit 1; }; \
	  grep -q '"egress_ok":true' <<<"$$out" || { echo "$$out"; echo "s7-smoke: pass $$i: egress_ok is not true (the VM did not echo exactly the connector)"; exit 1; }; \
	  grep -q '"exec_ok":true' <<<"$$out" || { echo "$$out"; echo "s7-smoke: pass $$i: exec_ok is not true (see exec_problems)"; exit 1; }; \
	  grep -q '"cred_ok":true' <<<"$$out" || { echo "$$out"; echo "s7-smoke: pass $$i: cred_ok is not true (the credentialed claude -p did not answer OK)"; exit 1; }; \
	  echo "s7-smoke: pass $$i ok"; \
	done; echo "s7-smoke: 3/3 ok (target/s7/smoke.jsonl)"

# The live tests may allow github.com for workspace ai-env-test (live_egress_extra_and_removal): on every exit of the
# recipe (success, failure, Ctrl-C) the entry is removed again, a no-op when it is absent, so a killed test never leaves
# github.com allowed for every vpc VM. INT, TERM and HUP are trapped too: bash 3.2 kills itself without running the
# EXIT trap when its foreground child dies of an untrapped SIGINT. A removal that fails fails the target. S8 operators:
# egress allow writes the extras parameter, which only ai-env-deployer may, so the tests run under the deployer's key
# (infra/infra.mk's TIER); the tests and the binary they run are compiled first, outside the runner, without any key
# in their environment (D18: a dependency's build script never sees it), and the run under it finds them built.
# test-egress-run checks the same builds again, still without the key (a no-op after the wrapper's), so one typed by
# hand under a runner compiles nothing with the key either, the removal's operator CLI included.
test-egress: ## (deployer: asks once for its key, from Strongbox; the VMs' Touch IDs) S5 T5.2-T5.4: the live egress tests (#[ignore]d; AI_ENV_AWS_TESTS=1 AI_ENV_EGRESS_TESTS=1; a vpc VM, the proxy, Touch ID), measurements shown; every exit removes the test's github.com entry; a test that skips its proof fails the target
	$(NO_KEY) $(LAB_UNSET) $(CARGO) test -p $(PKG) --features bridge --test aws --no-run
	@$(call NOT_UNDER_I_OR_P,test-egress)
	@$(call TIER,deployer,test-egress) $(MAKE) --no-print-directory test-egress-run

test-egress-run:
	@$(IDENTITY) deployer test-egress
	@$(call NOT_UNDER_I_OR_P,test-egress)
	$(NO_KEY) $(LAB_UNSET) $(CARGO) test -p $(PKG) --features bridge --test aws --no-run
	@$(AI_ENV_BUILD)
	@log=$$(mktemp "$${TMPDIR:-/tmp}/ai-env-test-egress.XXXXXX") || exit 1; \
	  trap 'rm -f "$$log"; echo "test-egress: removing the test allowlist entry (ai-env egress allow ai-env-test github.com --remove)"; $(LAB_UNSET) $(AI_ENV) egress allow ai-env-test github.com --remove || { echo "test-egress: the removal FAILED: github.com may still be allowed for every vpc VM: run ai-env as deployer -- ai-env egress allow ai-env-test github.com --remove"; exit 1; }' EXIT; \
	  trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP; \
	  set -o pipefail; \
	  $(LAB_UNSET) AI_ENV_AWS_TESTS=1 AI_ENV_EGRESS_TESTS=1 $(CARGO) test -p $(PKG) --features bridge --test aws -- --ignored live_egress_ --test-threads=1 --nocapture 2>&1 | tee "$$log" || exit $$?; \
	  if grep -q 'skipped:' "$$log"; then echo "test-egress: a live egress test skipped its proof (its skipped: line above), so this is not a pass"; exit 1; fi

# The systemd case boots the proxy's user-data under a real systemd as PID 1 in a privileged container (Docker Desktop
# allows it); SYSTEMD=0 on the command line leaves it out.
test-proxy: ## S5: the proxy host in Docker (squid of AL2023 pinned by digest, the reload script, user-data; AI_ENV_PROXY_TESTS=1); SYSTEMD=0 skips the privileged systemd boot
	AI_ENV_PROXY_TESTS=1 $(if $(filter 0,$(call cmdline,SYSTEMD)),,AI_ENV_PROXY_SYSTEMD=1 )$(CARGO) test -p $(PKG) --features bridge --test proxy_docker -- --include-ignored --test-threads=1

# PREWARM=1 on the command line adds T8.6's offline half (S8): auth status in remote mode with the prewarm spawning a
# stand-in sibling, against the same world with the prewarm off and against a bare exec of the fake (10 ms each).
perf-wrapper: ## T1.2 overhead: ai-env-claude (release) vs a bare exec of the fake, 100 interleaved runs, median delta <= 10 ms; PREWARM=1 also the prewarm's on auth status (T8.6)
	AI_ENV_PERF_TESTS=1 $(CARGO) test --release -p $(PKG) --features bridge --test wrapper -- --ignored overhead --nocapture --test-threads=1
	$(if $(filter 1,$(call cmdline,PREWARM)),AI_ENV_PERF_TESTS=1 $(CARGO) test --release -p $(PKG) --features bridge --test prewarm -- --ignored overhead --nocapture --test-threads=1)

# The build never sees an operator key (D18): part B0 runs make install in the account root's terminal, its key there.
install: ## cargo install both bins (ai-env + ai-env-claude) into $(INSTALL_ROOT)/bin with the committed Cargo.lock; asserts one version
	$(NO_KEY) $(CARGO) install --path crates/$(PKG) --locked --root "$(INSTALL_ROOT)"
	@a=$$("$(INSTALL_ROOT)/bin/ai-env" --version); b=$$("$(INSTALL_ROOT)/bin/ai-env-claude" --version); echo "$$a / $$b"; \
	  test "$${a##* }" = "$${b##* }" || { echo "install: version skew between the two bins"; exit 1; }
	@case ":$$PATH:" in *":$(INSTALL_ROOT)/bin:"*) ;; *) echo "note: $(INSTALL_ROOT)/bin is not on PATH";; esac

# --lambda-dir: cargo-lambda otherwise writes under the cargo target directory (CARGO_TARGET_DIR when set), and the cp
# below would take a stale bootstrap; the old one is removed first, so a build that writes nothing fails at the cp.
# The cross-build runs without any operator key or marker (D18), whoever calls it.
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
	  ulimit -n 10240; $(NO_KEY) RUSTUP_TOOLCHAIN=$(TOOLCHAIN) "$$cl" lambda build --release --arm64 --lambda-dir target/lambda -p $(PKG) --bin ai-env --no-default-features --features shim
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
	  grep -q 'ai-env-cli@0.11.0 requires rustc 1.94.1' <<<"$$out" || { echo "$$out"; echo "expected the MSRV refusal"; exit 1; }; \
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

lint: clippy lint-negative ## clippy + grep guards clippy cannot express (Connector::Plain; no raw `ai-env:` line on the remote path, which speaks through bridge::voice; TLS/WS dialing — every client_async form — confined to $(TLS_ALLOW); a listener only in src/shim and src/bridge/panel; every tests/*.rs declared)
	@bad=$$(grep -rn 'Connector::Plain' crates/$(PKG)/src || true); test -z "$$bad" || { echo "$$bad"; echo "lint: Connector::Plain is forbidden"; exit 1; }
	@bad=$$(grep -nE '(eprintln!|eprint!|say|writeln!|write!)\(.*"ai-env: ' crates/$(PKG)/src/bridge/vm/run.rs crates/$(PKG)/src/bridge/vm/lock.rs crates/$(PKG)/src/bridge/agent/credential.rs crates/$(PKG)/src/bridge/creds.rs crates/$(PKG)/src/bridge/remote/*.rs || true); test -z "$$bad" || { echo "$$bad"; echo "lint: the remote path speaks through bridge::voice (no raw ai-env: line in vm/run.rs, vm/lock.rs, agent/credential.rs, creds.rs, remote/)"; exit 1; }
	@bad=$$(grep -rlE 'connect_async|client_async|Connector::Rustls|use_preconfigured_tls|ClientConfig::builder|aws_smithy_http_client' crates/$(PKG)/src | grep -vE '$(TLS_ALLOW)' || true); \
	  test -z "$$bad" || { echo "$$bad"; echo "lint: TLS/WS/SDK-HTTP dialing must live in $(TLS_ALLOW)"; exit 1; }
	@bad=$$(for f in $$(grep -rlE 'TcpListener::bind|axum::serve' crates/$(PKG)/src | grep -vE '^crates/$(PKG)/src/(shim/|bridge/panel/)'); do \
	  awk -v f="$$f" '/^#\[cfg\((all\()?test/{t=1} t&&/^}/{t=0;next} !t&&/TcpListener::bind|axum::serve/{print f":"FNR": "$$0}' "$$f"; done); \
	  test -z "$$bad" || { echo "$$bad"; echo "lint: a listener (TcpListener::bind, axum::serve) lives only in src/shim and src/bridge/panel (test modules aside)"; exit 1; }
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

# Fails closed (S11): `ai-env claude manifest` fetches the version's manifest.json and its signature (curl with a
# cleared environment) and writes them only when gpgv verifies the signature against the vendored release key alone
# (GOODSIG and a VALIDSIG whose last field, the primary key's fingerprint, is CLAUDE_GPG_FPR); no gpg branch, no
# unverified pin. `infra pin --expect-version` refuses a manifest of another version. VMs follow the Cursor bundle's
# claude with no deploy (ai-env claude status): the lock is the image's fallback.
claude-pin: ## Pin Claude Code CLAUDE_VERSION=<v> into image/claude.lock, the image's fallback claude, from its release manifest (gpgv against the vendored release key, fail-closed)
	@test -n "$(CLAUDE_VERSION)" || { echo "usage: make claude-pin CLAUDE_VERSION=<version>   (ai-env infra pin --bundle-version prints the installed Cursor bundle; VMs follow it with no deploy: ai-env claude status)"; exit 2; }
	@set -euo pipefail; d="$(IMAGE_OUT)/claude-pin/$(CLAUDE_VERSION)"; mkdir -p "$$d"; rm -f "$$d/manifest.json" "$$d/manifest.json.sig"; \
	  $(AI_ENV) claude manifest $(CLAUDE_VERSION) --out "$$d"; \
	  $(AI_ENV) infra pin --manifest "$$d/manifest.json" --lock "$(IMAGE_DIR)/claude.lock" --expect-version "$(CLAUDE_VERSION)"

# S11 (D2): the claude-facing Docker L2 tests on a claude under test, bind-mounted read-only over the local image's
# /usr/local/bin/claude (tests/docker_exec.rs and tests/shim_docker.rs: claude_under_test, expected_claude). ai-env
# claude admit runs it on a version's Linux build. No AWS, no Touch ID, no key (NO_KEY); its own target dir
# (target/claude-admit: LD-12), never target/debug's matrix.
claude-admit-docker: ## (no AWS, no Touch ID) S11: the claude-facing Docker L2 tests on CLAUDE_BIN, the Linux build of CLAUDE_VERSION (its SHA-256 CLAUDE_SHA256), bind-mounted over the local image's claude: ai-env claude admit runs it
	@test -n "$(CLAUDE_BIN)" && test -n "$(CLAUDE_VERSION)" && test -n "$(CLAUDE_SHA256)" || { echo "usage: make claude-admit-docker CLAUDE_BIN=<absolute path> CLAUDE_VERSION=<version> CLAUDE_SHA256=<sha256>   (ai-env claude admit runs it)"; exit 2; }
	@docker image inspect $(LOCAL_IMAGE) >/dev/null 2>&1 || { echo "claude-admit-docker: $(LOCAL_IMAGE) is missing: make image-build-local"; exit 2; }
	$(NO_KEY) CARGO_TARGET_DIR='$(CURDIR)/target/claude-admit' AI_ENV_DOCKER_TESTS=1 AI_ENV_DOCKER_BASE='$(BASE_IMAGE)' AI_ENV_DOCKER_IMAGE='$(LOCAL_IMAGE)' AI_ENV_DOCKER_SHIM='$(CURDIR)/image/ai-env' \
	  AI_ENV_CLAUDE_UNDER_TEST='$(CLAUDE_BIN)' AI_ENV_CLAUDE_UNDER_TEST_VERSION='$(CLAUDE_VERSION)' AI_ENV_CLAUDE_UNDER_TEST_SHA256='$(CLAUDE_SHA256)' \
	  $(CARGO) test -p $(PKG) --features bridge --test docker_exec --test shim_docker -- --ignored --exact --test-threads=1 l2_wrapper_remote_session_initializes_the_pinned_claude l2_claude_auth_status_json_is_logged_out_with_no_network l2_claude_version_matches_the_lock

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

# The image's build needs no AWS: its sub-makes and the CLI's version read (a cargo run) never see an operator key or
# the runner's marker (D18), whoever calls it (deploy's wrapper, test-docker, a make typed under a runner).
image-zip: ## vm-build, stage + scan, then a deterministic $(IMAGE_ZIP) and $(IMAGE_JSON) (sha256, S3 key, versions)
	$(NO_KEY) $(MAKE) vm-build
	$(NO_KEY) $(MAKE) image-stage-scan
	@set -euo pipefail; stage="$(STAGE)"; mkdir -p "$(IMAGE_OUT)"; \
	  zip_abs="$$(cd "$(IMAGE_OUT)" && pwd)/$$(basename "$(IMAGE_ZIP)")"; rm -f "$$zip_abs"; \
	  find "$$stage" -exec env TZ=UTC touch -h -t 198001010000 {} +; \
	  (cd "$$stage" && find . -mindepth 1 | sed 's|^\./||' | LC_ALL=C sort | TZ=UTC zip -X -q "$$zip_abs" -@); \
	  sha=$$(shasum -a 256 "$$zip_abs" | cut -d' ' -f1); \
	  claude=$$(sed -n 's/^CLAUDE_VERSION=//p' "$$stage/claude.lock"); \
	  shim=$$($(NO_KEY) $(AI_ENV) --version | awk '{print $$NF}'); \
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

# test-docker needs no AWS: its every step runs without an operator key or the runner's marker (D18), also as the first
# goal of `ai-env as deployer -- make test-docker deploy` or in the root's terminal (B0.3), so neither its builds nor
# Docker nor its tests ever see one.
test-docker: ## T3.1: image-zip + image-build-local, then the opt-in Docker tests (L1 base image + shim, L2 local image, and S6 T6.7: the real `vm exec` on L2 through the fake endpoint); stamps the zip for deploy
	$(NO_KEY) $(MAKE) image-zip
	$(NO_KEY) $(MAKE) image-build-local
	$(NO_KEY) AI_ENV_DOCKER_TESTS=1 AI_ENV_DOCKER_BASE='$(BASE_IMAGE)' AI_ENV_DOCKER_IMAGE='$(LOCAL_IMAGE)' AI_ENV_DOCKER_SHIM='$(CURDIR)/image/ai-env' \
	  $(CARGO) test -p $(PKG) --no-default-features --features shim --test shim_docker -- --ignored --test-threads=1
	$(NO_KEY) AI_ENV_DOCKER_TESTS=1 AI_ENV_DOCKER_BASE='$(BASE_IMAGE)' AI_ENV_DOCKER_IMAGE='$(LOCAL_IMAGE)' AI_ENV_DOCKER_SHIM='$(CURDIR)/image/ai-env' \
	  $(CARGO) test -p $(PKG) --test docker_exec -- --ignored --test-threads=1
	@sha=$$(shasum -a 256 "$(IMAGE_ZIP)" | cut -d' ' -f1); echo "$$sha" > "$(DOCKER_STAMP)"; echo "test-docker: ok, stamped $$sha"

check-base-image: ## (ops: one Touch ID, none under ai-env as) T3.5: the pinned managed base image (baseImage in $(IMAGE_CONFIG)) is AVAILABLE
	@$(BASE_CHECK) || { echo "check-base-image: $(BASE_MISSING)"; exit 1; }
	@$(AI_ENV_BUILD)
	$(AI_ENV) infra base-image --name $(BASE_NAME) --version $(BASE_VERSION)

# P13-P16 (S5, read-only, both phases): the aws CLI's lambda-core (connector-wait and the probe use it), VPC Block
# Public Access off, or the egress VPC (tag Project=ai-env, its CIDR) excluded with allow-egress or allow-bidirectional
# (the proxy reaches the internet through its IGW, which ingress-only blocks as well: only NAT gateway and egress-only
# IGW traffic leaves), room for the egress VPC under the VPC quota, and whether the service-linked role the
# connector's first create makes exists (recorded only). Under
# pipefail no row pipes a tool into `grep -q`: grep stops at the first match and the writer's SIGPIPE would fail it.
# P8 (S8 operators): PHASE=b admits only the stack's deployer, or the account root for the bootstrap or with BREAKGLASS=1
# on the command line (ops.sh identity deployer: its one line is the row; a break-glass row is [-  ], loud but no
# refusal); PHASE=a only says who this shell's own credentials are (the agent's, in its own account). The operator CLI
# P9-P11 run is built first, without any key (D18: the preflight runs under ai-env as, deploy's or typed).
s3-preflight: ## S3/S5 preconditions P1-P16 (PHASE=a: build + read-only checks; PHASE=b: also the deploy ones, P8 the deploy identity: make deploy runs it as the deployer; alone: ai-env as deployer -- make s3-preflight PHASE=b); one row each, exit 1 on any [NO ]
	@$(AI_ENV_BUILD)
	@set -uo pipefail; phase="$(or $(PHASE),a)"; bad=0; \
	  row() { printf '%s %s\n' "$$1" "$$2"; [ "$$1" = "[NO ]" ] && bad=1; true; }; \
	  if out=$$($(SUBMAKE) -s --no-print-directory vm-build-pick 2>&1); then row "[ok ]" "P1 cargo-lambda: $$out"; else row "[NO ]" "P1 cargo-lambda: $$out"; fi; \
	  if targets=$$(rustup +$(TOOLCHAIN) target list --installed) && grep -qx '$(TARGET)' <<<"$$targets" && test -x $(LLVM_BIN)/llvm-nm; then row "[ok ]" "P2 $(TARGET) target, llvm tools"; else row "[NO ]" "P2 rustup target add $(TARGET) --toolchain $(TOOLCHAIN); brew install llvm"; fi; \
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
	  if node -e 'process.exit(+process.versions.node.split(".")[0] >= 20 ? 0 : 1)' 2>/dev/null && command -v npm >/dev/null && command -v zip >/dev/null; then row "[ok ]" "P4 node $$(node --version), npm, zip$$(test -f /opt/homebrew/bin/gpgv || test -f /usr/local/bin/gpgv && echo ', gpgv' || echo ' (no gpgv: make claude-pin and ai-env claude admit fail closed: brew install gnupg)')"; else row "[NO ]" "P4 node >= 20, npm and zip are required"; fi; \
	  claude=$$(sed -n 's/^CLAUDE_VERSION=//p' image/claude.lock); \
	  for u in "$(CLAUDE_RELEASES)/$$claude/manifest.json" https://public.ecr.aws/v2/ https://cdn.amazonlinux.com/al2023/core/mirrors/latest/aarch64/mirror.list; do \
	    code=$$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$$u" 2>/dev/null || echo 000); \
	    case "$$code" in 2*|3*|401) row "[ok ]" "P5 reachable ($$code) $$u";; *) row "[NO ]" "P5 unreachable ($$code) $$u";; esac; done; \
	  if [ "$$phase" = b ]; then \
	    if stacks=$$(cd infra && pulumi stack ls --json 2>/dev/null) && grep -q '"name": *"$(STACK)"' <<<"$$stacks"; then row "[ok ]" "P6 pulumi stack $(STACK) ($$(pulumi whoami -v 2>/dev/null | sed -n 's/^Backend URL: *//p'))"; else row "[NO ]" "P6 pulumi stack $(STACK) missing: cd infra && pulumi stack init $(STACK)"; fi; fi; \
	  if pulumi plugin ls --json 2>/dev/null | node -e 'const p=JSON.parse(require("fs").readFileSync(0,"utf8"));const has=(n,v)=>p.some(x=>x.name===n&&x.kind==="resource"&&x.version===v);process.exit(has("aws","7.10.0")&&has("aws-native","1.79.0")?0:1)'; then row "[ok ]" "P7 pulumi plugins aws 7.10.0, aws-native 1.79.0"; else row "[NO ]" "P7 pulumi plugin install resource aws 7.10.0; pulumi plugin install resource aws-native 1.79.0"; fi; \
	  if [ "$$phase" = b ]; then \
	    if out=$$($(IDENTITY) deployer 2>&1); then case "$$out" in BREAK-GLASS:*) row "[-  ]" "P8 $$out";; *) row "[ok ]" "P8 deploy identity $$out";; esac; \
	    else row "[NO ]" "P8 deploy identity $$out"; fi; \
	  elif arn=$$(aws sts get-caller-identity --region $(REGION) --query Arn --output text 2>/dev/null); then row "[ok ]" "P8 identity $${arn##*:} (PHASE=a reads only; PHASE=b admits only the stack's deployer)"; \
	  else row "[NO ]" "P8 no AWS credentials (PHASE=a: this shell's own, the agent's; on this Mac: ai-env as ops -- make s3-preflight)"; fi; \
	  if [ "$$phase" = b ]; then \
	    if out=$$($(AI_ENV) creds aws-set --check 2>&1); then row "[ok ]" "P9 runtime-key preconditions"; else row "[-  ]" "P9 runtime-key preconditions not met yet (needed by make runtime-key, not by deploy)"; fi; fi; \
	  if out=$$($(AI_ENV) infra pin --check-bundle --lock image/claude.lock 2>&1); then row "[ok ]" "P10 $$(echo "$$out" | tail -1)"; \
	  else rc=$$?; if [ $$rc -eq 3 ]; then row "[-  ]" "P10 $$(echo "$$out" | tail -1)"; else row "[NO ]" "P10 $$(echo "$$out" | tail -1)"; fi; fi; \
	  if ! $(BASE_CHECK); then row "[NO ]" "P11 $(BASE_MISSING)"; \
	  elif out=$$($(AI_ENV) infra base-image --name $(BASE_NAME) --version $(BASE_VERSION) 2>&1); then row "[ok ]" "P11 $$(echo "$$out" | tail -1)"; else row "[NO ]" "P11 $$(echo "$$out" | tail -1)"; fi; \
	  if [ "$$phase" = b ]; then \
	    zsha=$$(test -f "$(IMAGE_ZIP)" && shasum -a 256 "$(IMAGE_ZIP)" | cut -d' ' -f1); \
	    if [ "$(call cmdline,EXPECT_BUILD_FAILURE)" = 1 ]; then row "[-  ]" "P12 NOT CHECKED: EXPECT_BUILD_FAILURE=1 on the command line (the T3.4 negative): this zip is deployed whether or not make test-docker passed for it"; \
	    elif [ -n "$$zsha" ] && [ "$$(cat "$(DOCKER_STAMP)" 2>/dev/null)" = "$$zsha" ]; then row "[ok ]" "P12 make test-docker passed for this zip"; else row "[NO ]" "P12 make test-docker has not passed for the current $(IMAGE_ZIP)"; fi; fi; \
	  if out=$$(aws lambda-core list-network-connectors --region $(REGION) --endpoint-url $(LAMBDA_CORE_URL) --output json 2>&1); then row "[ok ]" "P13 aws lambda-core list-network-connectors answers"; \
	  else case "$$out" in \
	    *"Invalid choice"*) row "[NO ]" "P13 this aws CLI has no lambda-core service (botocore lambda-core/2026-04-30): update it";; \
	    *) row "[NO ]" "P13 aws lambda-core list-network-connectors failed: $$(grep -m1 -i error <<<"$$out" | cut -c1-160)";; \
	  esac; fi; \
	  if m=$$(aws ec2 describe-vpc-block-public-access-options --region $(REGION) --endpoint-url $(EC2_URL) --query VpcBlockPublicAccessOptions.InternetGatewayBlockMode --output text 2>/dev/null); then \
	    if [ "$$m" = off ]; then row "[ok ]" "P14 VPC Block Public Access off"; \
	    elif ! vpcs=$$(aws ec2 describe-vpcs --filters Name=tag:Project,Values=ai-env --region $(REGION) --endpoint-url $(EC2_URL) --query 'Vpcs[].[VpcId,CidrBlock]' --output text 2>/dev/null) \
	      || ! ex=$$(aws ec2 describe-vpc-block-public-access-exclusions --region $(REGION) --endpoint-url $(EC2_URL) --query 'VpcBlockPublicAccessExclusions[].[ResourceArn,InternetGatewayExclusionMode,State]' --output text 2>/dev/null); then \
	      row "[NO ]" "P14 VPC Block Public Access is $$m, and its exclusions or the egress VPC cannot be read (ec2 describe-vpc-block-public-access-exclusions, describe-vpcs)"; \
	    else evpc=$$(awk -v c="$(EGRESS_VPC_CIDR)" 'c != "" && $$2 == c { v = $$1 } END { print v }' <<<"$$vpcs"); \
	      if [ -n "$$evpc" ] && awk -v s=":vpc/$$evpc" 'length($$1) >= length(s) && substr($$1, length($$1) - length(s) + 1) == s && ($$2 == "allow-egress" || $$2 == "allow-bidirectional") && ($$3 == "create-complete" || $$3 == "update-complete") { f = 1 } END { exit !f }' <<<"$$ex"; then \
	        row "[ok ]" "P14 VPC Block Public Access is $$m, and the egress VPC $$evpc is excluded (allow-egress or allow-bidirectional)"; \
	      else row "[NO ]" "P14 VPC Block Public Access is $$m: it blocks the proxy's internet gateway (ingress-only lets only NAT gateway and egress-only IGW traffic out): turn it off, or exclude the egress VPC$${evpc:+ $$evpc} (allow-egress; it must exist first)"; fi; \
	    fi; \
	  else row "[NO ]" "P14 cannot read the VPC Block Public Access options (ec2 describe-vpc-block-public-access-options)"; fi; \
	  if vpcs=$$(aws ec2 describe-vpcs --region $(REGION) --endpoint-url $(EC2_URL) --query 'Vpcs[].[VpcId,CidrBlock]' --output text 2>/dev/null); then \
	    n=$$(grep -c . <<<"$$vpcs"); \
	    q=$$(aws service-quotas get-service-quota --service-code vpc --quota-code L-F678F1CE --region $(REGION) --query Quota.Value --output text 2>/dev/null); q=$${q%%.*}; qn=""; \
	    case "$$q" in ''|*[!0-9]*) q=5; qn=" (quota L-F678F1CE unreadable: the default 5)";; esac; \
	    if awk -v c="$(EGRESS_VPC_CIDR)" 'c != "" && $$2 == c { f = 1 } END { exit !f }' <<<"$$vpcs"; then row "[ok ]" "P15 $$n of $$q VPCs$$qn, one of them $(EGRESS_VPC_CIDR) (the egress VPC exists)"; \
	    elif [ "$$n" -lt "$$q" ]; then row "[ok ]" "P15 $$n of $$q VPCs$$qn: room for the egress VPC"; \
	    else row "[NO ]" "P15 $$n of $$q VPCs$$qn: the egress VPC needs one more (delete an unused VPC, or raise quota L-F678F1CE)"; fi; \
	  else row "[NO ]" "P15 cannot count the VPCs (ec2 describe-vpcs)"; fi; \
	  if out=$$(aws iam get-role --role-name AWSServiceRoleForLambda --region $(REGION) --query Role.Arn --output text 2>&1); then row "[ok ]" "P16 AWSServiceRoleForLambda present"; \
	  elif grep -q NoSuchEntity <<<"$$out"; then row "[ok ]" "P16 AWSServiceRoleForLambda absent: the connector's first create makes it (the deploy policy allows iam:CreateServiceLinkedRole for lambda.amazonaws.com)"; \
	  else row "[-  ]" "P16 AWSServiceRoleForLambda not determined (iam get-role: $$(tail -1 <<<"$$out" | cut -c1-120))"; fi; \
	  exit $$bad

# Internal: print the cargo-lambda vm-build would use (s3-preflight P1).
vm-build-pick:
	@cl="$(CARGO_LAMBDA)"; ver() { "$$1" lambda --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1; }; \
	  ok() { v=$$(ver "$$1"); test -n "$$v" && test "$$(printf '%s\n%s\n' "$(CARGO_LAMBDA_MIN)" "$$v" | sort -t. -k1,1n -k2,2n -k3,3n | head -1)" = "$(CARGO_LAMBDA_MIN)"; }; \
	  if [ -z "$$cl" ]; then for c in $$(which -a cargo-lambda 2>/dev/null) "$$HOME/.cargo/bin/cargo-lambda"; do if [ -x "$$c" ] && ok "$$c"; then cl="$$c"; break; fi; done; fi; \
	  if [ -n "$$cl" ] && ok "$$cl"; then echo "$$cl $$(ver "$$cl")"; else echo "none >= $(CARGO_LAMBDA_MIN) (cargo install cargo-lambda --locked --version $(CARGO_LAMBDA_MIN))"; exit 1; fi

# gates runs the tree's ai-env (cargo run, whatever AI_ENV says), built first without any key (D18: under ai-env as
# ops, the run's compile would otherwise see the key).
gates: ## (ops: one Touch ID, none under ai-env as; G7 simulates the deployer) Run the G1–G8 pre-code gates via `ai-env gates` (writes plans/gates.md); GATES_ARGS='--only G1,G3' re-measures a subset without writing
	@$(NO_KEY) $(CARGO) build -q -p $(PKG) --bin ai-env
	$(CARGO) run -q -p $(PKG) --bin ai-env -- gates $(GATES_ARGS)

# S8 acceptance (plans/v6-microvm-bridge.md §6, the S8 subset), live on this Mac: the pair `make install` put in
# ACCEPT_BIN (a relative one is taken from this directory), as Cursor runs it, against this Mac's bridge root. Each
# step is one recipe line of acceptance-run, so each negative is its own one-liner: its shell drops the lab knobs and
# the wrapper's own switches (the kill switch, the mode, the VM pin, the mirror root), works in a directory of its own
# under ACCEPT_DIR, removes it on every exit (ACCEPT_DIR too once empty, target/s8 too when the run made it) and stops
# the target with one "acceptance: STEP: ..." line. The fixture repositories are built at run time with no user
# or system git config (no hook, no signing), the tripwire's value with printf. S8 operators: the steps run as ai-env-ops
# (infra/infra.mk's TIER: credentials/ops.env's one Touch ID first, so doctor's AWS rows run); then the two Touch IDs
# of the runtime key come last (vm smoke, vm list). Under make -i a failed step would be ignored, the next ones would
# run (the Touch IDs among them) and the last line would say ok, and under make -p acceptance-run's make, the runner's,
# would print the ops key in its data base: the wrapper's first line is a $(error) that make expands before its runner
# or any step runs, -i or not (on MAKE_SWITCHES; under -k a failed line still ends the recipe), with infra.mk's -p
# refusal after it. The VM's own negatives (a 9418 token used against 8080, curl without the proxy from a VM shell,
# ai-env vm list inside the VM) are part B's.
ACCEPT_BIN   ?= $(INSTALL_ROOT)/bin
ACCEPT_DIR   := target/s8/acceptance
# A Cursor session's stream-json argv (the stand-in claude only records it).
ACCEPT_ARGV  := --output-format stream-json --verbose --input-format stream-json --permission-prompt-tool stdio --permission-mode default
# One step's shell, $(1) its name: `a` its directory, `ai` and `wrap` the pair (absolute: the steps change directory),
# `bridge` the bridge root; on exit it also removes ACCEPT_DIR once empty, and target/s8 once empty when make found it
# absent (make expands every line of the recipe before the first runs); `fail` says why and exits 1; `repo DIR`
# commits what DIR holds; `standin DIR` writes DIR/claude, which records its pid and argv in DIR/ran and exits 0
# (\043 is the shebang's first character).
ACCEPT_SH     = set -uo pipefail; unset $(LAB_KNOBS) AI_ENV_BRIDGE_LOCAL AI_ENV_BRIDGE_MODE AI_ENV_BRIDGE_VM AI_ENV_BRIDGE_MIRROR_ROOT; \
                a="$(CURDIR)/$(ACCEPT_DIR)/$(1)"; ai="$(if $(filter /%,$(ACCEPT_BIN)),,$(CURDIR)/)$(ACCEPT_BIN)/ai-env"; wrap="$(if $(filter /%,$(ACCEPT_BIN)),,$(CURDIR)/)$(ACCEPT_BIN)/ai-env-claude"; bridge="$(BRIDGE_DIR_SH)"; \
                rm -rf "$$a"; mkdir -p "$$a" || exit 1; \
                trap 'rm -rf "$$a"; rmdir "$(CURDIR)/$(ACCEPT_DIR)" $(if $(wildcard $(dir $(ACCEPT_DIR))),,"$(CURDIR)/$(dir $(ACCEPT_DIR))") 2>/dev/null; true' EXIT; trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP; \
                fail() { echo "acceptance: $(1): $$*"; exit 1; }; \
                git_() { env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 git -c user.name=ai-env-acceptance -c user.email=acceptance@ai-env.invalid "$$@"; }; \
                repo() { git_ init -q -b main "$$1" && git_ -C "$$1" add -A && git_ -C "$$1" commit -q -m fixture; }; \
                standin() { printf '\043!/bin/sh\necho "$$$$ $$*" > "%s/ran"\nexit 0\n' "$$1" > "$$1/claude" && chmod 755 "$$1/claude"; };

acceptance: ## (ops: one Touch ID first, then the smoke's two) S8 acceptance, live (v6 §6, the S8 subset; part B, after make install: the installed pair, or ACCEPT_BIN=DIR): [workspaces].roots must hold target/s8, checked first; doctor exits 0 in eu-central-1 (its AWS rows as ai-env-ops), ai-env and ai-env-claude are one version, creds status; then the negatives, each its own line: (a) a remote-mode session outside the roots execs the stand-in claude (census route local, reason outside_roots), (b) an AKIA-shaped value in a tracked file and (c) a committed bypassPermissions each make box seed --dry-run exit 9 naming it, (d) no egress connector: the remote wrapper refuses at the precheck, exit 9 (no Touch ID, no unseal row; it asks for vpc egress whatever [egress].require says), and on its line (h) [egress].require = true: vm run without --egress exits 9 from its plan, before any Touch ID or AWS call (a scratch bridge.toml in the step's directory names no connector, and an image of the example account), (e) AI_ENV_BRIDGE_LOCAL=1 execs the stand-in with no census row, (f) AWS_REGION=eu-west-3 leaves eu-central-1, (g) ai-env alone: doctor [NO ] exit 1, wrapper install exit 5; last vm smoke --max-duration 900, then vm list holds none of its VM: the runtime key's two Touch IDs, nothing between the ops key's and them needs one; a VM's own negatives (a 9418 token on 8080, curl without the proxy, ai-env vm list in the VM) are part B's; target/s8/acceptance removed on every exit (target/s8 too when the run made it); refused under make -i or -p
	@$(if $(findstring i,$(MAKE_SWITCHES)),$(error acceptance: not under make -i (a failed step would be ignored: the next ones would run and the last line say ok): run make acceptance without it))$(call NOT_UNDER_P,acceptance)
	@$(call TIER,ops,acceptance) $(MAKE) --no-print-directory acceptance-run

acceptance-run:
	@$(if $(findstring i,$(MAKE_SWITCHES)),$(error acceptance: not under make -i (a failed step would be ignored: the next ones would run and the last line say ok): run make acceptance without it))$(call NOT_UNDER_P,acceptance)
	@$(call ACCEPT_SH,roots) test -x "$$ai" && test -x "$$wrap" || fail "no ai-env and ai-env-claude in $(ACCEPT_BIN): make install first (or ACCEPT_BIN=DIR)"; \
	  printf 'acceptance fixture\n' > "$$a/README.md"; repo "$$a" > /dev/null || fail "git could not make the fixture repository $$a"; \
	  out=$$("$$ai" box seed "$$a" --dry-run 2>&1); rc=$$?; \
	  if [ $$rc -ne 0 ]; then cfg="$${AI_ENV_BRIDGE_CONFIG:-$$bridge/bridge.toml}"; printf '%s\n' "$$out"; \
	    fail "box seed --dry-run of a clean fixture exited $$rc: [workspaces].roots of $$cfg must hold target/s8 (part B, P0); its roots: $$(awk '/^[[:space:]]*roots[[:space:]]*=/ { p = 1 } p { printf "%s ", $$0 } p && /]/ { exit }' "$$cfg" 2>/dev/null)"; fi; \
	  echo "acceptance: roots: ok (box seed --dry-run plans a fixture under $(ACCEPT_DIR): no AWS call, no Touch ID)"
	@$(call ACCEPT_SH,doctor) out=$$("$$ai" doctor 2>&1); rc=$$?; printf '%s\n' "$$out"; \
	  test $$rc -eq 0 || fail "ai-env doctor exited $$rc (its rows above)"; \
	  grep -qF 'region eu-central-1 (pinned in code)' <<<"$$out" || fail "doctor shows no effective region eu-central-1"; \
	  echo "acceptance: doctor: ok (exit 0, region eu-central-1)"
	@$(call ACCEPT_SH,version) v1=$$("$$ai" --version) && v2=$$("$$wrap" --version) || fail "--version failed"; \
	  test "$${v1##* }" = "$${v2##* }" || fail "version skew: $$v1, $$v2 (make install)"; \
	  echo "acceptance: version: ok ($$v1, $$v2)"
	@$(call ACCEPT_SH,creds) out=$$("$$ai" creds status 2>&1); rc=$$?; printf '%s\n' "$$out"; \
	  test $$rc -eq 0 || fail "ai-env creds status exited $$rc"; \
	  grep -qF 'setup-token.env: sealed' <<<"$$out" || fail "no sealed setup-token (ai-env creds setup-token)"; \
	  ! grep -qF '[NO ]' <<<"$$out" || fail "a [NO ] row above"; \
	  echo "acceptance: creds: ok (the setup-token sealed; no Touch ID)"
	@$(call ACCEPT_SH,outside-roots) standin "$$a" || fail "cannot write the stand-in claude"; \
	  (cd / && exec env AI_ENV_BRIDGE_MODE=remote "$$wrap" "$$a/claude" $(ACCEPT_ARGV)) < /dev/null > "$$a/out" 2>&1 & pid=$$!; wait $$pid; rc=$$?; \
	  test $$rc -eq 0 || fail "ai-env-claude exited $$rc: $$(cat "$$a/out")"; \
	  test "$$(cat "$$a/ran" 2>/dev/null)" = "$$pid $(ACCEPT_ARGV)" || fail "the stand-in claude did not run in place of ai-env-claude (pid $$pid) with the session's argv"; \
	  rows=$$("$$ai" wrapper census --json) || fail "ai-env wrapper census failed"; row=$$(grep -F "\"pid\":$$pid," <<<"$$rows" | tail -1); \
	  grep -qF '"route":"local"' <<<"$$row" && grep -qF '"reason":"outside_roots"' <<<"$$row" || fail "the census row of pid $$pid is not route local, reason outside_roots: $${row:-none}"; \
	  echo "acceptance: outside-roots: ok (a remote-mode session from / exec'd the stand-in claude; census route local, reason outside_roots)"
	@$(call ACCEPT_SH,planted-key) key=$$(printf '%s%s' AKIA "$$(printf 'Q7ZT%.0s' 1 2 3 4)"); printf 'aws_access_key_id = %s\n' "$$key" > "$$a/deploy.conf"; \
	  repo "$$a" > /dev/null || fail "git could not make the fixture repository $$a"; \
	  out=$$("$$ai" box seed "$$a" --dry-run 2>&1); rc=$$?; \
	  ! grep -qF "$${key#AKIA}" <<<"$$out" || fail "box seed --dry-run shows the planted value"; \
	  test $$rc -eq 9 || fail "box seed --dry-run exited $$rc, not 9: $$out"; \
	  grep -qF 'HEAD:deploy.conf' <<<"$$out" && grep -qF 'rule aws-access-key-id' <<<"$$out" || fail "the refusal names neither HEAD:deploy.conf nor its rule: $$out"; \
	  echo "acceptance: planted-key: ok (exit 9 naming HEAD:deploy.conf and its rule, never the value)"
	@$(call ACCEPT_SH,bypass-settings) mkdir -p "$$a/.claude"; printf '{"permissions": {"defaultMode": "bypassPermissions"}}\n' > "$$a/.claude/settings.json"; \
	  repo "$$a" > /dev/null || fail "git could not make the fixture repository $$a"; \
	  out=$$("$$ai" box seed "$$a" --dry-run 2>&1); rc=$$?; \
	  test $$rc -eq 9 || fail "box seed --dry-run exited $$rc, not 9: $$out"; \
	  grep -qF 'HEAD:.claude/settings.json' <<<"$$out" && grep -qF 'key permissions.defaultMode' <<<"$$out" || fail "the refusal names neither HEAD:.claude/settings.json nor its key permissions.defaultMode: $$out"; \
	  echo "acceptance: bypass-settings: ok (exit 9 naming the key permissions.defaultMode)"
	@$(call ACCEPT_SH,egress-required) cfg="$${AI_ENV_BRIDGE_CONFIG:-$$bridge/bridge.toml}"; test -f "$$cfg" || fail "no bridge.toml at $$cfg"; \
	  sed -E '/^[[:space:]]*["'\'']?(egress_connector_arn|require)["'\'']?[[:space:]]*=/d' "$$cfg" > "$$a/bridge.toml" || fail "cannot copy $$cfg"; \
	  body=$$(sed 's/#.*//' "$$a/bridge.toml"); ! grep -qE 'egress_connector_arn|(^|[^A-Za-z0-9_])require[[:space:]]*=' <<<"$$body" || fail "the copy of $$cfg still names egress_connector_arn or require (a form this copy does not edit): nothing was run"; \
	  mkdir -p "$$a/repo"; printf 'acceptance fixture\n' > "$$a/repo/README.md"; repo "$$a/repo" > /dev/null || fail "git could not make the fixture repository $$a/repo"; \
	  standin "$$a" || fail "cannot write the stand-in claude"; seen=$$(wc -l 2>/dev/null < "$$bridge/audit.jsonl" || echo 0); \
	  (cd "$$a/repo" && exec env AI_ENV_BRIDGE_CONFIG="$$a/bridge.toml" AI_ENV_BRIDGE_MODE=remote "$$wrap" "$$a/claude" $(ACCEPT_ARGV)) < /dev/null > "$$a/out" 2>&1 & pid=$$!; wait $$pid; rc=$$?; \
	  test $$rc -eq 9 && grep -qF 'egress connector required' "$$a/out" || fail "ai-env-claude exited $$rc, not 9 naming the egress connector: $$(cat "$$a/out")"; \
	  test ! -e "$$a/ran" || fail "the stand-in claude ran: a session under the roots in remote mode runs no Mac binary"; \
	  unseals=$$(tail -n +$$((seen + 1)) "$$bridge/audit.jsonl" 2>/dev/null | grep -F '"event":"credential_unseal"' | grep -cF "\"pid\":$$pid," || true); \
	  test "$${unseals:-0}" = 0 || fail "$$unseals credential_unseal audit row(s) of pid $$pid: a credential was unsealed"; \
	  rows=$$("$$ai" wrapper census --json) || fail "ai-env wrapper census failed"; row=$$(grep -F "\"pid\":$$pid," <<<"$$rows" | grep -F '"end":' | tail -1); \
	  grep -qF 'step:precheck' <<<"$$row" && ! grep -qF 'touchid=' <<<"$$row" || fail "the census end row of pid $$pid shows no refusal at the precheck before any Touch ID: $${row:-none}"; \
	  printf '[aws]\nimage_arn = "arn:aws:lambda:eu-central-1:%s:microvm-image:ai-env-acceptance"\n\n[egress]\nrequire = true\n' "$$(printf '%s%s' 123456 789012)" > "$$a/require.toml" || fail "cannot write $$a/require.toml"; \
	  (exec env AI_ENV_BRIDGE_CONFIG="$$a/require.toml" "$$ai" vm run) < /dev/null > "$$a/run.out" 2>&1 & pid=$$!; wait $$pid; rc=$$?; \
	  test $$rc -eq 9 && grep -qF 'egress connector required' "$$a/run.out" || fail "(h) ai-env vm run without --egress under [egress].require = true exited $$rc, not 9 naming the egress connector: $$(cat "$$a/run.out")"; \
	  vmrows=$$(tail -n +$$((seen + 1)) "$$bridge/audit.jsonl" 2>/dev/null | grep -F "\"pid\":$$pid," | grep -cF '"event":"vm_' || true); \
	  test "$${vmrows:-0}" = 0 || fail "(h) $$vmrows vm audit row(s) of pid $$pid: vm run went past its plan"; \
	  echo "acceptance: egress-required: ok (no egress connector: the remote wrapper refused at the precheck: exit 9, no Touch ID, no credential_unseal row; (h) [egress].require = true: vm run without --egress refused by its plan, exit 9 before any Touch ID or AWS call)"
	@$(call ACCEPT_SH,kill-switch) mkdir -p "$$a/repo"; printf 'acceptance fixture\n' > "$$a/repo/README.md"; repo "$$a/repo" > /dev/null || fail "git could not make the fixture repository $$a/repo"; \
	  standin "$$a" || fail "cannot write the stand-in claude"; \
	  (cd "$$a/repo" && exec env AI_ENV_BRIDGE_LOCAL=1 AI_ENV_BRIDGE_MODE=remote "$$wrap" "$$a/claude" $(ACCEPT_ARGV)) < /dev/null > "$$a/out" 2>&1 & pid=$$!; wait $$pid; rc=$$?; \
	  test $$rc -eq 0 && test ! -s "$$a/out" || fail "ai-env-claude exited $$rc saying: $$(cat "$$a/out")"; \
	  test "$$(cat "$$a/ran" 2>/dev/null)" = "$$pid $(ACCEPT_ARGV)" || fail "the stand-in claude did not run in place of ai-env-claude (pid $$pid) with the session's argv"; \
	  rows=$$("$$ai" wrapper census --json) || fail "ai-env wrapper census failed"; hit=$$(grep -F "\"pid\":$$pid," <<<"$$rows" | grep -F "\"cwd\":\"$$a/repo\""); \
	  test -z "$$hit" || fail "a census row of pid $$pid: the kill switch records nothing: $$hit"; \
	  echo "acceptance: kill-switch: ok (AI_ENV_BRIDGE_LOCAL=1 under the roots in remote mode: the plain exec, no census row, no config read, no AWS call)"
	@$(call ACCEPT_SH,region) out=$$(AWS_REGION=eu-west-3 "$$ai" doctor 2>&1); rc=$$?; \
	  test $$rc -eq 0 || { printf '%s\n' "$$out"; fail "doctor with AWS_REGION=eu-west-3 exited $$rc"; }; \
	  grep -qF 'region eu-central-1 (pinned in code)  <- env AWS_REGION=eu-west-3 ignored (region pinned to eu-central-1)' <<<"$$out" || { printf '%s\n' "$$out"; fail "doctor with AWS_REGION=eu-west-3 does not say the variable is ignored for eu-central-1"; }; \
	  echo "acceptance: region: ok (AWS_REGION=eu-west-3 ignored, eu-central-1 pinned)"
	@$(call ACCEPT_SH,lone-ai-env) cp "$$ai" "$$a/ai-env" || fail "cannot copy $$ai"; \
	  p=; IFS=:; for d in $$PATH; do if [ -n "$$d" ] && [ ! -e "$$d/ai-env-claude" ]; then p="$${p:+$$p:}$$d"; fi; done; unset IFS; \
	  out=$$(PATH="$$p" "$$a/ai-env" doctor 2>&1); rc=$$?; \
	  test $$rc -eq 1 && grep -qF '[NO ] ai-env-claude missing' <<<"$$out" || { printf '%s\n' "$$out"; fail "doctor of ai-env alone exited $$rc (1 with [NO ] ai-env-claude missing wanted)"; }; \
	  out=$$(PATH="$$p" "$$a/ai-env" wrapper install 2>&1); rc=$$?; \
	  test $$rc -eq 5 || fail "wrapper install of ai-env alone exited $$rc, not 5: $$out"; \
	  echo "acceptance: lone-ai-env: ok (ai-env without ai-env-claude: doctor [NO ] exit 1, wrapper install exit 5)"
	@$(call ACCEPT_SH,smoke) echo "acceptance: smoke: ai-env vm smoke --max-duration 900, then vm list: answer their two Touch IDs"; \
	  rec=$$("$$ai" vm smoke --max-duration 900 --json); rc=$$?; printf '%s\n' "$$rec"; \
	  test $$rc -eq 0 || fail "ai-env vm smoke exited $$rc"; \
	  grep -qF '"backend":"sdk"' <<<"$$rec" || fail "the smoke did not use the SDK backend"; \
	  id=$$(sed -n 's/.*"id":"\([^"]*\)".*/\1/p' <<<"$$rec" | head -1); test -n "$$id" || fail "the smoke's record names no VM"; \
	  list=$$("$$ai" vm list --json); rc=$$?; test $$rc -eq 0 || fail "ai-env vm list exited $$rc"; \
	  ! grep -qF "\"$$id\"" <<<"$$list" || fail "vm list still holds $$id"; \
	  echo "acceptance: smoke: ok ($$id: PENDING, RUNNING, /health 200, TERMINATED; vm list holds none of it)"
	@echo "acceptance: ok: doctor, versions, creds, the negatives (a) to (h), the smoke; $(ACCEPT_DIR) removed"

clean: ## Remove build artifacts (keeps image/ sources)
	cargo clean
	rm -f image/ai-env

# ---- S3 infra (Pulumi program, deploy, image lifecycle): infra/infra.mk ----
include infra/infra.mk
