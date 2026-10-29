# S3/S5 infra targets (Pulumi program in infra/, deploy, image lifecycle, egress connector and proxy) and the S8
# operators' keys. Included by the top-level Makefile; shares its variables (REGION, STACK, AI_ENV, LAB_UNSET,
# IMAGE_OUT, IMAGE_JSON, IMAGE_CONFIG, IMAGE_NAME), its cmdline function and its MAKE_DRY.
#
# Part A (the agent; read-only against AWS, this shell's own credentials, the agent's own account): infra-install,
# infra-typecheck, check-policies, preview-scratch; S13's relay-artifact and relay-reload-gz build locally, keyless.
# Part B (Mike; creates or changes AWS resources), each target as one of the stack's AWS identities
# (plans/s8-operators-plan.md §7; TIER below asks once per top-level make):
#   the deployer (ai-env-deployer, its key pasted from Strongbox): deploy, preview, deploy-policies, runtime-key, ops-key,
#     deployer-key, image-activate, image-deactivate, image-prune YES=1, image-delete, connector-probe,
#     connector-delete, test-egress;
#   ops (ai-env-ops, credentials/ops.env: one Touch ID): image-wait, image-status, image-versions, image-builds,
#     image-prune's dry run, connector-status, connector-wait, logs, egress-logs, relay-logs (S13), acceptance;
#   the account root (its own credentials, ai-env as root): operator-keys, once after the bootstrap deploy, and destroy
#     (BREAKGLASS=1 only); the bootstrap deploy itself, and BREAKGLASS=1 on the command line for any deployer target;
#   no tier: infra-status, allowlist-reload, proxy-stop, proxy-start, proxy-patch (and gates, check-base-image) are one
#     ai-env command each, which resolves its identity itself (credentials/ops.env, one Touch ID; none under a runner).
#     claude-update is retired (S11: ai-env claude update).
# Nothing falls back to this shell's own AWS settings: `ai-env as` clears them for its command.
# Every aws call carries --region $(REGION), and the lambda-core, ec2 and logs ones the pinned --endpoint-url; nothing
# here runs `pulumi login` or uses --yes / --show-secrets (D17; `ai-env proxy stop --yes` is the operator CLI's own
# switch), and nothing writes, prints or passes the dev stack's passphrase as an argument: the targets that need it
# unseal its sealed file through `ai-env run -f` (A39, which amends D17; PASS_TARGETS below). The image lifecycle and
# egress logic lives in infra/scripts/ops.sh (bash 3.2).
.PHONY: infra-install infra-typecheck check-policies preview-scratch preview deploy deploy-policies image-wait image-status image-versions image-builds image-deactivate image-activate image-prune image-delete logs infra-status runtime-key ops-key deployer-key operator-keys destroy \
        connector-status connector-wait connector-probe connector-delete egress-logs allowlist-reload proxy-stop proxy-start proxy-patch claude-update \
        preview-run deploy-run deploy-policies-run image-wait-run image-status-run image-versions-run image-builds-run image-deactivate-run image-activate-run image-prune-run image-delete-run logs-run \
        runtime-key-run ops-key-run deployer-key-run operator-keys-run destroy-run connector-status-run connector-wait-run connector-probe-run connector-delete-run egress-logs-run \
        relay-artifact relay-reload-gz relay-logs relay-logs-run

INFRA              := infra
# The program reads image.json and (S13) relay.json, and resolves the paths inside them from the repo root, also from a
# scratch copy.
PULUMI_ENV          = IMAGE_JSON="$(abspath $(IMAGE_JSON))" RELAY_JSON="$(abspath $(RELAY_JSON))" AI_ENV_REPO_ROOT="$(CURDIR)"
# The stack's passphrase, sealed once per Mac (README "Identities"): PULUMI_SEALED=FILE, on the command line or from the
# environment, names another file (PULUMI_ENV above is the program's own), a leading ~/ HOME's (zsh hands make the
# command line's `PULUMI_SEALED=~/f` as it is), so that TIER, its dry form and ops.sh look at one file. PASS_TARGETS
# (A39): the tiered targets whose X-run runs pulumi preview, up or destroy of the real stack, the only ones that unseal
# it (TIER below).
PULUMI_SEALED      := $(or $(PULUMI_SEALED),$(HOME)/.config/ai-env/pulumi.env)
override PULUMI_SEALED := $(if $(filter ~/%,$(PULUMI_SEALED)),$(HOME)/$(PULUMI_SEALED:~/%=%),$(PULUMI_SEALED))
PASS_TARGETS       := preview deploy deploy-policies destroy
# The passphrase itself, or its file, on the make command line would sit in MAKEFLAGS, which hands it to every child of
# every make run, the builds among them (a sub-make started under NO_KEY exports its command line's variables again):
# refused before anything runs (exported, NO_KEY keeps either from the builds; make -p still prints the command line:
# never with it).
ifeq ($(origin PULUMI_CONFIG_PASSPHRASE),command line)
$(error PULUMI_CONFIG_PASSPHRASE on the make command line: MAKEFLAGS would hand it to every child of make, the builds among them: drop it; the targets that need the passphrase unseal $(PULUMI_SEALED) themselves (README "Identities"))
endif
ifeq ($(origin PULUMI_CONFIG_PASSPHRASE_FILE),command line)
$(error PULUMI_CONFIG_PASSPHRASE_FILE on the make command line: MAKEFLAGS would hand it to every child of make, the builds among them, past NO_KEY: export it instead, or drop it and let the targets that need the passphrase unseal $(PULUMI_SEALED) (README "Identities"))
endif
# D19: the log group comes from the one image parameter file.
LOG_GROUP          := $(shell sed -n 's/.*"logGroup": *"\([^"]*\)".*/\1/p' $(IMAGE_CONFIG))
RUNTIME_USER       := ai-env-runtime
DEPLOYER_USER      := ai-env-deployer
OPS_USER           := ai-env-ops
# The operator identities (plans/s8-operators-contracts.md §9). A tiered target X is its `##` help (its tier first, in
# parentheses), its prechecks that need no AWS, then the one line `@$(call TIER,<tier>,X) $(MAKE) --no-print-directory
# X-run`; X-run (no help: never typed) holds the recipe, the deployer's starting with $(IDENTITY). TIER runs X-run under
# `ai-env as <tier> --`, which asks once (the deployer's key pasted from Strongbox, or ops.env's Touch ID) and puts the
# key and its marker in X-run's environment, so nothing under it asks again; except:
#   - a runner that already covers the tier (`ai-env as --check`: a nested make, `ai-env as deployer -- make A B C`)
#     runs X-run as it is;
#   - BREAKGLASS=1 on the make command line (never from the environment), and the bootstrap (the deployer tier while
#     stack $(STACK) exports no deployer: ops.sh stack-deployer, a local read; outputs that cannot be read keep the
#     deployer, never this shell's own credentials), run it under `ai-env as root`, saying so on stderr; `ai-env as
#     root` admits only the account root, and ops.sh identity decides what the root may run.
# The runner is live: its two calls drop the lab knobs and the debug builds' paste knob ($(RUNNER_ENV)). In a dry run
# (-n, -q, -t: MAKE_DRY) the runner is only shown: the line names $(MAKE), which GNU make runs even then, and the
# sub-make inherits the switch, so `make -n X` prints X-run's recipe and asks for nothing (make -p is refused, -n or
# not: NOT_UNDER_I_OR_P); every other line naming $(MAKE) is a sub-make. Compile steps
# never see an operator key or the stack's passphrase (D18: either reaches every child, a dependency's build script
# included): they come first, in the wrapper, under $(NO_KEY), which a make nested under a runner (or under the unseal)
# needs too; and TIER itself first builds the operator CLI the same way ($(AI_ENV_BUILD)), before its `ai-env as
# --check`, which under a runner holds the key. make -j is not for tiered targets (two runners would ask at once);
# several goals under one ask: ai-env as deployer -- make A B C.
# A39, the stack's passphrase: for the PASS_TARGETS, which run pulumi preview, up or destroy of the real stack in X-run
# (nothing else needs it: reading the stack outputs has needed none since Pulumi 3.252), TIER unseals the sealed
# $(PULUMI_SEALED) when the passphrase is not set as Pulumi takes it (PULUMI_CONFIG_PASSPHRASE first, even empty, and
# an empty one is none; else PULUMI_CONFIG_PASSPHRASE_FILE) and that file exists: after the build, its Touch ID before
# the runner's ask (`ai-env run -f F -- pass-exec.sh X F ai-env as T -- X-run`, or under a covering runner `ai-env run
# -f F -- pass-exec.sh X F X-run`), said on stderr first; pass-exec.sh stops an empty sealed value before the runner.
# Once set (exported, a nested make, a make under `ai-env run -f`), nothing is unsealed again; several such goals unseal
# once each, as each asks its runner, or once for all under `ai-env run -f F -- ai-env as deployer -- make A B C`. The
# root's runner under another runner's marker refuses before it asks anything (`ai-env as root` starts only from a
# terminal of its own): nothing is unsealed for that refusal. Without the file deploy and deploy-policies refuse first
# (PASS_CHECK: their plan check cannot prompt), and preview and destroy keep Pulumi's own prompt. The dry form shows
# the unseal exactly where it would happen: make runs TIER's own test of the two variables and the file ($(shell): a
# test only, no value expanded).
NO_KEY             := env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN -u AI_ENV_BRIDGE_AS -u PULUMI_CONFIG_PASSPHRASE -u PULUMI_CONFIG_PASSPHRASE_FILE
# The operator CLI built without any key, marker or passphrase in its environment (D18): `$(AI_ENV) --version`, which
# with the default AI_ENV (cargo run) compiles the tree when it changed, its proc macros and any build script that
# reruns seeing only this environment. TIER runs it first, and so does every target or ops.sh command that calls
# $(AI_ENV) and may run under a runner (the one-command operator targets, s3-preflight, ops.sh's need_ai_env, and the
# X-runs that call it before any of those: one typed by hand under a runner builds too), so a make nested under `ai-env
# as`, or typed under it, finds the binary built and never compiles with the key.
AI_ENV_BUILD        = $(NO_KEY) $(LAB_UNSET) $(AI_ENV) --version >/dev/null
# make -i ignores a failed line and runs the next: a refused identity (ops.sh identity), a missing CONFIRM or
# BREAKGLASS would be ignored and the step it guards run anyway, as the account root or this shell's own credentials
# too. make -p prints its data base when it ends, every variable with its value, the environment's too, and MAKEFLAGS
# hands the -p to every sub-make: X-run's under the runner, and every make nested in it, would print the operator key
# and its secret, and the stack's passphrase once unsealed (A39). Every tiered target refuses both in its wrapper,
# before its build, its unseal and its runner, and again in its X-run (typed by hand), as acceptance does: a $(error)
# on MAKE_SWITCHES, which make expands with the whole recipe before any of its lines runs, wherever the line stands
# (otherwise the line is empty); -p under -n too, as -i. -k is no such risk: a failed line still ends the recipe. (A
# make typed under a runner, or under `ai-env run -f` with the passphrase, holds it itself and prints it under -p
# whatever this file says: the refusal stops its steps, never its own data base.)
NOT_UNDER_P         = $(if $(findstring p,$(MAKE_SWITCHES)),$(error $(1): not under make -p (it prints every variable when it ends, the environment's too: under the runner, the operator key and its secret, and the stack's passphrase once unsealed): run make $(1) without it))
NOT_UNDER_I_OR_P    = $(if $(findstring i,$(MAKE_SWITCHES)),$(error $(1): not under make -i (a refused identity, or a missing CONFIRM or BREAKGLASS, would be ignored and the steps after it run): run make $(1) without it))$(call NOT_UNDER_P,$(1))
BREAKGLASS_ON       = $(filter 1,$(call cmdline,BREAKGLASS))
# The runner's environment: no lab knob (A7: a debug `ai-env` reads them, AI_ENV_BRIDGE_LAB_OSASCRIPT among them)
# and no AI_ENV_PASTE_STDIN, with which a debug `ai-env as deployer` (the default AI_ENV is cargo run) would read the
# key from a stdin that is not a terminal (a pipe into make, an IDE's task runner) instead of /dev/tty; X-run inherits
# it.
RUNNER_ENV          = $(LAB_UNSET) -u AI_ENV_PASTE_STDIN
# A39 (above). PASS_SET_SH: the stack's passphrase is set as Pulumi takes it: PULUMI_CONFIG_PASSPHRASE when it is set
# at all, even empty (an empty one is none), else a PULUMI_CONFIG_PASSPHRASE_FILE that is not empty (only tested, never
# expanded; pass-exec.sh tests the same). PASS_CHECK, the first line of deploy and deploy-policies
# (their plan check cannot prompt): refused before the build when it is not set and there is no sealed file to unseal.
# PASS_SH, TIER's: u=unseal for a PASS_TARGET when it is not set and the sealed file exists, and `unseal CMD...`, which
# says so on stderr, then runs CMD under the passphrase through pass-exec.sh's guard, the lab and paste knobs dropped as
# for the runner. PASS_DRY: the dry form's unseal, where PASS_SH's own test would set u (make runs it: $(shell)).
PASS_SET_SH         = { [ -n "$${PULUMI_CONFIG_PASSPHRASE:+x}" ] || { [ -z "$${PULUMI_CONFIG_PASSPHRASE+x}" ] && [ -n "$${PULUMI_CONFIG_PASSPHRASE_FILE:+x}" ]; }; }
PASS_CHECK          = $(PASS_SET_SH) || test -f "$(PULUMI_SEALED)" || { printf '%s\n' "$(1): the $(STACK) stack's passphrase: neither PULUMI_CONFIG_PASSPHRASE nor PULUMI_CONFIG_PASSPHRASE_FILE is set (Pulumi takes PULUMI_CONFIG_PASSPHRASE first, even empty, and an empty one counts as none), and there is no sealed $(PULUMI_SEALED) to unseal (the plan check runs pulumi preview --non-interactive): seal it once (README \"Identities\"): printf 'PULUMI_CONFIG_PASSPHRASE=\n' | ai-env encrypt -k ai-env-bridge - > \"$(PULUMI_SEALED)\", then ai-env edit \"$(PULUMI_SEALED)\"; or export PULUMI_CONFIG_PASSPHRASE_FILE (a file holding it): nothing ran"; exit 1; }
PASS_SH             = u=; case " $(PASS_TARGETS) " in *" $$x "*) $(PASS_SET_SH) || test ! -f "$(PULUMI_SEALED)" || u=unseal ;; esac; \
                        unseal() { echo "$$x: the $(STACK) stack's passphrase: ai-env run -f $(PULUMI_SEALED) (one Touch ID)" >&2; \
                          $(RUNNER_ENV) $(AI_ENV) run -f "$(PULUMI_SEALED)" -- $(SHELL) $(INFRA)/scripts/pass-exec.sh "$$x" "$(PULUMI_SEALED)" "$$@"; };
PASS_DRY            = $(if $(filter $(1),$(PASS_TARGETS)),$(if $(shell $(PASS_SET_SH) || test ! -f "$(PULUMI_SEALED)" || echo y),$(AI_ENV) run -f "$(PULUMI_SEALED)" -- ))
# Nothing to unseal (u empty): the shell's unquoted $u vanishes, and the last line is the runner as it was. The root's
# runner under another runner's marker (the root's own covers it) refuses at once: nothing unsealed for it.
TIER_SH             = tier() { t=$$1; x=$$2; shift 2; $(AI_ENV_BUILD) || return $$?; $(PASS_SH) \
                        if [ -n "$(BREAKGLASS_ON)" ]; then \
                          echo "$$x: BREAKGLASS=1 on the make command line: ai-env as root (the account root's own credentials; README \"Break-glass\")" >&2; t=root; \
                        elif $(RUNNER_ENV) $(AI_ENV) as --check "$$t" >/dev/null 2>&1; then $$u "$$@"; return; \
                        elif [ "$$t" = deployer ] && d=$$($(OPS) stack-deployer) && [ -z "$$d" ]; then \
                          echo "$$x: stack $(STACK) exports no deployer yet: the bootstrap, as the account root (ai-env as root)" >&2; t=root; fi; \
                        if [ "$$t" = root ] && $(RUNNER_ENV) $(AI_ENV) as --check root >/dev/null 2>&1; then $$u "$$@"; return; fi; \
                        if [ "$$t" = root ] && [ -n "$${AI_ENV_BRIDGE_AS:-}" ]; then u=; fi; \
                        if [ -n "$$u" ]; then unseal $(AI_ENV) as "$$t" -- "$$@"; else $(RUNNER_ENV) $(AI_ENV) as "$$t" -- "$$@"; fi; };
TIER                = $(if $(MAKE_DRY),: $(call PASS_DRY,$(2))$(AI_ENV) as $(if $(BREAKGLASS_ON),root,$(1)) --;,$(TIER_SH) tier $(1) $(2))
# ops.sh identity TIER [LABEL]: one line, exit 0 (admitted; a loud break-glass line starts "BREAK-GLASS:") or 1.
IDENTITY            = BREAKGLASS='$(BREAKGLASS_ON)' $(OPS) identity
# ops.sh key-issue LABEL USER sealed|handover [first]: an access key whose secret never crosses a recipe (D23).
KEY_ISSUE           = $(LAB_UNSET) ROTATE='$(filter 1,$(call cmdline,ROTATE))' AI_ENV_CLI='$(AI_ENV)' $(OPS) key-issue
# The bridge root, where `ai-env creds aws-set` seals the keys and acceptance reads bridge.toml and the logs (shell
# syntax, expanded in the recipe).
BRIDGE_DIR_SH      := $${AI_ENV_BRIDGE_DIR:-$$HOME/.config/ai-env/bridge}
SCRATCH            := $(abspath $(IMAGE_OUT))/pulumi-scratch
IMAGE_WAIT_TIMEOUT ?= 2400
IMAGE_WAIT_POLL    ?= 15
VERSIONS_WARN      ?= 40
VERSIONS_QUOTA     := 50
SINCE              ?= 1h
# The switches that delete, rotate, write, pick a version or an identity (YES, KEEP, VERSION, ROTATE, WRITE, CONFIRM,
# RECORD_PROBE, FOLLOW, REFRESH, BREAKGLASS, ONLY) count only when given on the make command line: $(call cmdline,NAME),
# defined in the top-level Makefile (s3-preflight's EXPECT_BUILD_FAILURE uses it too); a make under the runner
# inherits them.
KEEP_N              = $(or $(call cmdline,KEEP),3)
# S5: the egress parameter file (contract 1, one scalar per line, read like IMAGE_CONFIG; ops.sh reads the names it
# needs from it the same way). A missing file or key leaves the value empty (tests plant repos without it) and the
# target using it fails loudly.
EGRESS_CONFIG      := $(INFRA)/egress-config.json
EGRESS_LOG_GROUP   := $(shell sed -n 's/.*"logGroup": *"\([^"]*\)".*/\1/p' $(EGRESS_CONFIG) 2>/dev/null)
EGRESS_VPC_CIDR    := $(shell sed -n 's/.*"vpcCidr": *"\([^"]*\)".*/\1/p' $(EGRESS_CONFIG) 2>/dev/null)
# S13: the relay's cross-built binary and relay.json (make relay-artifact; the program uploads it and pins it in the
# artifact parameter), and its log group (relay-logs), read like the egress names.
RELAY_OUT          ?= target/relay
RELAY_JSON         := $(RELAY_OUT)/relay.json
RELAY_LOG_GROUP    := $(shell sed -n 's/.*"relayLogGroup": *"\([^"]*\)".*/\1/p' $(EGRESS_CONFIG) 2>/dev/null)
# The endpoints the S5 operator calls pin (bridge::awscli; ops.sh derives the same from REGION): never taken from the
# command line or the environment.
override LAMBDA_CORE_URL := https://lambda.$(REGION).amazonaws.com
override EC2_URL         := https://ec2.$(REGION).amazonaws.com
override LOGS_URL        := https://logs.$(REGION).amazonaws.com
CONNECTOR_WAIT_TIMEOUT ?= 600
CONNECTOR_WAIT_POLL    ?= 10
OPS                 = REGION=$(REGION) IMAGE_NAME=$(IMAGE_NAME) IMAGE_OUT="$(abspath $(IMAGE_OUT))" STACK=$(STACK) \
                      IMAGE_WAIT_TIMEOUT=$(IMAGE_WAIT_TIMEOUT) IMAGE_WAIT_POLL=$(IMAGE_WAIT_POLL) VERSIONS_WARN=$(VERSIONS_WARN) \
                      VERSIONS_QUOTA=$(VERSIONS_QUOTA) CONNECTOR_WAIT_TIMEOUT=$(CONNECTOR_WAIT_TIMEOUT) CONNECTOR_WAIT_POLL=$(CONNECTOR_WAIT_POLL) \
                      $(SHELL) $(INFRA)/scripts/ops.sh
# D29, shared by image-wait and deploy: poll the build, then always record the post-deploy snapshot and run
# versions-diff (also after a failed build or a failed `pulumi up`: T3.4 records both). A subshell whose status is
# the wait's, or 1 when the snapshot or the diff fails.
IMAGE_WAIT_SH       = ( $(OPS) wait; st=$$?; \
                        $(OPS) snapshot post-deploy || exit 1; \
                        if [ -f $(IMAGE_OUT)/pre-deploy-versions.json ]; then \
                          $(AI_ENV) infra versions-diff --before $(IMAGE_OUT)/pre-deploy-versions.json --after $(IMAGE_OUT)/post-deploy-versions.json $(if $(filter 1,$(call cmdline,RECORD_PROBE)),--record-probe) || exit 1; \
                        else echo "image-wait: no pre-deploy snapshot: versions-diff skipped"; fi; \
                        exit $$st )
# deploy's gate before anything is recorded or changed, shared with deploy-policies ($(1) the target, $(2) plan-gate's
# options): ONE `pulumi preview --json` of the real stack, held in a shell variable (never written or echoed: it carries
# the account id), on stdin to ops.sh plan-gate (the plan check and the replacement guard; for deploy-policies also its
# five documents known in that plan, D18); any refusal stops it. Its failure names the passphrase's routes (A39): a
# wrong or empty value is Pulumi's "incorrect passphrase" here, after the paste.
PLAN_GATE           = echo "cd $(INFRA) && pulumi preview --json --stack $(STACK): the plan check and the replacement guard"; \
                        plan=$$(cd $(INFRA) && $(PULUMI_ENV) pulumi preview --json --show-sames --show-reads --non-interactive --stack $(STACK)) \
                          || { st=$$?; printf '%s' "$$plan" | $(OPS) plan-errors; echo "$(1): pulumi preview --json failed (exit $$st): nothing deployed (Pulumi's error above; its incorrect passphrase: the value in effect is wrong or empty, the sealed one set with ai-env edit $(PULUMI_SEALED), which make $(1) unseals unless PULUMI_CONFIG_PASSPHRASE or PULUMI_CONFIG_PASSPHRASE_FILE is set (README \"Identities\"))"; exit 1; }; \
                        printf '%s' "$$plan" | $(OPS) plan-gate$(if $(2), $(2))
# deploy-policies' targets: the stack's five managed policies (infra/policies.ts), the only resources it updates; S13:
# ONLY=<policy>... on the make command line updates those alone (S13's first deploy needs ai-env-deploy-egress before the
# relay exists, and ai-env-ops' new document cannot be known until it does: LD-I8). A name that is no stack policy is
# refused by the plan gate's own row (the plan holds no step of it) before pulumi up.
STACK_POLICIES     := ai-env-deploy ai-env-deploy-egress ai-env-deploy-dns ai-env-deployer ai-env-ops
DEPLOY_POLICIES     = $(or $(call cmdline,ONLY),$(STACK_POLICIES))

# --ignore-scripts: @pulumi/aws and @pulumi/aws-native would otherwise run `pulumi plugin install` into ~/.pulumi
# (errors hidden); the plugins are a precondition checked by s3-preflight P7.
infra-install: ## S3: install the Pulumi program's exact npm pins (npm ci from infra/package-lock.json, no install scripts; node >= 20)
	@command -v node >/dev/null && command -v npm >/dev/null || { echo "infra-install: node (>= 20) and npm are required"; exit 1; }
	@v=$$(node -p 'process.versions.node.split(".")[0]'); test "$$v" -ge 20 || { echo "infra-install: node $$v < 20"; exit 1; }
	cd $(INFRA) && npm ci --ignore-scripts --no-audit --no-fund

infra-typecheck: ## S3: typecheck the Pulumi program and its scripts (tsc --noEmit)
	@test -x $(INFRA)/node_modules/.bin/tsc || { echo "infra-typecheck: $(INFRA)/node_modules missing: make infra-install"; exit 1; }
	cd $(INFRA) && npx tsc --noEmit
	@echo "infra-typecheck: ok"

check-policies: ## S3 T3.6, S5: Access Analyzer on every IAM document; simulate-custom-policy of the runtime policy (§9), the proxy role and the operator role (its Deny with the AWS managed policy); the operator policy's (action, resource) pin and the Deny's shape; read-only
	AI_ENV_REPO_ROOT="$(CURDIR)" REGION=$(REGION) POLICIES_OUT="$(CURDIR)/target/infra-policies" $(SHELL) $(INFRA)/scripts/check-policies.sh

preview-scratch: ## S3 T3.2/T3.5, S5, S8 operators: pulumi preview of a scratch copy (throwaway backend, stack, passphrase) + the plan check, the existing-stack copies (the bootstrap passes, the tampered ones are refused); NEGATIVE=no-logging|no-logging-cast|region|vm-sg-open|private-route|nacl-open|dns-support-on-in-none-mode|stray-rule|stray-type|late-transform|early-transform|dns-firewall-qtype|miswired|iam-widen|owned-param-reset|identity-widen|document-widen|endpoint-on-vm-table|endpoint-policy-widen|bucket-policy-no-vpce|relay-sg-open|vm-relay-wide|relay-nacl-wide|relay-imds|relay-eip-elsewhere|relay-role-widen; EGRESS_MODE=none|firewall
	@$(PULUMI_ENV) REGION=$(REGION) SCRATCH="$(SCRATCH)" NEGATIVE="$(NEGATIVE)" EGRESS_MODE="$(EGRESS_MODE)" $(SHELL) $(INFRA)/scripts/preview-scratch.sh

# The deployer's targets that build the image zip (and, S13, the relay's binary) build it first, in the wrapper, without
# any key or the stack's passphrase in its environment (D18: cargo-lambda's build scripts, the stage's scan); the
# passphrase is unsealed and then the key pasted after the build (A39, TIER), and X-run does not build it again. Without the sealed passphrase,
# preview keeps Pulumi's own prompt for it (a terminal); deploy and deploy-policies, whose plan check cannot prompt,
# refuse first (PASS_CHECK).
preview: ## (deployer: asks once for its key, from Strongbox, after the zip is built and the stack's passphrase: one Touch ID unless set) S3 part B: image-zip and relay-artifact, then pulumi preview --diff of the real stack $(STACK); REFRESH=1 (command line only) adds --refresh (every resource read as the deployer)
	$(NO_KEY) $(MAKE) --no-print-directory image-zip relay-artifact
	@$(call NOT_UNDER_I_OR_P,preview)
	@$(call TIER,deployer,preview) $(MAKE) --no-print-directory preview-run

preview-run:
	@$(IDENTITY) deployer preview
	@$(call NOT_UNDER_I_OR_P,preview)
	cd $(INFRA) && $(PULUMI_ENV) pulumi preview --diff --stack $(STACK)$(if $(filter 1,$(call cmdline,REFRESH)), --refresh)

# The image-wait body runs even when `pulumi up` fails (the T3.4 `RUN false` negative: Cloud Control reports the
# failed build), so the D29 comparison, the post-deploy snapshot and versions-diff are always recorded; the exit
# status is pulumi's when it failed, else the wait's. No sub-make on that line: GNU make runs any recipe line that
# names MAKE literally even under -n, so `make -n deploy` stays a dry parse. `make deploy EXPECT_BUILD_FAILURE=1`
# (command line only; the sub-makes inherit it) turns preflight P12 into a loud [-  ] row and keeps every other gate:
# the T3.4 `RUN false` negative deploys a zip that make test-docker cannot pass, with its snapshots, wait and diff.
# S8 operators: the zip is built first, without a key; then everything else runs as the deployer (TIER), the identity
# first (ops.sh identity, which P8 repeats as a row): the bootstrap (no deployer exported yet) and BREAKGLASS=1 as the
# account root. S5, before anything is recorded or changed: check-policies (read-only Access Analyzer and simulations
# of every IAM document), then the plan gate (PLAN_GATE: the plan check, scripts/check-plan.sh, the final word on the
# inventory and the egress spec, and the replacement guard: nothing the connector's ENIs pin is replaced, and the VPC's
# Amazon DNS is not turned on, while a connector exists); either refusal stops the deploy before `pulumi up`. The
# preview is --non-interactive (its stdout is captured, so it could not prompt): the stack's passphrase comes from the
# environment, PULUMI_CONFIG_PASSPHRASE_FILE or PULUMI_CONFIG_PASSPHRASE exported, else TIER's unseal of the sealed
# file (A39); with neither and no file, PASS_CHECK refuses before the zip is built. Once `pulumi up` has started,
# ops.sh post-deploy runs on every
# exit: after image-wait and connector-wait succeeded the whole of it (egress reload --if-changed when the proxy runs,
# the vpc VM warning, the egress-check line on a new image version, egress status as the out-of-band drift check:
# `pulumi up` does not refresh; drift fails the deploy at the end), after any failure the reload and the warnings
# (`--after-failure`: Pulumi may already have written a proxy parameter); the exit status is the first failure's.
deploy: ## (deployer: asks once for its key, from Strongbox, after the zip is built and the stack's passphrase: one Touch ID unless set; the bootstrap, and BREAKGLASS=1 on the command line: as the account root, README "Break-glass") S3/S5 part B: image-zip and relay-artifact, s3-preflight PHASE=b, check-policies, plan check + replacement guard (pulumi preview --json), pre-deploy snapshots, pulumi up $(STACK) (interactive confirmation), image-wait, connector-wait, egress reload/status; EXPECT_BUILD_FAILURE=1 skips P12 (T3.4)
	@$(call PASS_CHECK,deploy)
	$(NO_KEY) $(MAKE) --no-print-directory image-zip relay-artifact
	@$(call NOT_UNDER_I_OR_P,deploy)
	@$(call TIER,deployer,deploy) $(MAKE) --no-print-directory deploy-run

deploy-run:
	@$(IDENTITY) deployer deploy
	@$(call NOT_UNDER_I_OR_P,deploy)
	$(MAKE) --no-print-directory s3-preflight PHASE=b
	$(MAKE) --no-print-directory check-policies
	@$(call PLAN_GATE,deploy)
	@$(OPS) snapshot pre-deploy
	@echo "cd $(INFRA) && pulumi up --stack $(STACK), then image-wait, connector-wait and the egress steps"; \
	  st=0; (cd $(INFRA) && $(PULUMI_ENV) pulumi up --stack $(STACK)) || st=$$?; \
	  $(IMAGE_WAIT_SH); w=$$?; st=$$(( st ? st : w )); \
	  if [ $$st -eq 0 ]; then $(OPS) connector-wait || st=$$?; fi; \
	  if [ $$st -eq 0 ]; then after=""; else after=--after-failure; fi; \
	  $(LAB_UNSET) AI_ENV_CLI='$(AI_ENV)' $(OPS) post-deploy $$after; p=$$?; \
	  exit $$(( st ? st : p ))

# How the deployer adds a right it lacks (an AccessDenied naming an action, fixed in infra/policies.ts): deploy's gates
# (the zip, P1-P16, check-policies, the plan check of the whole stack), then `pulumi up` of the five stack policies
# alone (--target each, Pulumi's own confirmation): the deployer may create, set and delete their versions, never
# create or delete a policy. IAM takes some seconds to apply a new version. The gate also wants the five documents
# known in its plan: one the plan check accepts unknown (a resource it names, the proxy instance, created or replaced)
# would be rendered anew by the targeted up from the old resource and applied uncompared; make deploy takes it whole.
deploy-policies: ## (deployer: asks once for its key, from Strongbox, after the zip is built and the stack's passphrase: one Touch ID unless set) S8 operators: image-zip and relay-artifact, s3-preflight PHASE=b, check-policies, the plan check, then pulumi up of the five stack policies only (--target each; interactive confirmation), or (S13) of ONLY=<policy>... (command line only); then wait about 15 s for IAM and make deploy
	@$(call PASS_CHECK,deploy-policies)
	$(NO_KEY) $(MAKE) --no-print-directory image-zip relay-artifact
	@$(call NOT_UNDER_I_OR_P,deploy-policies)
	@$(call TIER,deployer,deploy-policies) $(MAKE) --no-print-directory deploy-policies-run

deploy-policies-run:
	@$(IDENTITY) deployer deploy-policies
	@$(call NOT_UNDER_I_OR_P,deploy-policies)
	$(MAKE) --no-print-directory s3-preflight PHASE=b
	$(MAKE) --no-print-directory check-policies
	@$(call PLAN_GATE,deploy-policies,--known-documents $(DEPLOY_POLICIES))
	cd $(INFRA) && $(PULUMI_ENV) pulumi up --stack $(STACK) $(foreach p,$(DEPLOY_POLICIES),--target urn:pulumi:$(STACK)::ai-env::aws:iam/policy:Policy::$(p))
	@echo "deploy-policies: done: wait about 15 s for IAM, then make deploy"

# S11 (A.7): the daily Claude Code update is retired: VMs follow the Cursor extension's claude with no deploy (an
# admitted version staged in S3, fetched into each VM's claude cache: plans/s11-plan.md part A). The target stays so
# that a habit or a runbook typing it is told what replaced it; it changes nothing (exit 2).
claude-update: ## (retired, S11) VMs follow Cursor's Claude Code with no deploy: ai-env claude update admits and stages the installed bundle's version (one Touch ID); ai-env claude status shows where each version is
	@echo "claude-update: retired (S11): VMs follow Cursor's Claude Code with no deploy: ai-env claude update (admits and stages the installed bundle's version; ai-env claude status shows where each version is)"; exit 2

# D29: the wait decides from the versions against the pre-deploy snapshot; the post-deploy snapshot and
# versions-diff run even after a failed build (T3.4 records both).
image-wait: ## (ops: one Touch ID) S3 part B: poll the image until CREATED/UPDATED or *_FAILED (IMAGE_WAIT_TIMEOUT s), compare versions with the pre-deploy snapshot; RECORD_PROBE=1
	@$(call NOT_UNDER_I_OR_P,image-wait)
	@$(call TIER,ops,image-wait) $(MAKE) --no-print-directory image-wait-run

image-wait-run:
	@$(call NOT_UNDER_I_OR_P,image-wait)
	@$(AI_ENV_BUILD)
	@$(IMAGE_WAIT_SH)

image-status: ## (ops: one Touch ID) S3 part B: get-microvm-image of $(IMAGE_NAME) (state, latest active and failed versions)
	@$(call NOT_UNDER_I_OR_P,image-status)
	@$(call TIER,ops,image-status) $(MAKE) --no-print-directory image-status-run

image-status-run:
	@$(call NOT_UNDER_I_OR_P,image-status)
	@$(OPS) status

image-versions: ## (ops: one Touch ID) S3 part B: list the image versions (state, status); warns from $(VERSIONS_WARN) (quota $(VERSIONS_QUOTA))
	@$(call NOT_UNDER_I_OR_P,image-versions)
	@$(call TIER,ops,image-versions) $(MAKE) --no-print-directory image-versions-run

image-versions-run:
	@$(call NOT_UNDER_I_OR_P,image-versions)
	@$(OPS) versions

image-builds: ## (ops: one Touch ID) S3 part B: builds of VERSION=<n> (default: the latest active and the latest failed version)
	@$(call NOT_UNDER_I_OR_P,image-builds)
	@$(call TIER,ops,image-builds) $(MAKE) --no-print-directory image-builds-run

image-builds-run:
	@$(call NOT_UNDER_I_OR_P,image-builds)
	@$(OPS) builds $(call cmdline,VERSION)

image-deactivate: ## (deployer: asks once for its key, from Strongbox) S3 part B rollback: mark VERSION=<n> INACTIVE
	@test -n "$(call cmdline,VERSION)" || { echo "image-deactivate: VERSION=<n> is required on the command line (make image-versions lists them)"; exit 2; }
	@$(call NOT_UNDER_I_OR_P,image-deactivate)
	@$(call TIER,deployer,image-deactivate) $(MAKE) --no-print-directory image-deactivate-run

image-deactivate-run:
	@$(IDENTITY) deployer image-deactivate
	@$(call NOT_UNDER_I_OR_P,image-deactivate)
	@$(OPS) set-status INACTIVE "$(call cmdline,VERSION)"

image-activate: ## (deployer: asks once for its key, from Strongbox) S3 part B rollback: mark VERSION=<n> ACTIVE
	@test -n "$(call cmdline,VERSION)" || { echo "image-activate: VERSION=<n> is required on the command line (make image-versions lists them)"; exit 2; }
	@$(call NOT_UNDER_I_OR_P,image-activate)
	@$(call TIER,deployer,image-activate) $(MAKE) --no-print-directory image-activate-run

image-activate-run:
	@$(IDENTITY) deployer image-activate
	@$(call NOT_UNDER_I_OR_P,image-activate)
	@$(OPS) set-status ACTIVE "$(call cmdline,VERSION)"

# The dry run reads (ops); YES=1 deletes versions, the deployer's.
image-prune: ## (ops: one Touch ID; with YES=1 the deployer, its key from Strongbox) S3 part B: delete all but the newest KEEP=3 versions (never an ACTIVE one, one in progress or one a VM runs); dry run unless YES=1
	@$(call NOT_UNDER_I_OR_P,image-prune)
	@$(call TIER,$(if $(filter 1,$(call cmdline,YES)),deployer,ops),image-prune) $(MAKE) --no-print-directory image-prune-run

image-prune-run:
	$(if $(filter 1,$(call cmdline,YES)),@$(IDENTITY) deployer image-prune)
	@$(call NOT_UNDER_I_OR_P,image-prune)
	@$(OPS) prune "$(KEEP_N)" "$(call cmdline,YES)"

# The CONFIRM switches are checked before the runner asks (nothing is pasted for a typo), and again in X-run, which
# must not delete anything when it is typed by hand.
IMAGE_DELETE_CONFIRM = test "$(call cmdline,CONFIRM)" = delete-image || { echo "image-delete: deletes $(IMAGE_NAME) and its versions outside Pulumi; set CONFIRM=delete-image on the command line"; exit 1; }
image-delete: ## (deployer: asks once for its key, from Strongbox) S3 part B recovery (e.g. a first build left CREATE_FAILED): delete the image outside Pulumi (vm-guard first); CONFIRM=delete-image
	@$(IMAGE_DELETE_CONFIRM)
	@$(call NOT_UNDER_I_OR_P,image-delete)
	@$(call TIER,deployer,image-delete) $(MAKE) --no-print-directory image-delete-run

image-delete-run:
	@$(IMAGE_DELETE_CONFIRM)
	@$(IDENTITY) deployer image-delete
	@$(call NOT_UNDER_I_OR_P,image-delete)
	@$(OPS) vm-guard
	@$(OPS) delete-image

logs: ## (ops: one Touch ID) S3 part B: list log groups under /aws/lambda-microvms and /aws/lambda/microvms, then tail $(LOG_GROUP) (SINCE=1h, FOLLOW=1)
	@test -n "$(LOG_GROUP)" || { echo "logs: no logGroup in $(INFRA)/image-config.json"; exit 1; }
	@$(call NOT_UNDER_I_OR_P,logs)
	@$(call TIER,ops,logs) $(MAKE) --no-print-directory logs-run

logs-run:
	@$(call NOT_UNDER_I_OR_P,logs)
	@for p in /aws/lambda-microvms /aws/lambda/microvms; do echo "log groups under $$p:"; \
	  aws logs describe-log-groups --log-group-name-prefix $$p --region $(REGION) --query 'logGroups[].[logGroupName,retentionInDays,storedBytes]' --output text | sed 's/^/  /'; done
	aws logs tail $(LOG_GROUP) --since $(SINCE) --format short $(if $(filter 1,$(call cmdline,FOLLOW)),--follow) --region $(REGION)

infra-status: ## (ops: one Touch ID, none under ai-env as) S3/S5 part B: ai-env infra status (stack outputs + live read-only get-microvm-image and get-network-connector vs bridge.toml [aws]); WRITE=1 edits [aws] and writes state/infra.toml
	@$(AI_ENV_BUILD)
	$(AI_ENV) infra status --stack $(STACK) $(if $(filter 1,$(call cmdline,WRITE)),--write)

# D23: no access key ever enters Pulumi (its state would hold the secret). Each key is issued out of band by ops.sh
# key-issue (its comment says how): create-access-key piped into the CLI that seals it (aws-set: runtime-key, ops-key)
# or hands it over to Strongbox (creds deployer-key: deployer-key), then verified; whether a key was created is read
# from IAM afterwards, a failure names the delete command of every new id, and ROTATE=1 deletes the old key last. The
# CLI's check runs first (nothing is created when sealing cannot work).
runtime-key: ## (deployer: asks once for its key, from Strongbox) S3 part B (D23): create an access key for ai-env-runtime, seal it into credentials/aws.env with ai-env creds aws-set, verify it with ai-env creds aws-verify (one Touch ID); ROTATE=1 replaces the key
	@$(call NOT_UNDER_I_OR_P,runtime-key)
	@$(call TIER,deployer,runtime-key) $(MAKE) --no-print-directory runtime-key-run

runtime-key-run:
	@$(IDENTITY) deployer runtime-key
	@$(call NOT_UNDER_I_OR_P,runtime-key)
	@$(AI_ENV_BUILD)
	$(AI_ENV) creds aws-set --check
	@$(KEY_ISSUE) runtime-key $(RUNTIME_USER) sealed

ops-key: ## (deployer: asks once for its key, from Strongbox) S8 operators: create an access key for ai-env-ops, seal it into credentials/ops.env, verify it (one Touch ID); ROTATE=1 replaces it (a lost Mac: on the new one)
	@$(call NOT_UNDER_I_OR_P,ops-key)
	@$(call TIER,deployer,ops-key) $(MAKE) --no-print-directory ops-key-run

ops-key-run:
	@$(IDENTITY) deployer ops-key
	@$(call NOT_UNDER_I_OR_P,ops-key)
	@$(AI_ENV_BUILD)
	$(AI_ENV) creds aws-set --check --user $(OPS_USER)
	@$(KEY_ISSUE) ops-key $(OPS_USER) sealed

deployer-key: ## (deployer, ROTATE=1 only: asks once for the current key; a lost one: BREAKGLASS=1, as the account root, README "Break-glass") S8 operators: a new access key of ai-env-deployer onto Strongbox through the clipboard (this Mac only, concealed), pasted back and verified, then the old key deleted
	@test "$(filter 1,$(call cmdline,ROTATE))" = 1 || { echo "deployer-key: ROTATE=1 only (the first deployer key is make operator-keys's, as the account root, once)"; exit 2; }
	@$(call NOT_UNDER_I_OR_P,deployer-key)
	@$(call TIER,deployer,deployer-key) $(MAKE) --no-print-directory deployer-key-run

deployer-key-run:
	@$(IDENTITY) deployer deployer-key
	@$(call NOT_UNDER_I_OR_P,deployer-key)
	@$(KEY_ISSUE) deployer-key $(DEPLOYER_USER) handover

# The account root's, once, right after the bootstrap deploy made the two users: their first keys. A rerun resumes:
# key-issue's `first` skips a user that has a key.
operator-keys: ## (root: the account root's own credentials, once, right after the bootstrap deploy; a rerun resumes) S8 operators: the first keys: ai-env-deployer's onto Strongbox (pasted back, verified), then ai-env-ops' sealed into credentials/ops.env and verified (one Touch ID)
	@$(call NOT_UNDER_I_OR_P,operator-keys)
	@$(call TIER,root,operator-keys) $(MAKE) --no-print-directory operator-keys-run

operator-keys-run:
	@$(IDENTITY) root-keys operator-keys
	@$(call NOT_UNDER_I_OR_P,operator-keys)
	@$(AI_ENV_BUILD)
	$(AI_ENV) creds aws-set --check --user $(OPS_USER)
	@$(KEY_ISSUE) deployer-key $(DEPLOYER_USER) handover first
	@$(KEY_ISSUE) ops-key $(OPS_USER) sealed first
	@echo "operator-keys: done. Next (README \"Identities\"): close this terminal; in a new one, make infra-status WRITE=1, then the checks. ai-env no longer needs root's access key: delete it when nothing else uses it"

# destroy deletes the operator users themselves (forceDestroy) and the policies the deployer holds: as the deployer it
# would lose its rights half-way, so the account root runs it, BREAKGLASS=1 only (L8); destroy-run's identity line, the
# break-glass tier, admits the account root under its runner with it and nobody else, so destroy-run typed by hand
# under the deployer's runner (which the wrapper's root tier would refuse) never reaches pulumi destroy either. pulumi
# destroy needs the stack's passphrase: TIER unseals it (A39) when it is not set and the sealed file exists, else
# Pulumi asks for it on the terminal.
DESTROY_CONFIRM      = test "$(call cmdline,CONFIRM)" = "destroy-$(STACK)" || { echo "destroy: removes the image and its versions, roles, the deployer, ops and runtime users and their keys, the stack's policies, bucket, log group and budget, the egress VPC, proxy and connector of stack $(STACK); set CONFIRM=destroy-$(STACK) on the command line"; exit 1; }
DESTROY_BREAKGLASS   = test -n "$(BREAKGLASS_ON)" || { echo "destroy: it deletes the operator users themselves: as the account root only: make destroy CONFIRM=destroy-$(STACK) BREAKGLASS=1 (README \"Break-glass\")"; exit 1; }
destroy: ## (root, BREAKGLASS=1 only: the account root's own credentials, after the stack's passphrase: one Touch ID unless set; README "Break-glass") S3 part B: pulumi destroy of $(STACK) (CONFIRM=destroy-$(STACK) BREAKGLASS=1; refuses while a VM of the image is not TERMINATED or a connector other than the stack's exists), then the post-destroy checklist
	@$(DESTROY_CONFIRM)
	@$(DESTROY_BREAKGLASS)
	@$(call NOT_UNDER_I_OR_P,destroy)
	@$(call TIER,root,destroy) $(MAKE) --no-print-directory destroy-run

destroy-run:
	@$(DESTROY_CONFIRM)
	@$(DESTROY_BREAKGLASS)
	@$(IDENTITY) breakglass destroy
	@$(call NOT_UNDER_I_OR_P,destroy)
	@$(OPS) vm-guard
	cd $(INFRA) && $(PULUMI_ENV) pulumi destroy --stack $(STACK)
	@$(OPS) checklist

# ---- S5 egress: the connector and the proxy (plans/s5-plan.md "Makefile / ops") ----

connector-status: ## (ops: one Touch ID) S5 part B: the egress connector (get-network-connector), any other connector, and the ENIs in the VM subnet (describe-network-interfaces --include-managed-resources: count, IPs, SGs; the subnet from the stack outputs)
	@$(call NOT_UNDER_I_OR_P,connector-status)
	@$(call TIER,ops,connector-status) $(MAKE) --no-print-directory connector-status-run

connector-status-run:
	@$(call NOT_UNDER_I_OR_P,connector-status)
	@$(OPS) connector-status

connector-wait: ## (ops: one Touch ID) S5 part B: poll get-network-connector until ACTIVE (CONNECTOR_WAIT_TIMEOUT=600 s); FAILED or INACTIVE stop with the service's reason (make deploy runs it)
	@$(call NOT_UNDER_I_OR_P,connector-wait)
	@$(call TIER,ops,connector-wait) $(MAKE) --no-print-directory connector-wait-run

connector-wait-run:
	@$(call NOT_UNDER_I_OR_P,connector-wait)
	@$(OPS) connector-wait

# T5.1: a Pulumi create returns only once the connector is ACTIVE, so the PENDING window is measured on a throw-away
# second connector; ops.sh deletes it in a `trap ... EXIT` on every path, also when the probe or the wait fails.
CONNECTOR_PROBE_CONFIRM = test "$(call cmdline,CONFIRM)" = create-probe-connector || { echo "connector-probe: creates a throw-away egress connector on the VM subnet (deleted at the end) and runs a MicroVM against it (one Touch ID); set CONFIRM=create-probe-connector on the command line"; exit 1; }
connector-probe: ## (deployer: asks once for its key, from Strongbox; the probe's VM one Touch ID) S5 part B T5.1: a throw-away connector on the stack connector's subnet/SG/role, `ai-env lab run connector-pending` while it is PENDING, then its activation time; deleted on every path; CONFIRM=create-probe-connector
	@$(CONNECTOR_PROBE_CONFIRM)
	@$(call NOT_UNDER_I_OR_P,connector-probe)
	@$(call TIER,deployer,connector-probe) $(MAKE) --no-print-directory connector-probe-run

connector-probe-run:
	@$(CONNECTOR_PROBE_CONFIRM)
	@$(IDENTITY) deployer connector-probe
	@$(call NOT_UNDER_I_OR_P,connector-probe)
	@$(LAB_UNSET) AI_ENV_CLI='$(AI_ENV)' $(OPS) connector-probe

CONNECTOR_DELETE_CONFIRM = test "$(call cmdline,CONFIRM)" = delete-connector || { echo "connector-delete: deletes the egress connector outside Pulumi (vpc VMs cannot start until make deploy creates it again); set CONFIRM=delete-connector on the command line"; exit 1; }
connector-delete: ## (deployer: asks once for its key, from Strongbox) S5 part B recovery: delete the stack's egress connector outside Pulumi (before a replacement of the VPC, a subnet or an SG: the deploy's replacement guard says so); vm-guard first; CONFIRM=delete-connector
	@$(CONNECTOR_DELETE_CONFIRM)
	@$(call NOT_UNDER_I_OR_P,connector-delete)
	@$(call TIER,deployer,connector-delete) $(MAKE) --no-print-directory connector-delete-run

connector-delete-run:
	@$(CONNECTOR_DELETE_CONFIRM)
	@$(IDENTITY) deployer connector-delete
	@$(call NOT_UNDER_I_OR_P,connector-delete)
	@$(OPS) vm-guard
	@$(OPS) connector-delete

egress-logs: ## (ops: one Touch ID) S5 part B: tail the squid access log $(EGRESS_LOG_GROUP) (host names only, no paths; SINCE=1h, FOLLOW=1)
	@test -n "$(EGRESS_LOG_GROUP)" || { echo "egress-logs: no logGroup in $(EGRESS_CONFIG)"; exit 1; }
	@$(call NOT_UNDER_I_OR_P,egress-logs)
	@$(call TIER,ops,egress-logs) $(MAKE) --no-print-directory egress-logs-run

egress-logs-run:
	@$(call NOT_UNDER_I_OR_P,egress-logs)
	aws logs tail $(EGRESS_LOG_GROUP) --since $(SINCE) --format short $(if $(filter 1,$(call cmdline,FOLLOW)),--follow) --region $(REGION) --endpoint-url $(LOGS_URL)

# ---- S13: the relay (plans/s13-contracts.md §I-infra.4.7) ----

relay-logs: ## (ops: one Touch ID) S13 part B: tail the relay's log group $(RELAY_LOG_GROUP) (its request log, the reload unit's lines, its diagnostics: ids and hashes only; SINCE=1h, FOLLOW=1)
	@test -n "$(RELAY_LOG_GROUP)" || { echo "relay-logs: no relayLogGroup in $(EGRESS_CONFIG)"; exit 1; }
	@$(call NOT_UNDER_I_OR_P,relay-logs)
	@$(call TIER,ops,relay-logs) $(MAKE) --no-print-directory relay-logs-run

relay-logs-run:
	@$(call NOT_UNDER_I_OR_P,relay-logs)
	aws logs tail $(RELAY_LOG_GROUP) --since $(SINCE) --format short $(if $(filter 1,$(call cmdline,FOLLOW)),--follow) --region $(REGION) --endpoint-url $(LOGS_URL)

# The relay's binary, cross-built as vm-build builds the shim (the cargo-lambda vm-build-pick prints, picked inside one
# shell line through $(SUBMAKE), so a dry make -n stays dry), without any key, marker or passphrase in its environment
# (D18); then relay.json, which the program reads (relay.ts loadRelayJson: the binary hashed again, uploaded under
# relay/ai-env-relay-<sha16> and pinned by the artifact parameter, whose SHA-256 the relay's reload unit checks).
relay-artifact: ## S13: cross-build the relay (cargo-lambda --arm64, -p ai-env-relay) -> $(RELAY_OUT)/ai-env-relay; aarch64 ELF, glibc <= $(GLIBC_MAX); then $(RELAY_JSON) (sha256, S3 key, version)
	@set -eu; out=$$($(SUBMAKE) -s --no-print-directory vm-build-pick) || { echo "relay-artifact: $$out"; exit 1; }; cl=$${out% *}; \
	  echo "relay-artifact: using $$out"; \
	  rustup +$(TOOLCHAIN) target list --installed | grep -qx '$(TARGET)' || { echo "missing target: rustup target add $(TARGET) --toolchain $(TOOLCHAIN)"; exit 1; }; \
	  test -x $(LLVM_BIN)/llvm-objdump || { echo "relay-artifact: $(LLVM_BIN)/llvm-objdump missing (brew install llvm, or set LLVM_BIN)"; exit 1; }; \
	  rm -f target/lambda/ai-env-relay/bootstrap; \
	  ulimit -n 10240; $(NO_KEY) RUSTUP_TOOLCHAIN=$(TOOLCHAIN) "$$cl" lambda build --release --arm64 --lambda-dir target/lambda -p ai-env-relay --bin ai-env-relay
	mkdir -p $(RELAY_OUT)
	cp target/lambda/ai-env-relay/bootstrap $(RELAY_OUT)/ai-env-relay
	@file $(RELAY_OUT)/ai-env-relay | grep -q 'ELF 64-bit.*aarch64' || { file $(RELAY_OUT)/ai-env-relay; echo "relay-artifact: not an aarch64 ELF"; exit 1; }
	@max=$$($(LLVM_BIN)/llvm-objdump -T $(RELAY_OUT)/ai-env-relay | grep -o 'GLIBC_2\.[0-9]*' | sort -u -t. -k2,2n | tail -1); \
	  echo "relay-artifact: max glibc symbol version $$max"; \
	  test "$${max#GLIBC_2.}" -le $(subst 2.,,$(GLIBC_MAX)) || { echo "relay-artifact: glibc ceiling exceeded ($$max > GLIBC_$(GLIBC_MAX))"; exit 1; }
	@set -eu; sha=$$(shasum -a 256 $(RELAY_OUT)/ai-env-relay | cut -d' ' -f1); \
	  version=$$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version *= *"\([^"]*\)".*/\1/p' Cargo.toml | head -1); \
	  test -n "$$version" || { echo "relay-artifact: no [workspace.package] version in Cargo.toml"; exit 1; }; \
	  printf '{"binary":"%s","sha256":"%s","key":"relay/ai-env-relay-%s","version":"%s"}\n' "$(RELAY_OUT)/ai-env-relay" "$$sha" "$${sha:0:16}" "$$version" > "$(RELAY_JSON)"; \
	  ls -l $(RELAY_OUT)/ai-env-relay; cat "$(RELAY_JSON)"

relay-reload-gz: ## S13: regenerate infra/relay/reload.py.gz from infra/relay/reload.py (gzip -9 -n), the bytes the relay's user data embeds; commit both
	gzip -9 -n -c infra/relay/reload.py > infra/relay/reload.py.gz

# One ai-env command each: the binary resolves its identity itself (an ai-env as marker, else credentials/ops.env with
# one Touch ID), so no runner; egress allow, which widens egress, is the deployer's (ai-env as deployer -- ...). Each
# (and infra-status, check-base-image) builds the binary first without any key ($(AI_ENV_BUILD), D18): typed under
# `ai-env as ops --`, the command itself then compiles nothing with the key.
allowlist-reload: ## (ops: one Touch ID, none under ai-env as) S5 part B: ai-env egress reload (the proxy re-reads its parameters; squid -k parse first, the old config kept on any error)
	@$(AI_ENV_BUILD)
	$(LAB_UNSET) $(AI_ENV) egress reload

proxy-stop: ## (ops: one Touch ID, none under ai-env as) S5 part B: ai-env proxy stop (egress fails closed; a stopped proxy costs cents a day); refused while vpc VMs run unless YES=1
	@$(AI_ENV_BUILD)
	$(LAB_UNSET) $(AI_ENV) proxy stop $(if $(filter 1,$(call cmdline,YES)),--yes)

proxy-start: ## (ops: one Touch ID, none under ai-env as) S5 part B: ai-env proxy start (waits for running, SSM online and squid serving the current parameters)
	@$(AI_ENV_BUILD)
	$(LAB_UNSET) $(AI_ENV) proxy start

proxy-patch: ## (ops: one Touch ID, none under ai-env as) S5 part B: ai-env proxy patch (dnf upgrade --security through the fixed SSM document ai-env-proxy-patch, then squid restarted and proven to serve)
	@$(AI_ENV_BUILD)
	$(LAB_UNSET) $(AI_ENV) proxy patch
