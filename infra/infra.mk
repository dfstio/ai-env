# S3 infra targets (Pulumi program in infra/, deploy and image lifecycle).
# Included by the top-level Makefile; shares its variables (REGION, STACK,
# AI_ENV, IMAGE_OUT, IMAGE_JSON, IMAGE_CONFIG, IMAGE_NAME) and its cmdline function.
#
# Part A (the agent; read-only against AWS): infra-install, infra-typecheck, check-policies, preview-scratch.
# Part B (Mike; creates or changes AWS resources): preview, deploy, image-*, logs, infra-status, runtime-key, destroy.
# Every aws call carries --region $(REGION); nothing here runs `pulumi login`, sets the dev stack's passphrase or
# uses --yes / --show-secrets (D17). The image lifecycle logic lives in infra/scripts/ops.sh (bash 3.2).
.PHONY: infra-install infra-typecheck check-policies preview-scratch preview deploy image-wait image-status image-versions image-builds image-deactivate image-activate image-prune image-delete logs infra-status runtime-key destroy

INFRA              := infra
# The program reads image.json and resolves the paths inside it from the repo root, also from a scratch copy.
PULUMI_ENV          = IMAGE_JSON="$(abspath $(IMAGE_JSON))" AI_ENV_REPO_ROOT="$(CURDIR)"
# D19: the log group comes from the one image parameter file.
LOG_GROUP          := $(shell sed -n 's/.*"logGroup": *"\([^"]*\)".*/\1/p' $(IMAGE_CONFIG))
RUNTIME_USER       := ai-env-runtime
# Where `ai-env creds aws-set` seals the runtime key (shell syntax, expanded in the recipe).
BRIDGE_DIR_SH      := $${AI_ENV_BRIDGE_DIR:-$$HOME/.config/ai-env/bridge}
SCRATCH            := $(abspath $(IMAGE_OUT))/pulumi-scratch
IMAGE_WAIT_TIMEOUT ?= 2400
IMAGE_WAIT_POLL    ?= 15
VERSIONS_WARN      ?= 40
VERSIONS_QUOTA     := 50
SINCE              ?= 1h
# The switches that delete, rotate, write or pick a version (YES, KEEP, VERSION, ROTATE, WRITE, CONFIRM,
# RECORD_PROBE, FOLLOW) count only when given on the make command line: $(call cmdline,NAME), defined in the
# top-level Makefile (s3-preflight's EXPECT_BUILD_FAILURE uses it too).
KEEP_N              = $(or $(call cmdline,KEEP),3)
OPS                 = REGION=$(REGION) IMAGE_NAME=$(IMAGE_NAME) IMAGE_OUT="$(abspath $(IMAGE_OUT))" STACK=$(STACK) \
                      IMAGE_WAIT_TIMEOUT=$(IMAGE_WAIT_TIMEOUT) IMAGE_WAIT_POLL=$(IMAGE_WAIT_POLL) VERSIONS_WARN=$(VERSIONS_WARN) \
                      VERSIONS_QUOTA=$(VERSIONS_QUOTA) $(SHELL) $(INFRA)/scripts/ops.sh
# D29, shared by image-wait and deploy: poll the build, then always record the post-deploy snapshot and run
# versions-diff (also after a failed build or a failed `pulumi up`: T3.4 records both). A subshell whose status is
# the wait's, or 1 when the snapshot or the diff fails.
IMAGE_WAIT_SH       = ( $(OPS) wait; st=$$?; \
                        $(OPS) snapshot post-deploy || exit 1; \
                        if [ -f $(IMAGE_OUT)/pre-deploy-versions.json ]; then \
                          $(AI_ENV) infra versions-diff --before $(IMAGE_OUT)/pre-deploy-versions.json --after $(IMAGE_OUT)/post-deploy-versions.json $(if $(filter 1,$(call cmdline,RECORD_PROBE)),--record-probe) || exit 1; \
                        else echo "image-wait: no pre-deploy snapshot: versions-diff skipped"; fi; \
                        exit $$st )

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

check-policies: ## S3 T3.6: Access Analyzer on every IAM document + simulate-custom-policy of the runtime policy (§9); read-only
	AI_ENV_REPO_ROOT="$(CURDIR)" REGION=$(REGION) POLICIES_OUT="$(CURDIR)/target/infra-policies" $(SHELL) $(INFRA)/scripts/check-policies.sh

preview-scratch: ## S3 T3.2/T3.5: pulumi preview of a scratch copy (throwaway backend, stack, passphrase); NEGATIVE=no-logging|no-logging-cast|region
	@$(PULUMI_ENV) REGION=$(REGION) SCRATCH="$(SCRATCH)" NEGATIVE="$(NEGATIVE)" $(SHELL) $(INFRA)/scripts/preview-scratch.sh

preview: ## S3 part B: image-zip, then pulumi preview --diff of the real stack $(STACK)
	$(MAKE) --no-print-directory image-zip
	cd $(INFRA) && $(PULUMI_ENV) pulumi preview --diff --stack $(STACK)

# The image-wait body runs even when `pulumi up` fails (the T3.4 `RUN false` negative: Cloud Control reports the
# failed build), so the D29 comparison, the post-deploy snapshot and versions-diff are always recorded; the exit
# status is pulumi's when it failed, else the wait's. No sub-make on that line: GNU make runs any recipe line that
# names MAKE literally even under -n, so `make -n deploy` stays a dry parse. `make deploy EXPECT_BUILD_FAILURE=1`
# (command line only; the sub-make inherits it) turns preflight P12 into a loud [-  ] row and keeps every other gate:
# the T3.4 `RUN false` negative deploys a zip that make test-docker cannot pass, with its snapshots, wait and diff.
deploy: ## S3 part B: image-zip, s3-preflight PHASE=b, pre-deploy snapshots, pulumi up $(STACK) (interactive confirmation), image-wait; EXPECT_BUILD_FAILURE=1 skips P12 (T3.4)
	$(MAKE) --no-print-directory image-zip
	$(MAKE) --no-print-directory s3-preflight PHASE=b
	@$(OPS) snapshot pre-deploy
	@echo "cd $(INFRA) && pulumi up --stack $(STACK), then image-wait"; \
	  st=0; (cd $(INFRA) && $(PULUMI_ENV) pulumi up --stack $(STACK)) || st=$$?; \
	  $(IMAGE_WAIT_SH); w=$$?; exit $$(( st ? st : w ))

# D29: the wait decides from the versions against the pre-deploy snapshot; the post-deploy snapshot and
# versions-diff run even after a failed build (T3.4 records both).
image-wait: ## S3 part B: poll the image until CREATED/UPDATED or *_FAILED (IMAGE_WAIT_TIMEOUT s), compare versions with the pre-deploy snapshot; RECORD_PROBE=1
	@$(IMAGE_WAIT_SH)

image-status: ## S3 part B: get-microvm-image of $(IMAGE_NAME) (state, latest active and failed versions)
	@$(OPS) status

image-versions: ## S3 part B: list the image versions (state, status); warns from $(VERSIONS_WARN) (quota $(VERSIONS_QUOTA))
	@$(OPS) versions

image-builds: ## S3 part B: builds of VERSION=<n> (default: the latest active and the latest failed version)
	@$(OPS) builds $(call cmdline,VERSION)

image-deactivate: ## S3 part B rollback: mark VERSION=<n> INACTIVE
	@$(OPS) set-status INACTIVE "$(call cmdline,VERSION)"

image-activate: ## S3 part B rollback: mark VERSION=<n> ACTIVE
	@$(OPS) set-status ACTIVE "$(call cmdline,VERSION)"

image-prune: ## S3 part B: delete all but the newest KEEP=3 versions (never an ACTIVE one, one in progress or one a VM runs); dry run unless YES=1
	@$(OPS) prune "$(KEEP_N)" "$(call cmdline,YES)"

image-delete: ## S3 part B recovery (e.g. a first build left CREATE_FAILED): delete the image outside Pulumi; CONFIRM=delete-image
	@test "$(call cmdline,CONFIRM)" = delete-image || { echo "image-delete: deletes $(IMAGE_NAME) and its versions outside Pulumi; set CONFIRM=delete-image on the command line"; exit 1; }
	@$(OPS) vm-guard
	@$(OPS) delete-image

logs: ## S3 part B: list log groups under /aws/lambda-microvms and /aws/lambda/microvms, then tail $(LOG_GROUP) (SINCE=1h, FOLLOW=1)
	@test -n "$(LOG_GROUP)" || { echo "logs: no logGroup in $(INFRA)/image-config.json"; exit 1; }
	@for p in /aws/lambda-microvms /aws/lambda/microvms; do echo "log groups under $$p:"; \
	  aws logs describe-log-groups --log-group-name-prefix $$p --region $(REGION) --query 'logGroups[].[logGroupName,retentionInDays,storedBytes]' --output text | sed 's/^/  /'; done
	aws logs tail $(LOG_GROUP) --since $(SINCE) --format short $(if $(filter 1,$(call cmdline,FOLLOW)),--follow) --region $(REGION)

infra-status: ## S3 part B: ai-env infra status (stack outputs + one live read-only get-microvm-image vs bridge.toml [aws]); WRITE=1 edits [aws] and writes state/infra.toml
	$(AI_ENV) infra status --stack $(STACK) $(if $(filter 1,$(call cmdline,WRITE)),--write)

# D23: runtime credentials never enter Pulumi. The secret crosses exactly one pipe, from create-access-key into
# `ai-env creds aws-set` (zeroized memory, sealed to the keystore key's recipients); the recipe never holds it.
# The check runs first (and builds ai-env) so nothing is created when sealing cannot work. Whether a key was created
# is read from IAM afterwards, never from the CLI's exit status (the key exists even when the CLI fails writing into
# a sealer that already exited): on a sealing failure the recipe prints the delete command of every new id.
# The verification uses only the sealed key (every AWS_* credential variable is cleared) and decrypts it once, one
# Touch ID prompt: `ai-env run` picks the keystore key from the container's recipients (aws-set sealed it to
# [creds].key), and the child retries sts while IAM propagates. The child's exit 42 means the key never answered;
# any other failure is ai-env's own (cancelled, no key, ...) and is not retried. ROTATE=1 seals and verifies a new
# key, then deletes the old one; when the new key does not verify, the printed undo also restores the container
# aws-set kept as aws.env.<unix seconds>.bak.
runtime-key: ## S3 part B (D23): create an access key for ai-env-runtime, seal it with ai-env creds aws-set, verify it; ROTATE=1 replaces the key
	$(AI_ENV) creds aws-set --check
	@set -o pipefail; user=$(RUNTIME_USER); bridge="$(BRIDGE_DIR_SH)"; sealed="$$bridge/credentials/aws.env"; rotate="$(call cmdline,ROTATE)"; \
	  old=$$(aws iam list-access-keys --user-name $$user --region $(REGION) --query 'AccessKeyMetadata[].AccessKeyId' --output text) || exit 1; \
	  old=$${old/None/}; n=$$(wc -w <<<"$$old" | tr -d ' '); \
	  if [ "$$n" -ge 2 ]; then echo "runtime-key: $$user has 2 access keys (the IAM maximum); delete the one that is not sealed first:"; \
	    echo "  aws iam list-access-keys --user-name $$user --region $(REGION)"; \
	    echo "  aws iam delete-access-key --user-name $$user --access-key-id <id> --region $(REGION)"; exit 1; fi; \
	  if [ "$$n" -eq 1 ] && [ "$$rotate" != 1 ]; then echo "runtime-key: $$user already has a key ($$old); ROTATE=1 seals a new one, then deletes it"; exit 1; fi; \
	  if [ "$$n" -eq 0 ] && [ "$$rotate" = 1 ]; then echo "runtime-key: ROTATE=1, but $$user has no key: make runtime-key"; exit 1; fi; \
	  t0=$$(date +%s); \
	  aws iam create-access-key --user-name $$user --output json --region $(REGION) | $(AI_ENV) creds aws-set --user $$user; \
	  st=("$${PIPESTATUS[@]}"); \
	  now=$$(aws iam list-access-keys --user-name $$user --region $(REGION) --query 'AccessKeyMetadata[].AccessKeyId' --output text); lst=$$?; \
	  if [ "$$lst" -ne 0 ]; then \
	    if [ "$${st[1]}" -ne 0 ]; then echo "runtime-key: sealing failed (create-access-key exit $${st[0]}, aws-set exit $${st[1]}) and the keys of $$user cannot be listed (exit $$lst): delete any key not in ($${old:-none}):"; \
	      echo "  aws iam list-access-keys --user-name $$user --region $(REGION)"; exit 1; fi; \
	    echo "runtime-key: warning: cannot list the keys of $$user after sealing (exit $$lst); verifying the sealed key anyway"; now=""; fi; \
	  new=""; for k in $${now/None/}; do case " $$old " in *" $$k "*) ;; *) new="$${new:+$$new }$$k" ;; esac; done; \
	  if [ "$${st[1]}" -ne 0 ]; then \
	    if [ -n "$$new" ]; then echo "runtime-key: sealing failed (create-access-key exit $${st[0]}, aws-set exit $${st[1]}): the new key(s) $$new are sealed nowhere. Delete them:"; \
	      for k in $$new; do echo "  aws iam delete-access-key --user-name $$user --access-key-id $$k --region $(REGION)"; done; \
	    elif [ "$${st[0]}" -ne 0 ]; then echo "runtime-key: create-access-key failed (exit $${st[0]}) and IAM lists no new key of $$user: none was created"; \
	    else echo "runtime-key: sealing failed (aws-set exit $${st[1]}), and IAM does not list the new key yet: delete any key of $$user not in ($${old:-none}):"; \
	      echo "  aws iam list-access-keys --user-name $$user --region $(REGION)"; fi; \
	    exit 1; fi; \
	  bak=""; if [ "$$rotate" = 1 ]; then for f in "$$sealed".*.bak; do ts=$${f##*.env.}; ts=$${ts%.bak}; \
	    case "$$ts" in ''|*[!0-9]*) continue ;; esac; if [ "$$ts" -ge "$$t0" ]; then bak=$$f; fi; done; fi; \
	  out=$$(env $$(env | sed -n 's/^\(AWS_[A-Za-z0-9_]*\)=.*/-u \1/p') $(AI_ENV) run -f "$$sealed" -- sh -c \
	    'printf "id %s\n" "$$AWS_ACCESS_KEY_ID"; for i in 1 2 3 4 5 6; do a=$$(aws sts get-caller-identity --region $(REGION) --query Arn --output text) && { printf "arn %s\n" "$$a"; exit 0; }; \
	       test $$i = 6 && break; echo "runtime-key: the sealed key does not answer yet ($$i/6, IAM propagation)" >&2; sleep 5; done; exit 42'); rc=$$?; \
	  sid=$$(sed -n 's/^id //p' <<<"$$out" | head -1); arn=$$(sed -n 's/^arn //p' <<<"$$out" | head -1); \
	  key=$${sid:-$${new:-(not listed yet)}}; case "$$sid:$$new" in :*" "*) key="one of ($$new)" ;; esac; \
	  case " $$old " in *" $$sid "*) if [ -n "$$sid" ]; then \
	    echo "runtime-key: the container ai-env run verified ($$sealed) still holds the previous key $$sid: aws-set sealed the new key somewhere else. Nothing deleted; check AI_ENV_BRIDGE_DIR, then delete the key not in ($${old:-none}) by hand:"; \
	    echo "  aws iam list-access-keys --user-name $$user --region $(REGION)"; exit 1; fi ;; esac; \
	  extra=""; if [ -n "$$sid" ]; then for k in $$new; do test "$$k" = "$$sid" || extra="$${extra:+$$extra }$$k"; done; fi; \
	  undo() { for k in $$( [ -n "$$sid" ] && echo "$$sid" || echo "$$new" ); do echo "  aws iam delete-access-key --user-name $$user --access-key-id $$k --region $(REGION)"; done; \
	    test -n "$$sid$$new" || echo "  aws iam delete-access-key --user-name $$user --access-key-id <the id not in ($${old:-none})> --region $(REGION)"; \
	    if [ -n "$$bak" ]; then echo "  mv \"$$bak\" \"$$sealed\""; fi; }; \
	  if [ -n "$$extra" ]; then echo "runtime-key: IAM lists new key(s) sealed nowhere besides the sealed $$sid (a retried create-access-key). Delete them:"; \
	    for k in $$extra; do echo "  aws iam delete-access-key --user-name $$user --access-key-id $$k --region $(REGION)"; done; fi; \
	  case "$$rc:$$arn" in \
	  0:*:user/$$user) echo "runtime-key: the sealed key $$key identifies as user/$$user" ;; \
	  0:*|42:*) \
	    if [ -n "$$bak" ]; then echo "runtime-key: the sealed key $$key does not identify as user/$$user. $$sealed now holds it; the previous key $$old is still active and sealed in $$bak. If it never verifies, undo the rotation:"; \
	    else echo "runtime-key: the sealed key $$key does not identify as user/$$user; the previous key ($${old:-none}) is kept. If it never verifies, delete the new one:"; fi; \
	    undo; exit 1 ;; \
	  *) echo "runtime-key: ai-env run failed (exit $$rc): the sealed key $$key is NOT verified and nothing was deleted. Verify it with:"; \
	    echo "  ai-env run -f \"$$sealed\" -- aws sts get-caller-identity --region $(REGION) --query Arn --output text"; \
	    if [ "$$rotate" = 1 ]; then echo "If it identifies as user/$$user, finish the rotation:"; \
	      echo "  aws iam delete-access-key --user-name $$user --access-key-id $$old --region $(REGION)"; \
	      echo "If it never does, undo the rotation:"; undo; fi; \
	    exit 1 ;; \
	  esac; \
	  if [ "$$rotate" = 1 ]; then aws iam delete-access-key --user-name $$user --access-key-id $$old --region $(REGION) || exit 1; \
	    echo "runtime-key: rotated; deleted the old key $$old"; fi

destroy: ## S3 part B: pulumi destroy of $(STACK) (CONFIRM=destroy-$(STACK); refuses while a VM of the image is not TERMINATED), then the post-destroy checklist
	@test "$(call cmdline,CONFIRM)" = "destroy-$(STACK)" || { echo "destroy: removes the image and its versions, roles, runtime user and its keys, bucket, log group and budget of stack $(STACK); set CONFIRM=destroy-$(STACK) on the command line"; exit 1; }
	@$(OPS) vm-guard
	cd $(INFRA) && $(PULUMI_ENV) pulumi destroy --stack $(STACK)
	@$(OPS) checklist
