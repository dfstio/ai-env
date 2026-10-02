#!/usr/bin/env bash
# make preview-scratch [NEGATIVE=...] [EGRESS_MODE=none|firewall]: a full `pulumi preview` of a scratch COPY of infra/
# against the real account, with a throwaway backend, passphrase and stack (D17; T3.2, T3.5; S5).
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
# and name (53 in dnsMode none: S3's 16 and S5's 37; EGRESS_MODE=firewall previews the copy with dnsMode firewall:
# 58), the pinned providers, every egress input and reference, every IAM document (for the caller's account, read
# once from `aws sts get-caller-identity` into a shell variable) and no update of the parameters `ai-env egress`
# owns. A --json plan has no stack outputs, so the 14
# egress outputs `ai-env infra status` reads are checked in the text preview, squidConfSha256 and allowSha256
# against the SHA-256 of the planned parameter values. Then the same plan, rewritten in memory into the shape
# `pulumi preview --json` gives for the stack once it exists (every step same, or the VM subnet, VM security group
# and VPC as updates; each id in oldState only, every reference and IAM document resolved for those ids), must pass
# too, and four tampered copies of it (the deploy policy's CreateNetworkConnector condition naming the proxy
# subnet, the connector on the proxy subnet or the proxy's security group, the connector passed another role) must
# be refused: a fresh scratch stack only creates, and a check that saw only creates once refused every deploy after
# the first. The layers a negative goes through, each one alone (the
# earlier ones disabled in the scratch copy through their scratch:* markers):
#   spec   assertEgressSpec, before any resource is registered;
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
#                    swapped, every rule attached to the proxy group, the proxy's ingress referencing itself: plan
#   iam-widen        AdministratorAccess in the exec role's managedPolicyArns (guard); then also an inline policy on
#                    the operator role, a Widen statement in MacRuntimePolicy and ssm:* in the proxy's policy: plan
#   owned-param-reset
#                    the --json plan with an update step on the suspended parameter and a replace step on the extras
#                    one (what any change of theirs but tags would plan): plan (a fresh stack only creates, so the
#                    steps are rewritten in the plan held in memory)
#
# Env (set by infra/infra.mk): AI_ENV_REPO_ROOT, REGION, IMAGE_JSON (absolute), SCRATCH, NEGATIVE, EGRESS_MODE.
set -euo pipefail

root=${AI_ENV_REPO_ROOT:?}
: "${REGION:?}"
scratch=${SCRATCH:?}
negative=${NEGATIVE:-}
mode=${EGRESS_MODE:-}
real_image_json=${IMAGE_JSON:?}

negatives="no-logging no-logging-cast region vm-sg-open private-route nacl-open dns-support-on-in-none-mode stray-rule stray-type late-transform early-transform dns-firewall-qtype miswired iam-widen owned-param-reset"
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
# Disable a layer in the scratch copy, so the next one alone must refuse.
no_spec() {
    edit_file index.ts '/scratch:assert/s/assertEgressSpec(egress);/void assertEgressSpec;/'
    grep -qF 'void assertEgressSpec; // scratch:assert' index.ts || fail "the scratch:assert marker no longer disables assertEgressSpec"
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
# (a role's, user's or instance profile's is its name, the bucket's its name, a subnet's subnet-…, a group's
# sg-…), every unknown input resolved through its property dependencies, the IAM documents rendered by policies.ts
# for those ids (the compiled copy plan_check left in $scratch/plan-check). <variant>: none | updated (the VM subnet,
# the VM security group and the VPC are update steps: their ids, too, come from oldState) | deploy-proxy-subnet (the
# deploy policy names the proxy subnet) | connector-proxy-subnet (the connector's subnet is the proxy subnet) |
# connector-proxy-sg (its security group is the proxy's) | connector-operator-role (it is passed another role).
existing_plan() {
    ACCOUNT_ID="$acct" node -e '
const fs = require("fs");
const [out, egressConfig, imageConfig, variant] = process.argv.slice(1);
const pol = require(`${out}/policies.js`);
const spec = require(`${out}/egress-spec.js`);
const cfg = spec.loadEgressConfig(egressConfig);
const img = JSON.parse(fs.readFileSync(imageConfig, "utf-8"));
const plan = JSON.parse(fs.readFileSync(0, "utf-8"));
const UNKNOWN = "04da6b54-80e4-46f7-96ec-b56ff0331ba9";
const name = (s) => s.urn.split("::").pop();
const type = (s) => (s.newState || s.oldState).type;
const ids = new Map();
let n = 0;
for (const s of plan.steps) {
    const t = type(s), i = (s.newState || {}).inputs || {}, k = n++;
    const hex = (p) => `${p}-0${k.toString(16).padStart(16, "0")}`;
    ids.set(s.urn, t === "aws:iam/role:Role" || t === "aws:iam/user:User" || t === "aws:iam/instanceProfile:InstanceProfile" ? i.name
        : t === "aws:s3/bucket:Bucket" ? i.bucket
        : t === "aws:ec2/subnet:Subnet" ? hex("subnet") : t === "aws:ec2/securityGroup:SecurityGroup" ? hex("sg") : t === "aws:ec2/vpc:Vpc" ? hex("vpc")
        : t.startsWith("pulumi:providers:") ? `00000000-0000-4000-8000-${k.toString(16).padStart(12, "0")}` : hex("id"));
}
const byName = (t, nm) => plan.steps.find((s) => type(s) === t && name(s) === nm);
const vmSubnet = ids.get(byName("aws:ec2/subnet:Subnet", "ai-env-egress-vms").urn);
const proxySubnet = ids.get(byName("aws:ec2/subnet:Subnet", "ai-env-egress-proxy").urn);
const vmSg = ids.get(byName("aws:ec2/securityGroup:SecurityGroup", cfg.vmSecurityGroupName).urn);
const proxySg = ids.get(byName("aws:ec2/securityGroup:SecurityGroup", cfg.proxySecurityGroupName).urn);
const updated = new Set([byName("aws:ec2/subnet:Subnet", "ai-env-egress-vms").urn, byName("aws:ec2/securityGroup:SecurityGroup", cfg.vmSecurityGroupName).urn, byName("aws:ec2/vpc:Vpc", "ai-env-egress").urn]);
const bucket = ids.get(plan.steps.find((s) => type(s) === "aws:s3/bucket:Bucket").urn);
const names = (subnet) => ({ accountId: process.env.ACCOUNT_ID, region: pol.REGION, bucket, imageName: img.imageName, logGroup: img.logGroup,
    egress: { ...spec.egressNames(cfg), vmSubnetId: subnet, vmSecurityGroupId: vmSg } });
const docs = (subnet) => new Map(pol.allPolicies(names(subnet)).map((d) => [d.name, JSON.stringify(d.document)]));
const good = docs(vmSubnet), bad = docs(proxySubnet);
// Which document each IAM input is (print-policies names).
const doc = { "aws:iam/role:Role": { "ai-env-image-build": "build-trust", "ai-env-vm-exec": "execution-trust", [cfg.proxyRoleName]: "proxy-trust", [cfg.operatorRoleName]: "operator-trust" },
    "aws:iam/rolePolicy:RolePolicy": { "ai-env-image-build": "build", "ai-env-vm-exec": "execution", [cfg.proxyRoleName]: "proxy" },
    "aws:iam/userPolicy:UserPolicy": { MacRuntimePolicy: "runtime" },
    "aws:iam/policy:Policy": { "ai-env-deploy": "deploy", "ai-env-deploy-egress": "deploy-egress", "ai-env-deploy-dns": "deploy-dns" } };
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
        inputs[k] = which && k === iamKey ? ((variant === "deploy-proxy-subnet" && which === "deploy" ? bad : good).get(which) ?? v) : resolve(v, (st.propertyDependencies || {})[k] || [], k);
    }
    if (st.type === "aws-native:lambda:NetworkConnector") {
        // An ARN cannot be resolved from its two dependencies (the role and its attachment): it is the ARN of the operator role.
        inputs.operatorRole = pol.roleArn(names(vmSubnet), variant === "connector-operator-role" ? "ai-env-vm-exec" : cfg.operatorRoleName);
        if (variant === "connector-proxy-subnet") inputs.configuration.vpcEgressConfiguration.subnetIds = [proxySubnet];
        if (variant === "connector-proxy-sg") inputs.configuration.vpcEgressConfiguration.securityGroupIds = [proxySg];
    }
    const kept = { ...st, inputs };
    delete kept.id;
    s.op = variant === "updated" && updated.has(s.urn) ? "update" : "same";
    s.newState = kept;
    s.oldState = st.type === "pulumi:pulumi:Stack" ? { ...kept } : { ...kept, id: ids.get(s.urn), outputs: { ...inputs, id: ids.get(s.urn) } };
    if (st.provider) {
        const purn = st.provider.slice(0, st.provider.lastIndexOf("::"));
        s.provider = s.newState.provider = s.oldState.provider = `${purn}::${ids.get(purn)}`;
    }
}
const left = [];
const walk = (v, at) => { if (v === UNKNOWN || (typeof v === "string" && v.includes(UNKNOWN))) left.push(at); else if (v !== null && typeof v === "object") for (const [k, x] of Object.entries(v)) walk(x, `${at}.${k}`); };
plan.steps.forEach((s) => walk(s, name(s)));
if (left.length > 0) throw new Error(`existing_plan: unknown values left at ${left.slice(0, 8).join(", ")}`);
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
    # A --json plan has no stack outputs: the egress outputs `ai-env infra status` reads, from the text preview, and
    # the two parameter hashes against the SHA-256 of the planned values.
    outputs=$(sed -n '/--outputs:--/,/^Resources:/p' <<<"$out")
    for k in connectorArn connectorName proxyPrivateIp proxyInstanceId egressVpcId vmSubnetId vmEgressSecurityGroupId proxySecurityGroupId \
        operatorRoleArn egressLogGroup dnsMode parameterPrefix squidConfSha256 allowSha256; do
        grep -qE "^ +$k +: " <<<"$outputs" || fail "the preview plans no stack output $k"
    done
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
    # The same stack once it exists: the plan check must accept it (ids from oldState, for same and update steps) and
    # refuse it tampered.
    for v in none updated; do
        existing=$(existing_plan "$v" <<<"$plan") || fail "existing stack, $v: the plan could not be rewritten"
        out=$(plan_check <<<"$existing" 2>&1) || { echo "$out"; fail "existing stack, $v: the plan check refused the plan of the deployed stack (ids in oldState)"; }
        echo "existing stack, $v: $(first_line "check-plan: ok" "$out")"
    done
    for v in deploy-proxy-subnet connector-proxy-subnet connector-proxy-sg connector-operator-role; do
        case "$v" in
        deploy-proxy-subnet) t="aws:iam/policy:Policy ai-env-deploy: policy is not policies.ts deployPolicy()" ;;
        connector-proxy-subnet) t="connector: subnetIds is not the VM subnet" ;;
        connector-proxy-sg) t="connector: securityGroupIds is not the VM security group" ;;
        *) t="connector: operatorRole arn:aws:iam::" ;;
        esac
        tampered=$(existing_plan "$v" <<<"$plan") || fail "existing stack, $v: the plan could not be rewritten"
        if out=$(plan_check <<<"$tampered" 2>&1); then echo "$out"; fail "existing stack, $v: the plan check passed"; fi
        diag=$(first_line "$t" "$out")
        test -n "$diag" || { echo "$out"; fail "existing stack, $v: the plan check refused, but not with \"$t\""; }
        echo "existing stack, $v: $diag"
    done
    echo "$label: ok (dnsMode $(dns_mode): the preview, the plan check and the 14 egress outputs passed; the existing-stack plans (same, update) passed, their four tampered copies were refused)"
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
    expect_refusal spec "the VM security group allows exactly one rule, egress TCP 3128 to 10.42.0.10/32"
    no_spec
    expect_refusal guard "egress guard (infra/egress.ts) refused aws:vpc/securityGroupEgressRule:SecurityGroupEgressRule ai-env-vm-egress-to-0.0.0.0-0-tcp-443"
    no_guard
    expect_plan_refusal "not in the stack inventory: ai-env-vm-egress-to-0.0.0.0-0-tcp-443" \
        "ai-env-vm-egress-to-0.0.0.0-0-tcp-443: ai-env-vm-egress egress tcp 443 0.0.0.0/0: the VM security group allows exactly one rule"
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
    expect_refusal spec "the VM subnet's network ACL must allow exactly one egress rule"
    no_spec
    expect_refusal guard "egress guard (infra/egress.ts) refused aws:ec2/networkAcl:NetworkAcl ai-env-egress-vms: the VM subnet's network ACL must allow exactly one egress rule"
    no_guard
    expect_plan_refusal "network ACL ai-env-egress-vms: the VM subnet's network ACL must allow exactly one egress rule"
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
    echo "$label: ok (the plan check refused swapped route table associations, rules on the wrong group and a self-referencing rule)"
    ;;
iam-widen)
    edit_file iam.ts '/scratch:exec-role/s|assumeRolePolicy: trust, tags,|assumeRolePolicy: trust, tags, managedPolicyArns: ["arn:aws:iam::aws:policy/AdministratorAccess"],|'
    grep -qF 'managedPolicyArns: ["arn:aws:iam::aws:policy/AdministratorAccess"],' iam.ts || fail "the scratch:exec-role marker no longer widens the execution role"
    expect_refusal guard "egress guard (infra/egress.ts) refused aws:iam/role:Role ai-env-vm-exec: input managedPolicyArns is outside the stack spec"
    edit_file egress.ts '/scratch:operator-role/s|assumeRolePolicy: JSON.stringify(operatorTrustPolicy()), tags,|assumeRolePolicy: JSON.stringify(operatorTrustPolicy()), tags, inlinePolicies: [{ name: "widen", policy: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "iam:*", Resource: "*" }] }) }],|'
    grep -qF 'inlinePolicies: [{ name: "widen"' egress.ts || fail "the scratch:operator-role marker no longer adds an inline policy"
    edit_file policies.ts '/scratch:runtime/s|^\(.*\)}, // scratch:runtime$|\1}, { Sid: "Widen", Effect: "Allow", Action: ["*"], Resource: ["*"] }, // scratch:runtime|'
    grep -qF '{ Sid: "Widen", Effect: "Allow", Action: ["*"], Resource: ["*"] }, // scratch:runtime' policies.ts || fail "the scratch:runtime marker no longer widens MacRuntimePolicy"
    edit_file policies.ts '/scratch:proxy-policy/s|Action: \["ssm:GetParameter", "ssm:GetParameters"\]|Action: ["ssm:*"]|'
    grep -qF 'Action: ["ssm:*"], Resource: [proxyParameterArn(n)] }, // scratch:proxy-policy' policies.ts || fail "the scratch:proxy-policy marker no longer widens the proxy's policy"
    no_guard
    expect_plan_refusal "aws:iam/role:Role ai-env-vm-exec: managedPolicyArns must be unset" \
        "aws:iam/role:Role ai-env-egress-operator: inlinePolicies must be unset" \
        "aws:iam/userPolicy:UserPolicy MacRuntimePolicy: policy is not policies.ts runtimePolicy(); extra statements Widen" \
        "aws:iam/rolePolicy:RolePolicy ai-env-egress-proxy: policy is not policies.ts proxyRolePolicy(); a statement differs"
    echo "$label: ok (the guard refused a managed policy on a role; the plan check refused it, an operator inline policy and two widened documents)"
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
esac
