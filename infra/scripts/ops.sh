#!/usr/bin/env bash
# The part-B image lifecycle helpers behind infra/infra.mk (plans/s3-plan.md D26, D29): snapshots around a deploy,
# waiting for the build, versions and builds, rollback, pruning, the VM guard and the post-destroy checklist; and the
# S5 egress helpers (plans/s5-plan.md "Makefile / ops"): the deploy's plan gate (the plan check and the replacement
# guard over one `pulumi preview --json`), the connector's wait, status, probe and out-of-band delete, and the egress
# steps that end a deploy.
#
# Why a script: polling with a timeout, comparing against a snapshot and keep-N pruning do not fit one-line make
# recipes, and this must run under macOS's /bin/bash 3.2. The image ARN is composed at run time from the caller
# identity (D26); only the snapshots that `deploy` records for `ai-env infra versions-diff` hold it. Existence is
# asked of list-microvm-images (which never errors on absence), so every other error is a real one. Every call
# carries --region. The mutating commands (set-status, prune with YES=1, delete-image) are only reached through
# their make targets, which carry the guards.
#
# Every lookup fails closed with an explicit exit: `set -e` is off inside a function called from `if`, `||` or
# `$(...)`, and a guard (vm-guard before destroy and image-delete, prune's keep rules) must never pass because a
# call failed. Each `x=$(aws ...)` therefore carries its own `|| exit 1`.
#
# Env (set by infra/infra.mk): REGION, IMAGE_NAME, IMAGE_OUT, STACK, IMAGE_WAIT_TIMEOUT, IMAGE_WAIT_POLL,
# VERSIONS_WARN, VERSIONS_QUOTA, CONNECTOR_WAIT_TIMEOUT, CONNECTOR_WAIT_POLL; AI_ENV_CLI (connector-probe,
# post-deploy and claude-update only: the make target's $(AI_ENV), split on blanks and not passed on to any child);
# LOCK and CLAUDE_RELEASES (claude-update only).
set -euo pipefail
# The aws CLI pages its output through less on a terminal (measured 1 Oct 2026: `make image-status` stopped in the
# pager): never here.
export AWS_PAGER=""

region=${REGION:?}
name=${IMAGE_NAME:?IMAGE_NAME is empty: no imageName in infra/image-config.json}
out=${IMAGE_OUT:?}
stack=${STACK:-dev}

# S5: the egress names come from infra/egress-config.json (contract 1), read like the Makefile reads it: a missing file
# or key is empty, and the command that needs it refuses. Every lambda-core, ec2 and logs call carries the pinned
# --endpoint-url as well as --region (as bridge::awscli does); their JSON answers are read with node (jsq), never with
# --query, so a fake must serve the real shape.
infra=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
econf() { sed -n "s/.*\"$1\": *\"\\([^\"]*\\)\".*/\\1/p" "$infra/egress-config.json" 2>/dev/null | head -1 || true; }
connector=$(econf connectorName)
lambda_url="https://lambda.$region.amazonaws.com"
ec2_url="https://ec2.$region.amazonaws.com"
ai_env_line=${AI_ENV_CLI:-}
unset AI_ENV_CLI

# account_id: the caller's account; called as `x=$(account_id) || exit 1` (the exit below only leaves the substitution's
# subshell).
account_id() {
    local acct
    acct=$(aws sts get-caller-identity --region "$region" --query Account --output text) || { echo "ops.sh: sts get-caller-identity failed" >&2; exit 1; }
    case "$acct" in
    [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;;
    *) echo "ops.sh: sts get-caller-identity returned no 12-digit account id" >&2; exit 1 ;;
    esac
    printf '%s\n' "$acct"
}

# image_arn: called as `arn=$(image_arn) || exit 1`.
image_arn() {
    local acct
    acct=$(account_id) || exit 1
    printf 'arn:aws:lambda:%s:%s:microvm-image:%s\n' "$region" "$acct" "$name"
}

# The CLI's text output prints a missing value as None (once per page): drop those lines and empty ones.
none() { printf '%s\n' "$1" | sed -e '/^None$/d' -e '/^$/d'; }

# exists: runs in the current shell, so its exit on a failed listing ends the script even from `if exists`.
exists() {
    local found
    found=$(aws lambda-microvms list-microvm-images --name-filter "$name" --region "$region" --query "items[?name=='$name'].name" --output text) \
        || { echo "ops.sh: list-microvm-images failed" >&2; exit 1; }
    [ -n "$(none "$found")" ]
}

# json_field <file> <field>: a top-level string of a snapshot ("" when absent).
json_field() {
    node -e 'const j = JSON.parse(require("fs").readFileSync(process.argv[1], "utf-8")); const v = j[process.argv[2]]; process.stdout.write(v == null ? "" : String(v));' "$1" "$2"
}

# snapshot <prefix>: <prefix>-image.json (get-microvm-image) and <prefix>-versions.json (list-microvm-image-versions)
# in $IMAGE_OUT; an image that the listing does not show is recorded as {} and {"items": []}. Any failed call
# fails the snapshot and leaves neither file behind (never an older deploy's to compare with).
cmd_snapshot() {
    local prefix=${1:?snapshot needs a prefix} arn img ver
    mkdir -p "$out"
    img="$out/$prefix-image.json"
    ver="$out/$prefix-versions.json"
    rm -f "$img" "$ver" "$img.tmp" "$ver.tmp"
    arn=$(image_arn) || exit 1
    if exists; then
        aws lambda-microvms get-microvm-image --image-identifier "$arn" --region "$region" --output json >"$img.tmp" \
            || { rm -f "$img.tmp"; echo "snapshot: get-microvm-image failed" >&2; exit 1; }
        aws lambda-microvms list-microvm-image-versions --image-identifier "$arn" --region "$region" --output json >"$ver.tmp" \
            || { rm -f "$img.tmp" "$ver.tmp"; echo "snapshot: list-microvm-image-versions failed" >&2; exit 1; }
        mv "$img.tmp" "$img"
        mv "$ver.tmp" "$ver"
        echo "snapshot: $img, $ver"
    else
        echo '{}' >"$img"
        echo '{"items": []}' >"$ver"
        echo "snapshot: no image $name yet (recorded as absent in $out/$prefix-*.json)"
    fi
}

# wait: poll get-microvm-image until CREATED / UPDATED or *_FAILED, bounded by IMAGE_WAIT_TIMEOUT; then decide from
# the versions (D29), not from the state alone. A failed state is terminal too, and the snapshot decides whether this
# deploy failed: the state is a last-operation state, so an image whose earlier build failed stays UPDATE_FAILED
# through every deploy that changes no image input. Only a failed state identical to the pre-deploy snapshot (state,
# active and failed versions, updatedAt) passes, with a warning; a new failed version or a state that turned failed
# during this deploy fails.
cmd_wait() {
    local timeout=${IMAGE_WAIT_TIMEOUT:?} poll=${IMAGE_WAIT_POLL:?} pre="$out/pre-deploy-image.json"
    local arn start elapsed line state active failed updated errors=0 have_pre=0 pre_state="" pre_active="" pre_failed="" pre_updated=""
    arn=$(image_arn) || exit 1
    if [ -f "$pre" ]; then
        have_pre=1
        pre_state=$(json_field "$pre" state) || exit 1
        pre_active=$(json_field "$pre" latestActiveImageVersion) || exit 1
        pre_failed=$(json_field "$pre" latestFailedImageVersion) || exit 1
        pre_updated=$(json_field "$pre" updatedAt) || exit 1
    else
        echo "image-wait: no pre-deploy snapshot ($pre): the versions are not compared"
    fi
    # After a failed `pulumi up` the image may not exist at all: say so instead of polling a missing image.
    exists || { echo "image-wait: no image $name in $region (the deploy did not create it)"; exit 1; }
    start=$(date +%s)
    while :; do
        elapsed=$(($(date +%s) - start))
        if line=$(aws lambda-microvms get-microvm-image --image-identifier "$arn" --region "$region" \
            --query '[state,latestActiveImageVersion,latestFailedImageVersion,updatedAt]' --output text); then
            errors=0
            IFS=$'\t' read -r state active failed updated <<<"$line"
            state=$(none "$state") active=$(none "$active") failed=$(none "$failed") updated=$(none "$updated")
            case "$state" in CREATED | UPDATED | *_FAILED) break ;; esac
            echo "image-wait: ${state:-?} (${elapsed}s)"
        else
            errors=$((errors + 1))
            test "$errors" -lt 3 || { echo "image-wait: get-microvm-image failed 3 times in a row (${elapsed}s)"; exit 1; }
        fi
        if [ "$elapsed" -ge "$timeout" ]; then
            echo "image-wait: still ${state:-unknown} after ${elapsed}s (IMAGE_WAIT_TIMEOUT=$timeout): make image-status image-versions"
            exit 1
        fi
        sleep "$poll"
    done
    case "$state" in
    *_FAILED)
        if [ "$have_pre" -eq 1 ] && [ "$state" = "$pre_state" ] && [ "$active" = "$pre_active" ] && [ "$failed" = "$pre_failed" ] \
            && [ -n "$pre_updated" ] && [ "$updated" = "$pre_updated" ]; then
            echo "image-wait: warning: $state unchanged since the pre-deploy snapshot (active ${active:-none}, failed ${failed:-none}, updated $updated): no new build; the image still carries the earlier failure of version ${failed:-<n>} (make image-builds VERSION=${failed:-<n>}; a changed image input rebuilds)"
            return 0
        fi
        echo "image-wait: $state after ${elapsed}s (latest failed version ${failed:-none}, active ${active:-none}; pre-deploy state ${pre_state:-none}, failed ${pre_failed:-none}): make image-builds VERSION=${failed:-<n>}; make logs"
        exit 1
        ;;
    esac
    if [ "$have_pre" -eq 0 ]; then
        echo "image-wait: $state after ${elapsed}s, active version ${active:-none}, latest failed version ${failed:-none} (not compared: no pre-deploy snapshot)"
        return 0
    fi
    if [ -n "$failed" ] && [ "$failed" != "$pre_failed" ]; then
        echo "image-wait: $state after ${elapsed}s, but a new failed version $failed appeared (was ${pre_failed:-none}): the build failed, active stays ${active:-none}; make image-builds VERSION=$failed"
        exit 1
    fi
    if [ "$active" = "$pre_active" ]; then
        echo "image-wait: $state after ${elapsed}s, active version unchanged (${active:-none}): no new build (no image input changed)"
    else
        echo "image-wait: $state after ${elapsed}s, active version ${pre_active:-none} -> ${active:-none}"
    fi
}

cmd_status() {
    local arn
    arn=$(image_arn) || exit 1
    exists || { echo "image-status: no image $name in $region"; return 0; }
    aws lambda-microvms get-microvm-image --image-identifier "$arn" --region "$region" --output json
}

cmd_versions() {
    local arn warn=${VERSIONS_WARN:?} quota=${VERSIONS_QUOTA:?} vs n
    arn=$(image_arn) || exit 1
    exists || { echo "image-versions: no image $name in $region"; return 0; }
    aws lambda-microvms list-microvm-image-versions --image-identifier "$arn" --region "$region" \
        --query 'items[].{version:imageVersion,state:state,status:status,created:createdAt,reason:stateReason}' --output table || exit 1
    # Counted over the rows: the CLI applies --query per page, so `length(items)` would print one number per page.
    vs=$(aws lambda-microvms list-microvm-image-versions --image-identifier "$arn" --region "$region" --query 'items[].imageVersion' --output text) || exit 1
    n=$(none "$vs" | wc -w | tr -d ' ')
    echo "image-versions: $n of the $quota-version quota"
    if [ "$n" -ge "$warn" ]; then echo "image-versions: warning: $n versions (quota $quota per image): make image-prune KEEP=3, then again with YES=1" >&2; fi
}

# builds [VERSION]: the builds of one version, default the latest active and the latest failed.
cmd_builds() {
    local arn version=${1:-} line v versions
    arn=$(image_arn) || exit 1
    exists || { echo "image-builds: no image $name in $region"; return 0; }
    if [ -n "$version" ]; then
        versions=$version
    else
        line=$(aws lambda-microvms get-microvm-image --image-identifier "$arn" --region "$region" --query '[latestActiveImageVersion,latestFailedImageVersion]' --output text) || exit 1
        versions=$(tr '\t' '\n' <<<"$line" | grep -vx None | sort -u || true)
    fi
    test -n "$versions" || { echo "image-builds: the image has no active or failed version yet"; return 0; }
    for v in $versions; do
        echo "== builds of version $v"
        aws lambda-microvms list-microvm-image-builds --image-identifier "$arn" --image-version "$v" --region "$region" \
            --query 'items[].{build:buildId,state:buildState,arch:architecture,chipset:chipset,generation:chipsetGeneration,created:createdAt,reason:stateReason}' --output table
    done
}

# set-status <ACTIVE|INACTIVE> <VERSION>: rollback / roll forward of one version.
cmd_set_status() {
    local status=$1 version=${2:-} arn
    test -n "$version" || { echo "VERSION=<n> is required (make image-versions lists them)" >&2; exit 2; }
    arn=$(image_arn) || exit 1
    aws lambda-microvms update-microvm-image-version --image-identifier "$arn" --image-version "$version" --status "$status" --region "$region" \
        --query '[imageVersion,state,status]' --output text
}

# prune <KEEP> <YES>: delete every version but the newest KEEP, never an ACTIVE one (the latest active version by
# get-microvm-image, and every row the listing itself shows ACTIVE), one in progress or one a live VM runs; a dry
# run unless YES=1 (D29: storage cost and the 50-version quota). Any failed lookup aborts before anything is marked.
cmd_prune() {
    local keep=$1 yes=${2:-} arn active rows live i=0 created version state status
    case "$keep" in '' | *[!0-9]*) echo "KEEP must be a number >= 1" >&2; exit 2 ;; esac
    test "$keep" -ge 1 || { echo "KEEP must be >= 1" >&2; exit 2; }
    arn=$(image_arn) || exit 1
    exists || { echo "image-prune: no image $name in $region"; return 0; }
    active=$(aws lambda-microvms get-microvm-image --image-identifier "$arn" --region "$region" --query latestActiveImageVersion --output text) || exit 1
    active=$(none "$active")
    live=$(aws lambda-microvms list-microvms --image-identifier "$arn" --region "$region" --query "items[?state!='TERMINATED'].imageVersion" --output text) || exit 1
    live=$(none "$live" | tr '\t' '\n')
    rows=$(aws lambda-microvms list-microvm-image-versions --image-identifier "$arn" --region "$region" \
        --query 'items[].[createdAt,imageVersion,state,status]' --output text) || exit 1
    rows=$(none "$rows" | sort -r)
    local doomed=""
    while IFS=$'\t' read -r created version state status; do
        test -n "$version" || continue
        if [ "$state" = DELETED ]; then continue; fi
        i=$((i + 1))
        if [ "$i" -le "$keep" ]; then echo "keep   $version ($state, $status, $created): one of the newest $keep"; continue; fi
        if [ "$version" = "$active" ]; then echo "keep   $version ($state, $status, $created): the latest active version"; continue; fi
        if [ "$status" = ACTIVE ]; then echo "keep   $version ($state, $status, $created): ACTIVE"; continue; fi
        case "$state" in PENDING | IN_PROGRESS | DELETING) echo "keep   $version ($state, $status, $created): in progress"; continue ;; esac
        if grep -qxF -- "$version" <<<"$live"; then echo "keep   $version ($state, $status, $created): a VM runs it"; continue; fi
        echo "delete $version ($state, $status, $created)"
        doomed="$doomed $version"
    done <<<"$rows"
    test -n "$doomed" || { echo "image-prune: nothing to delete"; return 0; }
    if [ "$yes" != 1 ]; then echo "image-prune: dry run; YES=1 deletes the versions marked delete"; return 0; fi
    for version in $doomed; do
        aws lambda-microvms delete-microvm-image-version --image-identifier "$arn" --image-version "$version" --region "$region" >/dev/null \
            || { echo "image-prune: deleting version $version failed; stopped" >&2; exit 1; }
        echo "image-prune: deleted version $version"
    done
}

# vm-guard: refuse while a network connector other than the stack's exists (S5: a leftover probe connector pins the VM
# subnet and its security group, so destroy would stop half-way and a replacement would fail under its ENIs), then
# while any VM of the image is not TERMINATED (destroy, image-delete, connector-delete). A delete command is printed
# only for a connector that is ours: named <connectorName>-probe-*, or configured on the stack's VM subnet (the stack
# connector's, else the stack outputs' vmSubnetId); any other one is listed without one (it may be another project's).
cmd_vm_guard() {
    local arn alive list others subnet n st carn doc subnets ours
    need_connector
    list=$(connectors) || exit 1
    others=$(others_than "$list" "$connector")
    if [ -n "$others" ]; then
        subnet=$(vm_subnet "$list")
        echo "refusing: network connectors other than the stack's $connector exist (a leftover probe connector pins the VM subnet):"
        while IFS=$'\t' read -r n st carn; do
            subnets=""
            if doc=$(aws lambda-core get-network-connector --identifier "$n" --region "$region" --endpoint-url "$lambda_url" --output json </dev/null 2>/dev/null); then
                subnets=$(printf '%s' "$doc" | jsq '((j.Configuration || {}).VpcEgressConfiguration || {}).SubnetIds || []' | tr '\n' ' ') || subnets=""
                subnets=${subnets% }
            fi
            echo "  $n $st $carn (subnets: ${subnets:-unknown})"
            case "$n" in
            "$connector"-probe-*) ours=1 ;;
            *) if [ -n "$subnet" ] && in_words "$subnet" "$subnets"; then ours=1; else ours=0; fi ;;
            esac
            if [ "$ours" = 1 ]; then
                echo "    delete it once no VM uses it, then wait until make connector-status no longer lists it:"
                echo "    aws lambda-core delete-network-connector --region $region --endpoint-url $lambda_url --identifier $n"
            else
                echo "    not on the VM subnet ${subnet:-(unknown)} nor a probe of $connector: it may be another project's (no delete command; remove it only if it is yours)"
            fi
        done <<<"$others"
        exit 1
    fi
    echo "vm-guard: no network connector but the stack's $connector"
    arn=$(image_arn) || exit 1
    exists || { echo "vm-guard: no image $name, hence no VM of it"; return 0; }
    alive=$(aws lambda-microvms list-microvms --image-identifier "$arn" --region "$region" --query "items[?state!='TERMINATED'].[microvmId,state,imageVersion]" --output text) || exit 1
    alive=$(none "$alive")
    if [ -n "$alive" ]; then
        echo "refusing: VMs of $name are not TERMINATED:"
        printf '%s\n' "$alive" | sed 's/^/  /'
        echo "terminate them first: aws lambda-microvms terminate-microvm --microvm-identifier <id> --region $region"
        exit 1
    fi
    echo "vm-guard: every VM of $name is TERMINATED"
}

# delete-image: out-of-band delete, the recovery for a first build that left CREATE_FAILED (§13).
cmd_delete_image() {
    local arn
    arn=$(image_arn) || exit 1
    exists || { echo "image-delete: no image $name in $region"; return 0; }
    aws lambda-microvms delete-microvm-image --image-identifier "$arn" --region "$region" >/dev/null
    echo "image-delete: delete requested for $name (make image-status shows DELETING, then nothing)"
    echo "the Pulumi state of stack $stack still holds the image: remove it before the next deploy:"
    echo "  cd infra && pulumi stack --show-urns --stack $stack | grep MicrovmImage"
    echo "  cd infra && pulumi state delete '<that urn>' --stack $stack"
    echo "state/egress-verified.toml (${AI_ENV_BRIDGE_DIR:-\$HOME/.config/ai-env/bridge}/state/egress-verified.toml): the image created again numbers its versions anew, and a pass of an old build is no pass (the credential gate and ai-env egress check --if-needed both compare the build, so it is never honoured, and the next check replaces it): remove it to tidy up"
}

cmd_checklist() {
    local vpc log_group prefix
    vpc=$(econf vpcCidr)
    log_group=$(econf logGroup)
    prefix=$(econf parameterPrefix)
    cat <<EOF
Post-destroy checklist (read-only checks, region $region; each should show nothing of ai-env):
  1. aws lambda-microvms list-microvm-images --region $region             # no $name (deleting an image should remove its versions and snapshots: record it)
  2. aws lambda-microvms list-microvms --region $region                   # nothing of $name but TERMINATED
  3. aws logs describe-log-groups --log-group-name-prefix /aws/lambda-microvms --region $region
     aws logs describe-log-groups --log-group-name-prefix /aws/lambda/microvms --region $region
  4. aws iam get-user --user-name ai-env-runtime --region $region         # NoSuchEntity (forceDestroy removed its access keys)
     then delete the sealed key, now useless: rm "\${AI_ENV_BRIDGE_DIR:-\$HOME/.config/ai-env/bridge}/credentials/aws.env"
  5. aws iam get-role --role-name ai-env-image-build --region $region; aws iam get-role --role-name ai-env-vm-exec --region $region
     aws iam list-policies --scope Local --query "Policies[?PolicyName=='ai-env-deploy']" --region $region
  6. aws s3api list-buckets --query "Buckets[?starts_with(Name, 'ai-env-artifacts-')].Name" --region $region
  7. aws budgets describe-budgets --account-id "\$(aws sts get-caller-identity --query Account --output text --region $region)" --region $region   # no ai-env-monthly
  8. aws lambda-core list-network-connectors --region $region --endpoint-url $lambda_url   # no $connector, no $connector-probe-* connector
  9. aws ec2 describe-vpcs --filters Name=cidr,Values=$vpc Name=tag:Project,Values=ai-env --region $region --endpoint-url $ec2_url   # no egress VPC (its subnets, route tables, IGW and security groups go with it)
     aws ec2 describe-network-acls --filters Name=tag:Name,Values=ai-env-egress-vms --region $region --endpoint-url $ec2_url   # the VM subnet's network ACL is gone
 10. aws ec2 describe-instances --filters Name=tag:Name,Values=ai-env-egress-proxy --query 'Reservations[].Instances[].[InstanceId,State.Name]' --output text --region $region --endpoint-url $ec2_url   # the proxy instance: terminated only
 11. aws ssm get-parameters --names $prefix/squid.conf $prefix/allow $prefix/extras $prefix/suspended --query InvalidParameters --region $region --endpoint-url https://ssm.$region.amazonaws.com   # all four listed: none exists
     aws logs describe-log-groups --log-group-name-prefix ${log_group%/*} --region $region --endpoint-url https://logs.$region.amazonaws.com   # no $log_group (nor ${log_group%/*}/dns)
 12. aws iam get-role --role-name $(econf operatorRoleName) --region $region; aws iam get-role --role-name $(econf proxyRoleName) --region $region; aws iam get-instance-profile --instance-profile-name $(econf proxyInstanceProfileName) --region $region   # NoSuchEntity each
 13. bridge.toml [aws]: clear image_arn, execution_role_arn and budget_name, and remove egress_connector_arn and proxy_private_ip, by hand; delete state/infra.toml (infra status refuses a stack without outputs, so nothing rewrites it)
     $(verified_note)
 14. optional: cd infra && pulumi stack rm $stack
EOF
}

# verified_note: the line for state/egress-verified.toml once the connector is gone (informational).
verified_note() {
    echo "state/egress-verified.toml (${AI_ENV_BRIDGE_DIR:-\$HOME/.config/ai-env/bridge}/state/egress-verified.toml): its records are bound to the deleted connector's Id and no longer admit anything; remove it"
}

# ---- S5 egress (plans/s5-plan.md "Makefile / ops") -----------------------------------------------------------------

# jsq <expression> [arg...]: a JavaScript expression over the JSON document on stdin (`j`; the args are the array `a`):
# an array prints one line per element, null or undefined nothing, anything else as a string. Not JSON: exit 1.
jsq() {
    node -e '
let j;
try { j = JSON.parse(require("fs").readFileSync(0, "utf-8")); } catch (e) { process.stderr.write(`ops.sh: not a JSON answer (${e.message})\n`); process.exit(1); }
const v = new Function("j", "a", `return (${process.argv[1]});`)(j, process.argv.slice(2));
for (const x of Array.isArray(v) ? v : v === undefined || v === null ? [] : [v]) console.log(String(x));
' "$@"
}

need_connector() {
    test -n "$connector" || { echo "ops.sh: no connectorName in $infra/egress-config.json" >&2; exit 1; }
}

# need_ai_env: the ai-env command words of AI_ENV_CLI in the array ai_env.
need_ai_env() {
    test -n "$ai_env_line" || { echo "ops.sh: AI_ENV_CLI is empty (the make target passes \$(AI_ENV))" >&2; exit 1; }
    set -f
    ai_env=($ai_env_line)
    set +f
}

in_words() { case " $2 " in *" $1 "*) return 0 ;; esac; return 1; }

# connectors: "<name>\t<state>\t<arn>" per network connector of the account in the region (every page; the managed
# INTERNET_EGRESS and SHELL_INGRESS connectors are not listed: an account without its own lists none, measured
# 1 Oct 2026); called as `x=$(connectors) || exit 1`.
connectors() {
    local doc
    doc=$(aws lambda-core list-network-connectors --region "$region" --endpoint-url "$lambda_url" --output json) \
        || { echo "ops.sh: lambda-core list-network-connectors failed" >&2; exit 1; }
    printf '%s' "$doc" | jsq '(j.NetworkConnectors || []).map((c) => [c.Name, c.State, c.Arn].join("\t"))'
}

# has_connector <listing> <name>; others_than <listing> <name>: the listing's rows of any other name. awk reads its
# whole input (a `| grep -q` would end early, and pipefail would read the writer's SIGPIPE as "not found").
has_connector() { awk -F'\t' -v n="$2" '$1 == n { f = 1 } END { exit !f }' <<<"$1"; }
others_than() { awk -F'\t' -v n="$2" '$1 != "" && $1 != n' <<<"$1"; }

# stack_outputs: `pulumi stack output --json` of the stack (never --show-secrets: it exports no secret), for the ids
# right after `pulumi up` (state/infra.toml is only as new as the last `make infra-status WRITE=1`); the caller holds
# it in a variable, never a file: it carries the account id. Called as `x=$(stack_outputs) || exit 1`.
stack_outputs() {
    pulumi stack output --json --stack "$stack" --cwd "$infra" </dev/null || { echo "ops.sh: pulumi stack output --stack $stack failed" >&2; exit 1; }
}

# vm_subnet <listing>: the stack's VM subnet, the stack connector's configured one, else the stack outputs'
# vmSubnetId; empty when neither answers (vm-guard then names only the probe connectors as ours).
vm_subnet() {
    local doc s=""
    if has_connector "$1" "$connector" \
        && doc=$(aws lambda-core get-network-connector --identifier "$connector" --region "$region" --endpoint-url "$lambda_url" --output json </dev/null 2>/dev/null); then
        s=$(printf '%s' "$doc" | jsq '(((j.Configuration || {}).VpcEgressConfiguration || {}).SubnetIds || [])[0]') || s=""
    fi
    if [ -z "$s" ] && doc=$(stack_outputs 2>/dev/null); then
        s=$(printf '%s' "$doc" | jsq 'j.vmSubnetId') || s=""
    fi
    printf '%s' "$s"
}

# wait_active <identifier> <label>: poll get-network-connector until ACTIVE, bounded by CONNECTOR_WAIT_TIMEOUT.
# FAILED, INACTIVE, DELETING and DELETE_FAILED never turn ACTIVE: exit 1 with the service's StateReasonCode and
# StateReason. Three failed reads in a row: exit 1.
wait_active() {
    local id=$1 what=$2 timeout=${CONNECTOR_WAIT_TIMEOUT:?} poll=${CONNECTOR_WAIT_POLL:?} start elapsed doc state="" code reason errors=0
    start=$(date +%s)
    while :; do
        elapsed=$(($(date +%s) - start))
        if doc=$(aws lambda-core get-network-connector --identifier "$id" --region "$region" --endpoint-url "$lambda_url" --output json); then
            errors=0
            state=$(printf '%s' "$doc" | jsq 'j.State') || exit 1
            case "$state" in
            ACTIVE)
                echo "$what: $id ACTIVE after ${elapsed}s"
                return 0
                ;;
            FAILED | INACTIVE | DELETING | DELETE_FAILED)
                code=$(printf '%s' "$doc" | jsq 'j.StateReasonCode') || exit 1
                reason=$(printf '%s' "$doc" | jsq 'j.StateReason') || exit 1
                echo "$what: $id is $state after ${elapsed}s: ${code:-no StateReasonCode}: ${reason:-no StateReason} (make connector-status)"
                exit 1
                ;;
            esac
            echo "$what: ${state:-?} (${elapsed}s)"
        else
            errors=$((errors + 1))
            test "$errors" -lt 3 || { echo "$what: get-network-connector $id failed 3 times in a row (${elapsed}s)"; exit 1; }
        fi
        if [ "$elapsed" -ge "$timeout" ]; then
            echo "$what: $id still ${state:-unknown} after ${elapsed}s (CONNECTOR_WAIT_TIMEOUT=$timeout): make connector-status"
            exit 1
        fi
        sleep "$poll"
    done
}

# connector-wait: the stack's connector, by name, until ACTIVE (make deploy runs it after image-wait: RunMicrovm may
# use a connector only once it is ACTIVE). A connector the listing does not show fails at once.
cmd_connector_wait() {
    local list
    need_connector
    list=$(connectors) || exit 1
    has_connector "$list" "$connector" || { echo "connector-wait: no connector $connector in $region (did the deploy create it? make connector-status)"; exit 1; }
    wait_active "$connector" connector-wait
}

# connector-status: the stack's connector (get-network-connector), any other connector of the account, and the ENIs
# in the VM subnet (describe-network-interfaces --include-managed-resources: the connector's ENIs are managed and
# invisible without it): count, IPs, security groups. The subnet id comes from the stack outputs (current after every
# `pulumi up`, and still there after connector-delete, when the connector can no longer name it).
cmd_connector_status() {
    local list doc others outputs subnet enis
    need_connector
    list=$(connectors) || exit 1
    if has_connector "$list" "$connector"; then
        doc=$(aws lambda-core get-network-connector --identifier "$connector" --region "$region" --endpoint-url "$lambda_url" --output json) || exit 1
        printf '%s' "$doc" | jsq '(() => { const v = (j.Configuration || {}).VpcEgressConfiguration || {}; const why = [j.StateReasonCode, j.StateReason].filter(Boolean).join(": "); return [
  `connector ${j.Name}: ${j.State}${why ? ` (${why})` : ""}${j.Version === undefined || j.Version === null ? "" : `, version ${j.Version}`}, last modified ${j.LastModified}`,
  `  arn ${j.Arn}`, `  id ${j.Id}`,
  `  subnets ${(v.SubnetIds || []).join(",")}, security groups ${(v.SecurityGroupIds || []).join(",")}, ${v.NetworkProtocol} for ${(v.AssociatedComputeResourceTypes || []).join(",")}`,
  `  operator role ${j.OperatorRole}`]; })()' || exit 1
    else
        echo "connector-status: no connector $connector in $region"
    fi
    others=$(others_than "$list" "$connector")
    if [ -n "$others" ]; then
        echo "other network connectors (destroy, image-delete and connector-delete refuse while they exist):"
        tr '\t' ' ' <<<"$others" | sed 's/^/  /'
    fi
    outputs=$(stack_outputs) || exit 1
    subnet=$(printf '%s' "$outputs" | jsq 'j.vmSubnetId') || exit 1
    test -n "$subnet" || { echo "connector-status: stack $stack exports no vmSubnetId (deployed before S5?)"; exit 1; }
    enis=$(aws ec2 describe-network-interfaces --include-managed-resources --filters "Name=subnet-id,Values=$subnet" --region "$region" --endpoint-url "$ec2_url" --output json) || exit 1
    printf '%s' "$enis" | jsq '(() => { const n = j.NetworkInterfaces || []; return [`${n.length} ENI(s) in the VM subnet ${a[0]} (managed ones included):`,
  ...n.map((e) => `  ${e.NetworkInterfaceId}  ${(e.PrivateIpAddresses || []).map((p) => p.PrivateIpAddress).join(",") || e.PrivateIpAddress}  ${(e.Groups || []).map((g) => g.GroupId).join(",")}  ${e.Status} ${e.InterfaceType || ""}`)]; })()' "$subnet" || exit 1
}

# connector-probe (T5.1; CONFIRM in the make target): a throw-away connector <connectorName>-probe-<unix time> on the
# stack connector's own subnet, security group and operator role (read live from it), then at once, while it is
# PENDING, `ai-env lab run connector-pending <its ARN>` (what RunMicrovm does with a connector that is not ACTIVE: a
# Pulumi create returns only once it is). Its activation time, T5.1's second measurement, is polled in the background
# from the create on (probe_poll), so the time the probe's RunMicrovm takes cannot hide it. The EXIT trap deletes it on
# every path once the create was sent (an ambiguous create may have made it), retrying a refused delete a few times (a
# PENDING connector, or a VM still TERMINATING on it): a probe connector left behind pins the VM subnet, and vm-guard
# refuses while one exists. INT, TERM and HUP are trapped as exits: bash 3.2 kills itself without running the EXIT trap
# when its foreground child dies of an untrapped SIGINT.
PROBE_DELETE_TRIES=6
probe=""
poller=""
watch=""
probe_cleanup() {
    local rc=$? list st i=1 poll=${CONNECTOR_WAIT_POLL:-10}
    trap - EXIT
    if [ -n "$poller" ]; then kill "$poller" 2>/dev/null || true; fi
    if [ -n "$watch" ]; then rm -rf "${watch:?}"; fi
    test -n "$probe" || exit "$rc"
    while :; do
        if aws lambda-core delete-network-connector --identifier "$probe" --region "$region" --endpoint-url "$lambda_url" --output json >/dev/null </dev/null; then
            echo "connector-probe: deleted $probe (DELETING; make connector-status shows when it is gone)"
            break
        fi
        if list=$(connectors); then
            st=$(awk -F'\t' -v n="$probe" '$1 == n { print $2 }' <<<"$list")
            if [ -z "$st" ]; then echo "connector-probe: no connector $probe exists (the create made none, or it is gone): nothing to delete"; break; fi
            if [ "$st" = DELETING ]; then echo "connector-probe: $probe is DELETING already"; break; fi
        fi
        if [ "$i" -ge "$PROBE_DELETE_TRIES" ]; then
            echo "connector-probe: DELETING $probe FAILED $i times: delete it by hand (it pins the VM subnet):" >&2
            echo "  aws lambda-core delete-network-connector --identifier $probe --region $region --endpoint-url $lambda_url" >&2
            test "$rc" -ne 0 || rc=1
            break
        fi
        echo "connector-probe: deleting $probe was refused (attempt $i of $PROBE_DELETE_TRIES: still PENDING, or a VM still holds it); again in ${poll}s"
        sleep "$poll"
        i=$((i + 1))
    done
    exit "$rc"
}

# probe_poll <arn> <t0>: get-network-connector every CONNECTOR_WAIT_POLL s (in the background from the create on) until
# the connector leaves PENDING, three reads in a row fail, or CONNECTOR_WAIT_TIMEOUT passes; prints one line
# "<state|ERROR|TIMEOUT> <seconds since t0> <detail>".
probe_poll() {
    local id=$1 t0=$2 timeout=${CONNECTOR_WAIT_TIMEOUT:?} poll=${CONNECTOR_WAIT_POLL:?} doc state="" elapsed errors=0
    while :; do
        elapsed=$(($(date +%s) - t0))
        if doc=$(aws lambda-core get-network-connector --identifier "$id" --region "$region" --endpoint-url "$lambda_url" --output json </dev/null); then
            errors=0
            state=$(printf '%s' "$doc" | jsq 'j.State') || state=""
            case "$state" in
            "" | PENDING) ;;
            *)
                printf '%s %s %s\n' "$state" "$elapsed" "$(printf '%s' "$doc" | jsq '`${j.StateReasonCode || "no StateReasonCode"}: ${j.StateReason || "no StateReason"}`')"
                return 0
                ;;
            esac
        else
            errors=$((errors + 1))
            if [ "$errors" -ge 3 ]; then printf 'ERROR %s get-network-connector failed 3 times in a row\n' "$elapsed"; return 0; fi
        fi
        if [ "$elapsed" -ge "$timeout" ]; then printf 'TIMEOUT %s still %s\n' "$elapsed" "${state:-unknown}"; return 0; fi
        sleep "$poll"
    done
}

cmd_connector_probe() {
    local doc cfg role arn state t0 rc secs detail
    need_connector
    need_ai_env
    doc=$(aws lambda-core get-network-connector --identifier "$connector" --region "$region" --endpoint-url "$lambda_url" --output json) \
        || { echo "connector-probe: cannot read the stack's connector $connector, whose subnet, security group and operator role the probe takes (make connector-status)"; exit 1; }
    cfg=$(printf '%s' "$doc" | jsq '(() => { const v = (j.Configuration || {}).VpcEgressConfiguration || {}; const s = v.SubnetIds || [], g = v.SecurityGroupIds || [];
  return s.length && g.length ? JSON.stringify({ VpcEgressConfiguration: { SubnetIds: s, SecurityGroupIds: g, NetworkProtocol: "IPv4", AssociatedComputeResourceTypes: ["MicroVm"] } }) : ""; })()') || exit 1
    role=$(printf '%s' "$doc" | jsq 'j.OperatorRole') || exit 1
    if [ -z "$cfg" ] || [ -z "$role" ]; then echo "connector-probe: $connector reports no subnet, security group or operator role"; exit 1; fi
    probe="$connector-probe-$(date +%s)"
    trap probe_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    t0=$(date +%s)
    doc=$(aws lambda-core create-network-connector --name "$probe" --configuration "$cfg" --operator-role "$role" --region "$region" --endpoint-url "$lambda_url" --output json) \
        || { echo "connector-probe: create-network-connector $probe failed"; exit 1; }
    arn=$(printf '%s' "$doc" | jsq 'j.Arn') || exit 1
    state=$(printf '%s' "$doc" | jsq 'j.State') || exit 1
    echo "connector-probe: created $probe ($state): $arn"
    test "$state" = PENDING || echo "connector-probe: warning: $probe is already ${state:-in no state}, not PENDING: the probe records what RunMicrovm does with it anyway"
    watch=$(mktemp -d "${TMPDIR:-/tmp}/ai-env-probe.XXXXXX") || exit 1
    probe_poll "$arn" "$t0" >"$watch/state" &
    poller=$!
    if "${ai_env[@]}" lab run connector-pending "$arn"; then :; else
        rc=$?
        echo "connector-probe: ai-env lab run connector-pending failed (exit $rc, above); the probe connector is deleted"
        exit 1
    fi
    echo "connector-probe: waiting for $probe to leave PENDING (polled every ${CONNECTOR_WAIT_POLL}s since the create)"
    wait "$poller" || true
    poller=""
    state="" secs="" detail=""
    read -r state secs detail <"$watch/state" || true
    case "$state" in
    ACTIVE) echo "connector-probe: $probe became ACTIVE ${secs}s after create-network-connector (polled every ${CONNECTOR_WAIT_POLL}s from the create on)" ;;
    TIMEOUT) echo "connector-probe: $probe $detail after ${secs}s (CONNECTOR_WAIT_TIMEOUT=$CONNECTOR_WAIT_TIMEOUT): make connector-status"; exit 1 ;;
    ERROR) echo "connector-probe: $detail (${secs}s after the create)"; exit 1 ;;
    "") echo "connector-probe: the poll of $probe ended without a state"; exit 1 ;;
    *) echo "connector-probe: $probe is $state after ${secs}s: $detail (make connector-status)"; exit 1 ;;
    esac
}

# connector-delete (CONFIRM and vm-guard in the make target): delete the stack's connector outside Pulumi, the step a
# replacement of what its ENIs pin needs (the replacement guard says so), and wait until the listing no longer shows
# it (CONNECTOR_WAIT_TIMEOUT); DELETE_FAILED stops with the service's reason. Re-run on a connector already DELETING
# (an earlier run that timed out), it resumes the wait; a delete refused because the connector turned DELETING or
# went away meanwhile counts as sent.
cmd_connector_delete() {
    local list timeout=${CONNECTOR_WAIT_TIMEOUT:?} poll=${CONNECTOR_WAIT_POLL:?} start elapsed st doc
    need_connector
    list=$(connectors) || exit 1
    st=$(awk -F'\t' -v n="$connector" '$1 == n { print $2 }' <<<"$list")
    case "$st" in
    "") echo "connector-delete: no connector $connector in $region"; return 0 ;;
    DELETING) echo "connector-delete: $connector is DELETING already: waiting until it is gone" ;;
    *)
        if aws lambda-core delete-network-connector --identifier "$connector" --region "$region" --endpoint-url "$lambda_url" --output json >/dev/null; then
            echo "connector-delete: delete requested for $connector"
        else
            list=$(connectors) || exit 1
            st=$(awk -F'\t' -v n="$connector" '$1 == n { print $2 }' <<<"$list")
            case "$st" in
            "" | DELETING) echo "connector-delete: the delete was refused, but $connector is ${st:-gone} now: waiting until it is gone" ;;
            *) echo "connector-delete: delete-network-connector $connector failed (it is $st)" >&2; exit 1 ;;
            esac
        fi
        ;;
    esac
    start=$(date +%s)
    while :; do
        elapsed=$(($(date +%s) - start))
        list=$(connectors) || exit 1
        st=$(awk -F'\t' -v n="$connector" '$1 == n { print $2 }' <<<"$list")
        test -n "$st" || break
        if [ "$st" = DELETE_FAILED ]; then
            doc=$(aws lambda-core get-network-connector --identifier "$connector" --region "$region" --endpoint-url "$lambda_url" --output json) || exit 1
            echo "connector-delete: $connector is DELETE_FAILED: $(printf '%s' "$doc" | jsq '`${j.StateReasonCode || "no StateReasonCode"}: ${j.StateReason || "no StateReason"}`')"
            exit 1
        fi
        if [ "$elapsed" -ge "$timeout" ]; then echo "connector-delete: $connector still $st after ${elapsed}s (CONNECTOR_WAIT_TIMEOUT=$timeout): make connector-status"; exit 1; fi
        echo "connector-delete: $st (${elapsed}s)"
        sleep "$poll"
    done
    echo "connector-delete: $connector is gone after ${elapsed}s (AWSServiceRoleForLambda releases its ENIs: make connector-status lists the VM subnet's)"
    echo "the Pulumi state of stack $stack still holds it: remove it before the next deploy, which then creates it again:"
    echo "  cd infra && pulumi stack --show-urns --stack $stack | grep NetworkConnector"
    echo "  cd infra && pulumi state delete '<that urn>' --stack $stack"
    verified_note
}

# replace-guard: the plan (stdin) must not replace what the connector's ENIs pin: the egress VPC, a subnet, a security
# group or one of its rules, the VM subnet's network ACL, or the connector itself (fixed names and descriptions keep
# an ordinary change in place). Such a plan passes only while list-network-connectors shows no connector at all: after
# `make connector-delete` nothing pins them (Pulumi's plan still shows the replacements, so a guard without this check
# could never pass again), while a leftover probe connector pins the VM subnet too. A replaced proxy instance is
# allowed and named: any change to a file embedded in its user-data replaces it by design. The same rule holds for a
# VPC step turning enableDnsSupport or enableDnsHostnames from off (or unknown) to on (dnsMode none -> firewall): the
# VPC's Amazon DNS answers the VMs before the DNS Firewall exists, so not while a connector exists.
cmd_replace_guard() {
    local plan verdict guarded proxies dns list
    plan=$(cat)
    verdict=$(printf '%s' "$plan" | node -e '
let plan;
try { plan = JSON.parse(require("fs").readFileSync(0, "utf-8")); } catch (e) { process.stderr.write(`replacement guard: not a pulumi preview --json plan (${e.message})\n`); process.exit(2); }
if (!Array.isArray(plan.steps)) { process.stderr.write("replacement guard: the plan has no steps\n"); process.exit(2); }
const guarded = new Set(["aws:ec2/vpc:Vpc", "aws:ec2/subnet:Subnet", "aws:ec2/securityGroup:SecurityGroup", "aws:vpc/securityGroupIngressRule:SecurityGroupIngressRule",
    "aws:vpc/securityGroupEgressRule:SecurityGroupEgressRule", "aws:ec2/networkAcl:NetworkAcl", "aws-native:lambda:NetworkConnector"]);
const replacing = new Set(["replace", "create-replacement", "delete-replaced", "read-replacement", "import-replacement", "discard-replaced"]);
const seen = new Set();
const dns = new Set();
for (const s of plan.steps) {
    const parts = String(s.urn).split("::");
    const type = (s.newState || s.oldState || {}).type || String(parts[parts.length - 2] || "").split("$").pop();
    const what = `${type} ${parts[parts.length - 1]}`;
    if (type === "aws:ec2/vpc:Vpc" && s.oldState && s.newState) {
        for (const k of ["enableDnsSupport", "enableDnsHostnames"]) {
            const was = (s.oldState.outputs || {})[k] ?? (s.oldState.inputs || {})[k];
            if (was !== true && (s.newState.inputs || {})[k] === true && !dns.has(k)) { dns.add(k); console.log(`dns\t${k}`); }
        }
    }
    if (!replacing.has(s.op) || seen.has(s.urn)) continue;
    seen.add(s.urn);
    if (guarded.has(type)) console.log(`guarded\t${what}`);
    else if (type === "aws:ec2/instance:Instance") console.log(`proxy\t${what}\t${(s.replaceReasons || []).join(", ")}`);
}
') || { echo "replacement guard: cannot read the plan: refusing"; exit 1; }
    proxies=$(awk -F'\t' '$1 == "proxy" { print $2 "\t" $3 }' <<<"$verdict")
    guarded=$(awk -F'\t' '$1 == "guarded" { printf "%s%s", (n++ ? ", " : ""), $2 }' <<<"$verdict")
    dns=$(awk -F'\t' '$1 == "dns" { printf "%s%s", (n++ ? " and " : ""), $2 }' <<<"$verdict")
    if [ -n "$proxies" ]; then
        while IFS=$'\t' read -r p why; do
            echo "replacement guard: $p will be replaced (${why:-the plan names no reason}; a change to a file embedded in its user-data is one): vpc VMs have no egress until the new instance serves; it reads its parameters at boot"
        done <<<"$proxies"
    fi
    if [ -z "$guarded" ] && [ -z "$dns" ]; then
        echo "replacement guard: nothing the connector's ENIs pin is replaced, and the VPC's Amazon DNS stays as it is"
        return 0
    fi
    list=$(connectors) || { echo "replacement guard: the plan replaces or turns on (${guarded}${guarded:+; }${dns}) what the connector constrains, and the connectors cannot be listed: refusing"; exit 1; }
    if [ -n "$list" ]; then
        if [ -n "$guarded" ]; then
            echo "replacement guard: $guarded would be replaced: run \`make connector-delete CONFIRM=delete-connector\` first (the connector's ENIs pin them)"
        fi
        if [ -n "$dns" ]; then
            echo "replacement guard: the plan turns the VPC's $dns on: turning the VPC's Amazon DNS on under a live connector opens DNS until the DNS Firewall exists: make connector-delete first (CONFIRM=delete-connector)"
        fi
        echo "network connectors that exist:"
        tr '\t' ' ' <<<"$list" | sed 's/^/  /'
        exit 1
    fi
    if [ -n "$guarded" ]; then echo "replacement guard: $guarded will be replaced: no network connector exists, so no ENI pins them"; fi
    if [ -n "$dns" ]; then echo "replacement guard: the plan turns the VPC's $dns on: no network connector exists, so no VM reaches that DNS meanwhile"; fi
}

# plan-gate: make deploy's gate before anything is recorded or changed, over the real stack's `pulumi preview --json
# --show-sames --show-reads` on stdin (held in a variable, never written: it carries the account id). The plan check
# (scripts/check-plan.sh --mode <dnsMode> --account-id <the caller's>: the inventory, the egress spec and the IAM
# documents, plans/s5-plan.md "W1 review") and the replacement guard both run, so both verdicts are shown; either
# refusal is exit 1, before `pulumi up`. The account id is an argument only, never written.
cmd_plan_gate() {
    local plan mode acct rc=0 st
    plan=$(cat)
    test -n "$plan" || { echo "deploy: the preview printed no plan: nothing deployed"; exit 1; }
    mode=$(econf dnsMode)
    test -n "$mode" || { echo "deploy: no dnsMode in $infra/egress-config.json: the plan check cannot run; nothing deployed"; exit 1; }
    acct=$(account_id) || { echo "deploy: the plan check needs the caller's account id: nothing deployed"; exit 1; }
    if printf '%s' "$plan" | "$infra/scripts/check-plan.sh" --mode "$mode" --account-id "$acct"; then :; else
        st=$?
        echo "deploy: the plan check refused the plan (exit $st, above)"
        rc=1
    fi
    printf '%s' "$plan" | cmd_replace_guard || rc=1
    test "$rc" -eq 0 || { echo "deploy: refused before pulumi up: nothing deployed"; exit 1; }
}

# plan-errors: the error diagnostics of a failed `pulumi preview --json` (stdin), on the terminal only.
cmd_plan_errors() {
    node -e '
let j;
try { j = JSON.parse(require("fs").readFileSync(0, "utf-8")); } catch (e) { process.exit(0); }
for (const d of j.diagnostics || []) if (d.severity === "error") process.stderr.write(`  ${String(d.message).trim().split("\n").slice(0, 4).join("\n  ")}\n`);
' || true
}

# infra_state_lag <outputs> <state/infra.toml>: the keys of the file whose value is not the stack output's (the egress
# ids and hashes the ai-env egress commands read from it), space-separated; "-" when the file does not exist.
infra_state_lag() {
    printf '%s' "$1" | node -e '
const fs = require("fs");
const out = JSON.parse(fs.readFileSync(0, "utf-8"));
let text;
try { text = fs.readFileSync(process.argv[1], "utf-8"); } catch (e) { console.log("-"); process.exit(0); }
const rec = {};
for (const l of text.split("\n")) { const m = /^([a-z0-9_]+) = "(.*)"$/.exec(l); if (m) rec[m[1]] = m[2]; }
const keys = { proxyInstanceId: "proxy_instance_id", proxyPrivateIp: "proxy_private_ip", egressVpcId: "egress_vpc_id", vmSubnetId: "vm_subnet_id",
    vmEgressSecurityGroupId: "vm_egress_security_group_id", proxySecurityGroupId: "proxy_security_group_id", egressLogGroup: "egress_log_group",
    dnsMode: "dns_mode", parameterPrefix: "parameter_prefix", squidConfSha256: "squid_conf_sha256", allowSha256: "allow_sha256" };
console.log(Object.keys(keys).filter((k) => String(out[k] ?? "") !== (rec[keys[k]] ?? "")).map((k) => keys[k]).join(" "));
' "$2"
}

# vpc_rows <state/vms dir>: the rows that may still run a VM with VPC egress (egress not internet, status not
# terminated; a row without either key counts, as unreadable), by file stem, as `ai-env proxy stop` counts them.
vpc_rows() {
    local f stem egress status rows=""
    for f in "$1"/*.toml; do
        test -f "$f" || continue
        stem=$(basename "$f" .toml)
        egress=$(sed -n 's/^egress = "\([^"]*\)"$/\1/p' "$f" | head -1 || true)
        status=$(sed -n 's/^status = "\([^"]*\)"$/\1/p' "$f" | head -1 || true)
        if [ -z "$egress" ] || [ -z "$status" ]; then rows="$rows $stem (unreadable)"; continue; fi
        if [ "$egress" = internet ] || [ "$status" = terminated ]; then continue; fi
        rows="$rows $stem"
    done
    printf '%s' "${rows# }"
}

# post-deploy [--after-failure]: make deploy's egress steps, run on every exit once `pulumi up` started, in this order:
#   1. `ai-env egress reload --if-changed` when the proxy instance runs (a stopped one reads its parameters when it
#      starts, a new one did at boot);
#   2. a warning naming the state/vms rows that may still run a vpc VM;
#   3. "new image version: run `ai-env egress check`" when the active image version changed (the D29 snapshots): only a
#      passing egress check records what the credential gate admits, per image version;
#   4. `ai-env egress status`, the out-of-band drift check (`pulumi up` does not refresh): drift (exit 1) is named and
#      fails the deploy at the very end; anything it could not verify (exit 7) is a warning.
# --after-failure (pulumi up, image-wait or connector-wait failed): steps 1-3 as above (Pulumi may already have written
# a proxy parameter), and when the reload did not run on a running proxy, a loud line that the proxy may still serve
# the pre-deploy parameters — unless the stack outputs name no proxy at all (no S5 `pulumi up` has completed: a
# proxy an S5 update created read squid.conf and allow at its own boot, and one an earlier failed deploy created may
# serve what it booted with; nothing can name it until a deploy completes); no step 4 (a half-applied stack drifts by
# definition).
# The ai-env egress commands read the stack's ids from state/infra.toml; the outputs tell whether it is current: the
# reload needs the same proxy instance, the status every egress id and hash (else a note says to run make
# infra-status WRITE=1 first). Exit 1 when the reload failed, the proxy's state could not be read, or status found drift.
cmd_post_deploy() {
    local after=0 reloaded=0 have_outputs=1 bridge infra_toml outputs lag proxy doc st rc=0 vms pre="$out/pre-deploy-image.json" post="$out/post-deploy-image.json" a b s report drift
    case "${1:-}" in
    "") ;;
    --after-failure) after=1 ;;
    *) echo "usage: ops.sh post-deploy [--after-failure]" >&2; exit 2 ;;
    esac
    need_ai_env
    bridge=${AI_ENV_BRIDGE_DIR:-$HOME/.config/ai-env/bridge}
    infra_toml="$bridge/state/infra.toml"
    if ! outputs=$(stack_outputs); then
        test "$after" = 1 || exit 1
        outputs='{}'
        have_outputs=0
    fi
    lag=$(infra_state_lag "$outputs" "$infra_toml") || exit 1
    proxy=$(printf '%s' "$outputs" | jsq 'j.proxyInstanceId') || exit 1
    if [ -z "$proxy" ]; then
        echo "deploy: stack $stack exports no proxyInstanceId: egress reload skipped"
    elif [ "$lag" = - ] || in_words proxy_instance_id "$lag"; then
        echo "deploy: $infra_toml does not name the proxy instance $proxy yet (a new instance reads its parameters at boot): egress reload skipped; make infra-status WRITE=1, then make allowlist-reload if a parameter changed since the proxy booted (an earlier failed deploy counts)"
    elif doc=$(aws ec2 describe-instances --instance-ids "$proxy" --region "$region" --endpoint-url "$ec2_url" --output json) \
        && st=$(printf '%s' "$doc" | jsq '(j.Reservations || []).flatMap((r) => r.Instances || []).map((i) => (i.State || {}).Name)'); then
        case "$st" in
        running)
            echo "deploy: ai-env egress reload --if-changed (the proxy instance $proxy runs)"
            if "${ai_env[@]}" egress reload --if-changed; then reloaded=1; else
                echo "deploy: egress reload failed (exit $?, above): the proxy may not serve the deployed parameters (make allowlist-reload; make proxy-stop fails closed)"
                rc=1
            fi
            ;;
        stopped)
            reloaded=1
            echo "deploy: the proxy instance $proxy is stopped: it reads its parameters when it starts (make proxy-start); egress reload skipped"
            ;;
        *) echo "deploy: the proxy instance $proxy is ${st:-in no state}: egress reload skipped (make allowlist-reload once it runs)" ;;
        esac
    else
        echo "deploy: cannot read the state of the proxy instance $proxy (ec2 describe-instances): egress reload skipped (make allowlist-reload)"
        rc=1
    fi
    if [ "$after" = 1 ] && [ "$reloaded" = 0 ]; then
        if [ "$have_outputs" = 1 ] && [ -z "$proxy" ]; then
            echo "deploy: the stack outputs name no proxy yet (no S5 pulumi up has completed): nothing can be reloaded now. A proxy an S5 update created read squid.conf and allow at its own boot; if an earlier failed deploy created it and they changed since, run make infra-status WRITE=1 and make allowlist-reload after the next deploy that completes (make proxy-start and ai-env egress status refuse a proxy serving an older config). Fix the failure above and run make deploy again"
        else
            echo "deploy: THE DEPLOY FAILED AFTER pulumi up STARTED, AND THE PROXY WAS NOT RELOADED: it may still serve the pre-deploy parameters: make allowlist-reload (make infra-status WRITE=1 first when state/infra.toml does not name the proxy instance)"
        fi
    fi
    vms=$(vpc_rows "$bridge/state/vms")
    if [ -n "$vms" ]; then
        echo "deploy: warning: state/vms rows that may still run a vpc VM: $vms; a replaced proxy or connector cut their egress, and they keep their image version (ai-env vm list; ai-env vm terminate ID)"
    fi
    if [ -f "$pre" ] && [ -f "$post" ]; then
        a=$(json_field "$pre" latestActiveImageVersion) || exit 1
        b=$(json_field "$post" latestActiveImageVersion) || exit 1
        if [ "$a" != "$b" ]; then echo "new image version: run \`ai-env egress check\` (active version ${a:-none} -> ${b:-none}: the credential gate admits an image version only with its own passing egress check record) and re-run \`make test-egress\`, the broader live test"; fi
    else
        echo "deploy: no pre- and post-deploy image snapshots in $out: whether the image version changed is unknown (if it did: ai-env egress check)"
    fi
    if [ "$after" = 1 ]; then
        echo "deploy: egress status skipped: the deploy failed (above); ai-env egress status once it is fixed"
    elif [ "$lag" = - ]; then
        echo "deploy: no $infra_toml: make infra-status WRITE=1, then make proxy-start (it waits for a new proxy's first boot: SSM online, squid serving the parameters), then ai-env egress status (the out-of-band drift check)"
    elif [ -n "$lag" ]; then
        echo "deploy: $infra_toml predates this deploy ($lag differ from the stack outputs): make infra-status WRITE=1, then make proxy-start (it waits for a new proxy's first boot: SSM online, squid serving the parameters), then ai-env egress status (the out-of-band drift check)"
    else
        echo "deploy: ai-env egress status (the out-of-band drift check: pulumi up does not refresh)"
        if report=$("${ai_env[@]}" egress status 2>&1); then s=0; else s=$?; fi
        test -z "$report" || printf '%s\n' "$report"
        case "$s" in
        0) ;;
        1)
            drift=$(sed -n 's/.*egress status: drift in //p' <<<"$report" | tail -1)
            echo "deploy: DRIFT: ai-env egress status found drift in ${drift:-the rows above}: something changed outside Pulumi; every other step ran, the deploy fails"
            rc=1
            ;;
        *) echo "deploy: warning: ai-env egress status exit $s (above; 7: a check could not be verified)" ;;
        esac
    fi
    exit "$rc"
}

# update_step <n/total> <label> <command...>: one step of claude-update, announced by its label; the first failure
# stops it, naming the step.
update_step() {
    local at=$1 label=$2 st
    shift 2
    echo "claude-update [$at] $label"
    "$@" && return 0
    st=$?
    echo "claude-update: STOPPED at step $at ($label: exit $st): fix the cause above, then run make claude-update again (it resumes: every step is idempotent)"
    exit "$st"
}

# is_version <text>: a release version as the release site and the extension name it (2.1.287; a pre-release suffix).
is_version() { [[ "$1" =~ ^[0-9]+(\.[0-9]+)+([-+][0-9A-Za-z.]+)?$ ]]; }

# vercmp <a> <b>: older, same or newer — <a> against <b> on their numeric dot parts (a pre-release suffix ignored).
vercmp() {
    awk -v a="${1%%[-+]*}" -v b="${2%%[-+]*}" 'BEGIN { n = split(a, x, "."); m = split(b, y, "."); k = n > m ? n : m;
        for (i = 1; i <= k; i++) { p = x[i] + 0; q = y[i] + 0; if (p < q) { print "older"; exit } if (p > q) { print "newer"; exit } } print "same" }'
}

# live_active: the image version new VMs start now (get-microvm-image, live); empty when it cannot be read.
live_active() {
    local arn doc
    arn=$(image_arn 2>/dev/null) || return 0
    doc=$(aws lambda-microvms get-microvm-image --image-identifier "$arn" --region "$region" --output json 2>/dev/null) || return 0
    printf '%s' "$doc" | jsq 'j.latestActiveImageVersion' 2>/dev/null || true
}

# pinned_image_version: bridge.toml's [aws].image_version when it pins one (`N` or `N.M`; empty for `active` or none).
# Fail-closed: an `[aws]` header spaced or quoted, a quoted key and both quote kinds are read; any other line naming
# image_version outside a comment (a form this reader does not follow: a multi-line string, a dotted or inline key)
# prints `?` and that line, which stops claude-update with what it saw.
pinned_image_version() {
    local f=${AI_ENV_BRIDGE_CONFIG:-${AI_ENV_BRIDGE_DIR:-$HOME/.config/ai-env/bridge}/bridge.toml}
    awk '
        { sub(/\r$/, ""); line = $0; code = $0; sub(/#.*$/, "", code) }
        /^[[:space:]]*\[/ { s = ($0 ~ /^[[:space:]]*\[[[:space:]]*("aws"|\047aws\047|aws)[[:space:]]*\][[:space:]]*(#.*)?$/); next }
        code !~ /image_version/ { next }
        s && /^[[:space:]]*("image_version"|\047image_version\047|image_version)[[:space:]]*=/ {
            sub(/^[^=]*=[[:space:]]*/, ""); sub(/[[:space:]]*(#.*)?$/, "")
            if ($0 ~ /^("active"|\047active\047)$/) next
            gsub(/["\047]/, ""); print ($0 == "" ? "?" line : $0); exit
        }
        { print "?" line; exit }' "$f" 2>/dev/null || true
}

# active_is_deployed: the image version new VMs start (live) is the one the stack deployed (its outputs, which only
# `pulumi up` moves) and was built from the zip the stack deployed (the version's codeArtifact.uri is
# s3://<bucket>/<zipKey>, the outputs naming both, whose claudeVersion is the deployed one): after a rollback with make
# image-deactivate or image-activate, or a failed build the stack would have recorded as done, new VMs start a build
# that does not carry the deployed Claude Code; nor do they while bridge.toml's [aws].image_version pins a version.
# Sets `started` to the live version.
started=""
active_is_deployed() {
    local outputs want pin bucket key arn doc uri
    outputs=$(stack_outputs) || return 1
    want=$(printf '%s' "$outputs" | jsq 'j.latestActiveImageVersion') || return 1
    pin=$(pinned_image_version)
    case "$pin" in
    "") ;;
    \?*)
        echo "claude-update: bridge.toml names image_version in a form this script does not read (${pin#\?}): it may pin new VMs to one version; write image_version = \"active\" under [aws] (or remove it), then make claude-update again"
        return 1
        ;;
    "$want" | "$want.0" | "${want%.0}") echo "claude-update: note: bridge.toml's [aws].image_version = \"$pin\" pins new VMs to the deployed $want today, but no later update will reach them: set it to \"active\" (or remove it)" ;;
    *)
        echo "claude-update: bridge.toml's [aws].image_version = \"$pin\" pins new VMs to that version: the deployed ${want:-(none)} does not reach them; set it to \"active\" (or remove it) to use the update"
        return 1
        ;;
    esac
    started=$(live_active)
    test -n "$started" || { echo "claude-update: cannot read the image's live active version (aws lambda-microvms get-microvm-image)"; return 1; }
    if [ "$started" != "$want" ]; then
        echo "claude-update: new VMs start image version $started, not the deployed ${want:-(none)} (a rollback with make image-deactivate or image-activate?): it does not carry the Claude Code the stack deployed; make image-activate VERSION=$want returns to it"
        return 1
    fi
    bucket=$(printf '%s' "$outputs" | jsq 'j.bucket') || return 1
    key=$(printf '%s' "$outputs" | jsq 'j.zipKey') || return 1
    arn=$(image_arn) || return 1
    doc=$(aws lambda-microvms get-microvm-image-version --image-identifier "$arn" --image-version "$started" --region "$region" --output json) \
        || { echo "claude-update: cannot read image version $started (aws lambda-microvms get-microvm-image-version, above)"; return 1; }
    uri=$(printf '%s' "$doc" | jsq '(j.codeArtifact || {}).uri') || return 1
    if [ -z "$bucket" ] || [ -z "$key" ] || [ "$uri" != "s3://$bucket/$key" ]; then
        echo "claude-update: image version $started was built from ${uri:-an unnamed artifact}, not the zip the stack deployed (s3://${bucket:-?}/${key:-?}): it does not carry the deployed Claude Code; make deploy again"
        return 1
    fi
    echo "claude-update: new VMs start image version $started, the deployed one, built from $key"
    return 0
}

# versions_note: from VERSIONS_WARN image versions on, how many there are and the commands that free some (each
# update adds one; a deploy fails at VERSIONS_QUOTA; make image-prune deletes only inactive ones and never one a VM
# runs). Best effort: nothing when the versions cannot be listed.
versions_note() {
    local arn doc n vms running
    arn=$(image_arn 2>/dev/null) || return 0
    doc=$(aws lambda-microvms list-microvm-image-versions --image-identifier "$arn" --region "$region" --output json 2>/dev/null) || return 0
    n=$(printf '%s' "$doc" | jsq '(j.items || []).length' 2>/dev/null) || return 0
    case "$n" in '' | *[!0-9]*) return 0 ;; esac
    test "$n" -ge "${VERSIONS_WARN:-40}" || return 0
    echo "claude-update: $n of ${VERSIONS_QUOTA:-50} image versions (each update adds one; at ${VERSIONS_QUOTA:-50} a deploy fails): deactivate the old ones no VM runs, then prune them:"
    # Never a version a VM still runs (as image-prune): the VMs listed live; when they cannot be, no deactivate command.
    if vms=$(aws lambda-microvms list-microvms --image-identifier "$arn" --region "$region" --output json 2>/dev/null) \
        && running=$(printf '%s' "$vms" | jsq '(j.items || []).filter((v) => v.state !== "TERMINATED").map((v) => String(v.imageVersion)).join(" ")' 2>/dev/null); then
        printf '%s' "$doc" | jsq '(j.items || []).filter((v) => v.status === "ACTIVE").map((v) => String(v.imageVersion))
            .sort((x, y) => { const a = x.split(".").map(Number), b = y.split(".").map(Number); for (let i = 0; i < Math.max(a.length, b.length); i++) { const d = (b[i] || 0) - (a[i] || 0); if (d) return d; } return 0; })
            .slice(3).map((v) => a[0].split(" ").includes(v) ? `  (not ${v}: a VM runs it)` : `  make image-deactivate VERSION=${v}`)' "$running" 2>/dev/null || true
    else
        echo "  (the VMs could not be listed: make image-versions, then deactivate only an old version no VM runs)"
    fi
    echo "  make image-prune KEEP=3       (a dry run first; it never deletes a version a VM runs)"
    echo "  make image-prune KEEP=3 YES=1"
}

# older_vms_note <version>: the state/vms rows that may still run another image version (and its claude).
older_vms_note() {
    local f st v rows="" dir="${AI_ENV_BRIDGE_DIR:-$HOME/.config/ai-env/bridge}/state/vms"
    for f in "$dir"/*.toml; do
        test -f "$f" || continue
        st=$(sed -n 's/^status = "\([^"]*\)"$/\1/p' "$f" | head -1 || true)
        v=$(sed -n 's/^image_version = "\([^"]*\)"$/\1/p' "$f" | head -1 || true)
        if [ "$st" = terminated ] || [ -z "$v" ] || [ "$v" = "$1" ]; then continue; fi
        rows="$rows $(basename "$f" .toml) ($v)"
    done
    test -z "$rows" || echo "claude-update: VMs still on another image version, and its claude:$rows; they keep it until ai-env vm terminate (ai-env vm list)"
}

# make_ignores_errors: the make that runs this recipe was given -i or -k (its MAKEFLAGS, as GNU make 3.81 and later
# write it: a first word of option letters, or `-x` words after long options, then `--` and the variables; a variable
# alone is the first word). Its children would inherit it and go on past a failed preflight or test. In a subshell:
# no glob of a variable's value.
make_ignores_errors() (
    set -f
    for w in ${MAKEFLAGS:-}; do
        case "$w" in
        --) exit 1 ;;
        --*) ;;
        *=*) exit 1 ;;
        -*) case "${w#-}" in *[ik]*) exit 0 ;; esac ;;
        *) case "$w" in *[ik]*) exit 0 ;; esac ;;
        esac
    done
    exit 1
)

# claude-update (make claude-update): bring the image's Claude Code to the version the Cursor extension bundles (Cursor
# updates the extension on its own, often daily; preflight P10 requires the image to carry exactly the version the Mac
# runs), then rebuild, test, deploy and verify the egress again, each step its own make run (or the operator CLI):
#   1. the versions: B the installed bundle (`ai-env infra pin --bundle-version`), L the lock, D the deployed image's
#      (the stack output claudeVersion); the release site's `latest` for information only (newer, older: said so; a
#      bundle older than D is said to be a downgrade);
#   2. B = L = D: nothing to pin, build or deploy: `make infra-status WRITE=1`, the live active version must be the
#      deployed one (a rollback stops it, and so does bridge.toml's [aws].image_version pinning another version or
#      written in a form pinned_image_version does not read), `ai-env egress check --if-needed` (it starts nothing when
#      that version has its pass; with a stopped proxy and no pass it stops asking for make proxy-start, revoking
#      nothing): a run after a deploy whose check failed or was cancelled finishes it. When the marker
#      $IMAGE_OUT/claude-update.pending names B (a deploy this command started, "B <proxy state before>", removed once
#      a run is done), `make proxy-start` too, and the end notes of a deploy, the proxy's with the state that run found;
#   3. else, after the preconditions (not under make -i or -k; a terminal for Pulumi's confirmation and the Touch ID;
#      the Pulumi passphrase in the environment, as make deploy's preview runs --non-interactive; Docker answering;
#      the AWS identity answering), so that nothing changes when they fail: `make claude-pin CLAUDE_VERSION=B` (when
#      L != B), `make test-docker` (skipped when it already passed for the current zip of B: make deploy rebuilds the
#      zip, and its P12 refuses one that differs), the marker, `make deploy EXPECT_BUILD_FAILURE=` (Pulumi asks before
#      it changes anything; the T3.4 switch never reaches it), `make infra-status WRITE=1`, the live active version
#      check, `make proxy-start` (the check needs squid serving; it also waits for a stopped proxy's boot), `ai-env
#      egress check --if-needed`.
# The first failure stops it naming the step; make claude-update again resumes (every step is idempotent). The lock
# changes in the tree: Mike reviews and commits it.
# Env (infra.mk): AI_ENV_CLI, LOCK, CLAUDE_RELEASES, CLAUDE_GPG_FPR; AI_ENV_BRIDGE_LAB_ASSUME_TTY=1 (the tests only:
# LAB_UNSET clears it on every make run) skips the terminal check.
cmd_claude_update() {
    local lock=${LOCK:?} releases=${CLAUDE_RELEASES:-} bundle locked deployed active latest="" outputs steps s n=0 total st proxy proxy_before="" pinned=0 deploying=0 marker
    local pending="$out/claude-update.pending"
    need_ai_env
    if make_ignores_errors; then echo "claude-update: not under make -i or -k (a failing preflight or test must stop the deploy): run make claude-update without them"; exit 2; fi
    bundle=$("${ai_env[@]}" infra pin --bundle-version) || { st=$?; echo "claude-update: cannot read the Cursor bundle's version (ai-env infra pin --bundle-version: exit $st, above; exit 1 when no bundle is installed): nothing changed"; exit 1; }
    is_version "$bundle" || { echo "claude-update: ai-env infra pin --bundle-version printed \"$bundle\", not a version: nothing changed"; exit 1; }
    locked=$(sed -n 's/^CLAUDE_VERSION=//p' "$lock" 2>/dev/null | head -1 || true)
    outputs=$(stack_outputs) || { echo "claude-update: cannot read the stack outputs of $stack (above): nothing changed"; exit 1; }
    deployed=$(printf '%s' "$outputs" | jsq 'j.claudeVersion') || exit 1
    active=$(printf '%s' "$outputs" | jsq 'j.latestActiveImageVersion') || exit 1
    proxy=$(printf '%s' "$outputs" | jsq 'j.proxyInstanceId') || exit 1
    if [ -n "$releases" ]; then
        latest=$(curl --proto '=https' --tlsv1.2 -fsS -m 10 "$releases/latest" 2>/dev/null | head -c 64 | tr -d '[:space:]' || true)
        is_version "$latest" || latest=""
    fi
    echo "claude-update: Cursor bundle $bundle; $lock ${locked:-(none)}; deployed ${deployed:-(none)} (image version ${active:-none}); the release site's latest ${latest:-unknown}"
    if [ -n "$latest" ]; then
        case $(vercmp "$latest" "$bundle") in
        newer) echo "claude-update: the release site's latest $latest is newer than the Cursor bundle $bundle: the image follows the bundle, the version the Mac runs (preflight P10); once Cursor updates the extension, run make claude-update again" ;;
        older) echo "claude-update: the Cursor bundle $bundle is ahead of the release site's latest $latest (a release not promoted yet, or pulled): the image follows the bundle" ;;
        esac
    fi
    if is_version "$deployed" && [ "$(vercmp "$bundle" "$deployed")" = older ]; then
        echo "claude-update: a DOWNGRADE: the Cursor bundle $bundle is older than the deployed $deployed (the extension went back): the image follows the bundle"
    fi
    if [ "$bundle" = "$locked" ] && [ "$bundle" = "$deployed" ]; then
        marker=$(cat "$pending" 2>/dev/null || true)
        case "$marker" in
        "$bundle "?*)
            # A deploy of this bundle that this command started did not finish its steps: resume them all.
            proxy_before=${marker#* }
            [ "$proxy_before" != unknown ] || proxy_before=""
            echo "claude-update: $bundle is deployed, and the run that deployed it stopped before its end: its remaining steps (the status, the active version, the proxy, the egress check)"
            steps="status active proxy check"
            deploying=1
            ;;
        *)
            rm -f "$pending"
            echo "claude-update: $bundle is pinned and deployed: nothing to build or deploy; the status, then the egress check if the active image version has no pass"
            steps="status active check"
            ;;
        esac
    else
        if [ "${AI_ENV_BRIDGE_LAB_ASSUME_TTY:-}" != 1 ] && { [ ! -t 0 ] || [ ! -t 1 ]; }; then
            echo "claude-update: needs a terminal (make deploy asks Pulumi's confirmation, the egress check one Touch ID: not from a pipe, cron or launchd): nothing changed"
            exit 1
        fi
        test -n "${PULUMI_CONFIG_PASSPHRASE:-}${PULUMI_CONFIG_PASSPHRASE_FILE:-}" \
            || { echo "claude-update: export PULUMI_CONFIG_PASSPHRASE_FILE first (the file holding the $stack stack's passphrase: make deploy's preview runs --non-interactive): nothing changed"; exit 1; }
        docker info >/dev/null 2>&1 || { echo "claude-update: Docker does not answer (docker info), and make test-docker needs it: start Docker, then make claude-update: nothing changed"; exit 1; }
        ( account_id ) >/dev/null || { echo "claude-update: the AWS identity does not answer (aws sts get-caller-identity, above): renew the session, then make claude-update: nothing changed"; exit 1; }
        steps="deploy status active proxy check"
        deploying=1
        if [ "$bundle" != "$locked" ]; then
            steps="pin test $steps"
        elif [ -f "$out/test-docker.ok" ] && [ -f "$out/image.zip" ] && [ "$(cat "$out/test-docker.ok")" = "$(shasum -a 256 "$out/image.zip" | cut -d' ' -f1)" ] \
            && [ "$(jsq 'j.claudeVersion' <"$out/image.json" 2>/dev/null)" = "$bundle" ]; then
            echo "claude-update: make test-docker already passed for $out/image.zip (claude $bundle): not again (make deploy rebuilds the zip; its preflight P12 refuses one that differs)"
        else
            steps="test $steps"
        fi
        if [ -n "$proxy" ]; then
            proxy_before=$(aws ec2 describe-instances --instance-ids "$proxy" --region "$region" --endpoint-url "$ec2_url" --output json 2>/dev/null \
                | jsq '(j.Reservations || []).flatMap((r) => r.Instances || []).map((i) => (i.State || {}).Name)' 2>/dev/null || true)
        fi
    fi
    total=$(wc -w <<<"$steps" | tr -d ' ')
    for s in $steps; do
        n=$((n + 1))
        case "$s" in
        pin) update_step "$n/$total" "make claude-pin CLAUDE_VERSION=$bundle" make --no-print-directory claude-pin CLAUDE_VERSION="$bundle"; pinned=1 ;;
        test) update_step "$n/$total" "make test-docker" make --no-print-directory test-docker ;;
        deploy)
            # A deploy this command starts: a rerun after any failure from here on still owes the proxy step. An
            # unfinished run's marker keeps the proxy state that run found first (it may have started the proxy since).
            marker=$(cat "$pending" 2>/dev/null || true)
            case "$marker" in *" "?*) [ "${marker#* }" = unknown ] || proxy_before=${marker#* } ;; esac
            mkdir -p "$out" && printf '%s %s\n' "$bundle" "${proxy_before:-unknown}" >"$pending"
            # EXPECT_BUILD_FAILURE= : the T3.4 switch typed on claude-update's command line must not reach the
            # deploy (it would skip P12, which the test-docker skip relies on).
            update_step "$n/$total" "make deploy" make --no-print-directory deploy EXPECT_BUILD_FAILURE=
            ;;
        status) update_step "$n/$total" "make infra-status WRITE=1" make --no-print-directory infra-status WRITE=1 ;;
        active) update_step "$n/$total" "new VMs start the deployed image version" active_is_deployed ;;
        proxy) update_step "$n/$total" "make proxy-start (squid serving the deployed parameters)" make --no-print-directory proxy-start ;;
        check) update_step "$n/$total" "ai-env egress check --if-needed" "${ai_env[@]}" egress check --if-needed ;;
        esac
    done
    if outputs=$(stack_outputs 2>/dev/null); then
        deployed=$(printf '%s' "$outputs" | jsq 'j.claudeVersion') || deployed=""
    fi
    if [ "$deployed" != "$bundle" ]; then
        echo "claude-update: the stack now reports Claude Code ${deployed:-(none)}, not the Cursor bundle's $bundle (did the extension update during the run?): run make claude-update again"
        exit 1
    fi
    echo "claude-update: done: new VMs start image version ${started:-unknown} with Claude Code $deployed, the Cursor bundle's, and its egress check passed"
    rm -f "$pending"
    if [ "$pinned" = 1 ] && ! { command -v gpg >/dev/null && gpg --list-keys "${CLAUDE_GPG_FPR:-none}" >/dev/null 2>&1; }; then
        echo "claude-update: the new pin rests on the release manifest over HTTPS only (its signature was not checked: the release key ${CLAUDE_GPG_FPR:-} is not in gpg); import it once, then make claude-pin verifies it, fail-closed"
    fi
    case "$proxy_before" in
    "" | running) ;;
    *) echo "claude-update: the proxy was $proxy_before before this run and runs now: make proxy-stop when idle" ;;
    esac
    test -z "$started" || older_vms_note "$started"
    if [ "$deploying" = 1 ]; then
        versions_note
        echo "claude-update: make test-egress, the broader live test the deploy names, is not part of the daily update: run it when the egress side changes"
    fi
    if git ls-files --error-unmatch -- "$lock" >/dev/null 2>&1 && ! git diff --quiet -- "$lock" 2>/dev/null; then
        echo "claude-update: $lock changed: review and commit it"
    fi
}

cmd=${1:-}
shift || true
case "$cmd" in
snapshot) cmd_snapshot "$@" ;;
wait) cmd_wait ;;
status) cmd_status ;;
versions) cmd_versions ;;
builds) cmd_builds "$@" ;;
set-status) cmd_set_status "$@" ;;
prune) cmd_prune "$@" ;;
vm-guard) cmd_vm_guard ;;
delete-image) cmd_delete_image ;;
checklist) cmd_checklist ;;
connector-wait) cmd_connector_wait ;;
connector-status) cmd_connector_status ;;
connector-probe) cmd_connector_probe ;;
connector-delete) cmd_connector_delete ;;
plan-gate) cmd_plan_gate ;;
replace-guard) cmd_replace_guard ;;
plan-errors) cmd_plan_errors ;;
post-deploy) cmd_post_deploy "$@" ;;
claude-update) cmd_claude_update ;;
*) echo "usage: ops.sh snapshot <prefix> | wait | status | versions | builds [VERSION] | set-status ACTIVE|INACTIVE VERSION | prune KEEP [1] | vm-guard | delete-image | checklist | connector-wait | connector-status | connector-probe | connector-delete | plan-gate | replace-guard | plan-errors | post-deploy [--after-failure] | claude-update (the plan on stdin for plan-gate, replace-guard, plan-errors)" >&2; exit 2 ;;
esac
