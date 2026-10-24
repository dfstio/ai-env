#!/usr/bin/env bash
# The part-B image lifecycle helpers behind infra/infra.mk (plans/s3-plan.md D26, D29): snapshots around a deploy,
# waiting for the build, versions and builds, rollback, pruning, the VM guard and the post-destroy checklist; and the
# S5 egress helpers (plans/s5-plan.md "Makefile / ops"): the deploy's plan gate (the plan check and the replacement
# guard over one `pulumi preview --json`), the connector's wait, status, probe and out-of-band delete, and the egress
# steps that end a deploy; and the S8 operators' helpers (plans/s8-operators-contracts.md §9): which AWS identity may run
# a step (identity), whether the stack has its deployer yet (stack-deployer, infra.mk's TIER), and issuing an access
# key of the runtime, ops or deployer user (key-issue). Every operator step runs under `ai-env as` (infra.mk's TIER):
# the key in its environment, never this shell's own AWS settings. (S11 retired claude-update: VMs follow Cursor's
# Claude Code with no deploy, `ai-env claude update`.)
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
# post-deploy and key-issue only: the make target's $(AI_ENV), split on blanks and not passed on to any child);
# BREAKGLASS (identity only: 1 when given on the make command line) and ROTATE
# (key-issue only, the same); AI_ENV_BRIDGE_AS, the marker `ai-env as` sets, read by identity, and by the printed
# recovery commands, which start with the runner of the identity that must run them (as_writer).
# AI_ENV_PASTE_STDIN, the debug builds' paste knob (a test session's leftover), is dropped for every command.
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
# The operator CLI the make targets run is a debug build (cargo run), whose `ai-env as deployer` reads the key from a
# stdin that is not a terminal when AI_ENV_PASTE_STDIN=1: never from here (key-issue's CLI).
unset AI_ENV_PASTE_STDIN

# as_writer: how a printed recovery command that writes (an access key, a connector) starts on this Mac, where a bare
# `aws` has no credentials: under the account root's runner (the bootstrap, operator-keys, break-glass: its terminal
# holds the root's own credentials, and the deployer may have no key yet) `ai-env as root -- `, else
# `ai-env as deployer -- `, who writes them in every other run.
as_writer() {
    case "${AI_ENV_BRIDGE_AS:-}" in
    root) printf 'ai-env as root -- ' ;;
    *) printf 'ai-env as deployer -- ' ;;
    esac
}

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
                echo "    $(as_writer)aws lambda-core delete-network-connector --region $region --endpoint-url $lambda_url --identifier $n"
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
        echo "terminate them first, each with the runtime key's Touch ID (--yes for a VM this Mac has no row of): ai-env vm terminate <id>"
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
    # Pasted into zsh (no INTERACTIVE_COMMENTS by default: a `#` is an argument, an unquoted `(` syntax), so no command
    # line carries a comment or anything unquoted beyond its words: what it should show is on its step's numbered line.
    cat <<EOF
Post-destroy checklist (read-only checks, region $region), in this terminal (the account root's own credentials: the
operator users are gone): paste each command line on its own; its step's numbered line says what it should show.
  1. no image $name (deleting an image should remove its versions and snapshots: record it):
     aws lambda-microvms list-microvm-images --region $region
  2. nothing of $name but TERMINATED:
     aws lambda-microvms list-microvms --region $region
  3. no log group of the image:
     aws logs describe-log-groups --log-group-name-prefix /aws/lambda-microvms --region $region
     aws logs describe-log-groups --log-group-name-prefix /aws/lambda/microvms --region $region
  4. NoSuchEntity for each of the three users (forceDestroy removed their access keys):
     aws iam get-user --user-name ai-env-runtime --region $region
     aws iam get-user --user-name ai-env-deployer --region $region
     aws iam get-user --user-name ai-env-ops --region $region
     then delete the sealed keys, now useless:
     rm "\${AI_ENV_BRIDGE_DIR:-\$HOME/.config/ai-env/bridge}/credentials/aws.env" "\${AI_ENV_BRIDGE_DIR:-\$HOME/.config/ai-env/bridge}/credentials/ops.env"
     and delete the Strongbox entry ai-env-deployer: its key went with the user
  5. NoSuchEntity for both roles, and no ai-env-* policy left (ai-env-deploy, ai-env-deploy-egress, ai-env-deploy-dns, ai-env-deployer, ai-env-ops):
     aws iam get-role --role-name ai-env-image-build --region $region; aws iam get-role --role-name ai-env-vm-exec --region $region
     aws iam list-policies --scope Local --query "Policies[?starts_with(PolicyName, 'ai-env-')].PolicyName" --output text --region $region
  6. no ai-env-artifacts-* bucket:
     aws s3api list-buckets --query "Buckets[?starts_with(Name, 'ai-env-artifacts-')].Name" --region $region
  7. no budget ai-env-monthly:
     aws budgets describe-budgets --account-id "\$(aws sts get-caller-identity --query Account --output text --region $region)" --region $region
  8. no $connector, no $connector-probe-* connector:
     aws lambda-core list-network-connectors --region $region --endpoint-url $lambda_url
  9. no egress VPC (its subnets, route tables, IGW and security groups go with it), and the VM subnet's network ACL gone:
     aws ec2 describe-vpcs --filters Name=cidr,Values=$vpc Name=tag:Project,Values=ai-env --region $region --endpoint-url $ec2_url
     aws ec2 describe-network-acls --filters Name=tag:Name,Values=ai-env-egress-vms --region $region --endpoint-url $ec2_url
 10. the proxy instance, terminated only:
     aws ec2 describe-instances --filters Name=tag:Name,Values=ai-env-egress-proxy --query 'Reservations[].Instances[].[InstanceId,State.Name]' --output text --region $region --endpoint-url $ec2_url
 11. all four parameters listed as invalid (none exists), and no $log_group (nor ${log_group%/*}/dns):
     aws ssm get-parameters --names $prefix/squid.conf $prefix/allow $prefix/extras $prefix/suspended --query InvalidParameters --region $region --endpoint-url https://ssm.$region.amazonaws.com
     aws logs describe-log-groups --log-group-name-prefix ${log_group%/*} --region $region --endpoint-url https://logs.$region.amazonaws.com
 12. NoSuchEntity for each:
     aws iam get-role --role-name $(econf operatorRoleName) --region $region; aws iam get-role --role-name $(econf proxyRoleName) --region $region; aws iam get-instance-profile --instance-profile-name $(econf proxyInstanceProfileName) --region $region
 13. bridge.toml [aws]: clear image_arn, execution_role_arn and budget_name, and remove egress_connector_arn and proxy_private_ip, by hand; delete state/infra.toml (infra status refuses a stack without outputs, so nothing rewrites it)
     $(verified_note)
 14. optional, the stack's own record in the Pulumi backend:
     cd infra && pulumi stack rm $stack
 15. the account root ran this destroy (BREAKGLASS=1): when done, unset its key and close this terminal (README "Break-glass"); delete the key when nothing else uses it (IAM console as the root, with MFA: Security credentials, Access keys)
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

# The six variables a compile or a test must never see (D18): an operator key, the runner's marker and the stack's
# passphrase (A39).
NO_KEY_ENV=(env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN -u AI_ENV_BRIDGE_AS -u PULUMI_CONFIG_PASSPHRASE -u PULUMI_CONFIG_PASSPHRASE_FILE)

# need_ai_env: the ai-env command words of AI_ENV_CLI in the array ai_env, built first without any key, marker or
# passphrase in its environment (D18): `<ai-env> --version`, which with the make targets' default (cargo run) compiles
# the tree when it changed, so no later call compiles under the key `ai-env as` put in this process's environment
# (key-issue, post-deploy and connector-probe run under it), or the passphrase an unseal put there.
need_ai_env() {
    local st
    test -n "$ai_env_line" || { echo "ops.sh: AI_ENV_CLI is empty (the make target passes \$(AI_ENV))" >&2; exit 1; }
    set -f
    ai_env=($ai_env_line)
    set +f
    "${NO_KEY_ENV[@]}" "${ai_env[@]}" --version >/dev/null || {
        st=$?
        echo "ops.sh: $ai_env_line --version failed (exit $st, above): the operator CLI could not be built or run without a key" >&2
        exit 1
    }
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
# A progress line every PROBE_PROGRESS_S while the probe waits for its connector (minutes: 255 and 265 s live).
PROBE_PROGRESS_S=${PROBE_PROGRESS_S:-60}
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
            echo "  $(as_writer)aws lambda-core delete-network-connector --identifier $probe --region $region --endpoint-url $lambda_url" >&2
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
    local doc cfg role arn state t0 rc secs detail next
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
    echo "connector-probe: waiting for $probe to leave PENDING (polled every ${CONNECTOR_WAIT_POLL}s since the create, at most ${CONNECTOR_WAIT_TIMEOUT}s; a connector took 255-265 s on 2 Oct 2026)"
    # The poll writes its one line when it ends: until then a line every PROBE_PROGRESS_S (a silent wait of minutes
    # looked like a hang).
    next=$PROBE_PROGRESS_S
    while [ ! -s "$watch/state" ] && kill -0 "$poller" 2>/dev/null; do
        sleep 1
        secs=$(($(date +%s) - t0))
        if [ "$secs" -ge "$next" ]; then
            echo "connector-probe: still waiting after ${secs}s"
            next=$((secs + PROBE_PROGRESS_S))
        fi
    done
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
# --known-documents POLICY... (make deploy-policies, whose `pulumi up --target` updates those policies alone): each must
# be in the plan with its document known. The plan check accepts an unknown document while a resource it names is
# created or replaced (the proxy instance, for ai-env-ops'), and the whole deploy builds it from the new resource; a
# targeted up replaces nothing, renders the document anew from the old resource and would apply what no check compared.
cmd_plan_gate() {
    local plan mode acct rc=0 st docs what p unsure=0
    case "${1:-}" in
    "") ;;
    --known-documents)
        shift
        test $# -ge 1 || { echo "usage: ops.sh plan-gate [--known-documents POLICY...]" >&2; exit 2; }
        ;;
    *) echo "usage: ops.sh plan-gate [--known-documents POLICY...]" >&2; exit 2 ;;
    esac
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
    if [ $# -ge 1 ]; then
        docs=$(printf '%s' "$plan" | node -e '
const UNKNOWN = "04da6b54-80e4-46f7-96ec-b56ff0331ba9";
let plan;
try { plan = JSON.parse(require("fs").readFileSync(0, "utf-8")); } catch (e) { console.log(`unreadable\t${e.message}`); process.exit(0); }
const known = new Map();
for (const s of plan.steps || []) {
    const st = s.newState;
    if (!st || st.type !== "aws:iam/policy:Policy") continue;
    const v = (st.inputs || {}).policy;
    known.set(String(s.urn).split("::").pop(), typeof v === "string" && v !== "" && v !== UNKNOWN);
}
for (const name of process.argv.slice(1)) console.log(`${!known.has(name) ? "missing" : known.get(name) ? "known" : "unknown"}\t${name}`);
' "$@") || docs=$'unreadable\tnode failed'
        while IFS=$'\t' read -r what p; do
            case "$what" in
            known) ;;
            unknown) echo "deploy-policies: the plan holds the document of $p unknown (it names a resource the plan creates or replaces, such as the proxy instance): pulumi up --target would render it anew from the old resource and apply what no check compared: run make deploy, the whole plan, instead"; unsure=1 ;;
            missing) echo "deploy-policies: the plan holds no step of the policy $p, which pulumi up --target would update"; unsure=1 ;;
            *) echo "deploy-policies: the documents of the plan cannot be read (${p:-no answer}): refusing"; unsure=1 ;;
            esac
        done <<<"$docs"
        if [ "$unsure" = 0 ]; then echo "deploy-policies: the plan holds every document of $* known: the targeted pulumi up applies what the plan check compared"; else rc=1; fi
    fi
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
# ids and hashes the ai-env egress commands read from it, S9's transcript store included: a deploy that only changes
# the S3 endpoint's policy is lag, never drift; S10: the connector, which egress status judges by the ARN the file
# records, compared as egress status compares connectors (a final :N version dropped: the file holds the live read's
# ARN), and the names of the proxy documents, which every egress command holds to the ones it sends), space-separated;
# "-" when the file does not exist. Only keys whose lag egress status would call drift belong here: each one listed
# skips post-deploy's drift check until make infra-status WRITE=1.
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
    dnsMode: "dns_mode", parameterPrefix: "parameter_prefix", squidConfSha256: "squid_conf_sha256", allowSha256: "allow_sha256",
    transcriptsBucket: "transcripts_bucket", s3EndpointId: "s3_endpoint_id", s3EndpointPolicySha256: "s3_endpoint_policy_sha256",
    transcriptsBucketPolicySha256: "transcripts_bucket_policy_sha256", proxyRouteTableId: "proxy_route_table_id",
    connectorArn: "connector_arn", proxyReloadDocument: "proxy_reload_document", proxyStatusDocument: "proxy_status_document",
    proxyPatchDocument: "proxy_patch_document" };
// normalize_connector (src/bridge/egress/mod.rs): trimmed, a final all-digit segment after the resource name dropped.
const connector = (a) => { const p = a.trim().split(":"); return p.length >= 8 && /^[0-9]+$/.test(p[p.length - 1]) ? p.slice(0, -1).join(":") : a.trim(); };
const same = (k, a, b) => (k === "connectorArn" ? connector(a) === connector(b) : a === b);
console.log(Object.keys(keys).filter((k) => !same(k, String(out[k] ?? ""), rec[keys[k]] ?? "")).map((k) => keys[k]).join(" "));
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
# reload needs the same proxy instance and no proxy document the state names that the stack no longer exports (every
# egress command refuses such a state), the status every egress id and hash, the connector and the proxy documents'
# names (else a note says to run make infra-status WRITE=1 first). Exit 1 when the reload failed, the proxy's state
# could not be read, or status found drift.
cmd_post_deploy() {
    local after=0 reloaded=0 have_outputs=1 bridge infra_toml outputs lag named_docs k proxy doc st rc=0 vms pre="$out/pre-deploy-image.json" post="$out/post-deploy-image.json" a b s report drift
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
    # The proxy documents the state names but the stack no longer exports (a renamed document): every egress command
    # refuses such a state (exit 1), the reload included. A state that names none (from before the documents' outputs)
    # passes the CLI's check, so its reload runs; lag "-" (no state) never reaches the grep.
    named_docs=""
    for k in proxy_reload_document proxy_status_document proxy_patch_document; do
        if in_words "$k" "$lag" && grep -q "^$k = \"..*\"\$" "$infra_toml"; then named_docs="$named_docs $k"; fi
    done
    proxy=$(printf '%s' "$outputs" | jsq 'j.proxyInstanceId') || exit 1
    if [ -z "$proxy" ]; then
        echo "deploy: stack $stack exports no proxyInstanceId: egress reload skipped"
    elif [ "$lag" = - ] || in_words proxy_instance_id "$lag"; then
        echo "deploy: $infra_toml does not name the proxy instance $proxy yet (a new instance reads its parameters at boot): egress reload skipped; make infra-status WRITE=1, then make allowlist-reload if a parameter changed since the proxy booted (an earlier failed deploy counts)"
    elif [ -n "$named_docs" ]; then
        echo "deploy: $infra_toml names other proxy documents than this deploy's (${named_docs# }; every egress command refuses it): egress reload skipped; make infra-status WRITE=1, then make allowlist-reload"
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
            echo "deploy: THE DEPLOY FAILED AFTER pulumi up STARTED, AND THE PROXY WAS NOT RELOADED: it may still serve the pre-deploy parameters: make allowlist-reload (make infra-status WRITE=1 first when state/infra.toml does not name the proxy instance or names other proxy documents)"
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

# ---- S8 operators (plans/s8-operators-contracts.md §9) -----------------------------------------------------------------

# identity_say <exit> <text> <label>: ops.sh identity's one line (`LABEL: identity <text>`, `LABEL: <text>` for a
# BREAK-GLASS line, `<text>` without a label), then its exit.
identity_say() {
    if [ -z "$3" ]; then
        printf '%s\n' "$2"
    else
        case "$2" in
        BREAK-GLASS:*) printf '%s: %s\n' "$3" "$2" ;;
        *) printf '%s: identity %s\n' "$3" "$2" ;;
        esac
    fi
    exit "$1"
}

# identity TIER [LABEL]: whether this process may run a TIER step: deployer (a deployer make target: the first line of
# its X-run, and P8), ops (an ops step), root-keys (make operator-keys) or breakglass (make destroy: the account root
# alone, with BREAKGLASS=1; its X-run typed under the deployer's runner must not reach pulumi destroy, which as the
# deployer would delete the operator users and its own rights half-way). One line on stdout, exit 0 (admitted) or 1
# (refused); 2 for an unknown TIER. The caller is what `aws sts get-caller-identity` answers in this environment (under
# ai-env as, the runner's key alone); its account, the ARN's fifth field, is compared, never printed. The stack's facts
# come from its outputs (accountId, deployerUserName, opsUserName: a local read, no passphrase). The account root is
# admitted only under the marker AI_ENV_BRIDGE_AS=root (ai-env as root, which infra.mk's TIER runs for the bootstrap
# and for BREAKGLASS=1), and in the deployer tier, once the stack exports its deployer, only with BREAKGLASS=1 (set
# by infra.mk's IDENTITY from the make command line alone). What it calls says nothing: its one line is all (P8's row).
cmd_identity() {
    local tier=${1:-} label=${2:-} marker=${AI_ENV_BRIDGE_AS:-} arn who acct outputs facts stack_acct stack_deployer stack_ops
    local glass="BREAK-GLASS: root, with BREAKGLASS=1 on the make command line: no deploy policy applies; afterwards unset root's key and close this terminal (README \"Break-glass\")"
    local glass_only="break-glass only: BREAKGLASS=1 on the make command line (make destroy deletes the operator users themselves; README \"Break-glass\")"
    case "$tier" in
    deployer | ops | root-keys | breakglass) ;;
    *)
        echo "usage: ops.sh identity deployer|ops|root-keys|breakglass [LABEL]" >&2
        exit 2
        ;;
    esac
    if [ -n "${AWS_ACCESS_KEY_ID:-}" ] && [ -n "${AWS_PROFILE:-}${AWS_DEFAULT_PROFILE:-}" ]; then
        identity_say 1 "AWS_ACCESS_KEY_ID and AWS_PROFILE are both set: the aws CLI takes the key, Pulumi's providers may take the profile: unset AWS_PROFILE" "$label"
    fi
    if ! arn=$(aws sts get-caller-identity --region "$region" --query Arn --output text 2>/dev/null) || [ -z "$arn" ]; then
        identity_say 1 "none: no AWS credentials answer: make deploy asks for the deployer's key; P8 alone: ai-env as deployer -- make s3-preflight PHASE=b" "$label"
    fi
    who=${arn##*:}
    acct=$(printf '%s' "$arn" | cut -d: -f5)
    if ! outputs=$(stack_outputs 2>/dev/null) \
        || ! facts=$(printf '%s' "$outputs" | jsq '[j.accountId, j.deployerUserName, j.opsUserName].map((v) => (v === undefined || v === null ? "" : String(v)))' 2>/dev/null); then
        identity_say 1 "$who: the outputs of stack $stack cannot be read (pulumi stack output --stack $stack): whether it has a deployer, and its account, are unknown: refused" "$label"
    fi
    stack_acct=$(sed -n 1p <<<"$facts")
    stack_deployer=$(sed -n 2p <<<"$facts")
    stack_ops=$(sed -n 3p <<<"$facts")
    if [ -n "$stack_acct" ] && [ "$stack_acct" != "$acct" ]; then
        identity_say 1 "$who of another AWS account than stack $stack's (its accountId output): make deploy asks for the deployer's key of the stack's account" "$label"
    fi
    if [ "$marker" = root ] && [ "$who" != root ]; then
        identity_say 1 "$who: under ai-env as root, but not the account root: refused" "$label"
    fi
    case "$tier:$who" in
    deployer:user/ai-env-deployer) identity_say 0 "user/ai-env-deployer (the deployer of stack $stack)" "$label" ;;
    deployer:root | root-keys:root | breakglass:root)
        if [ "$marker" != root ]; then
            identity_say 1 "root: not under ai-env as root (make decides it: the bootstrap, or BREAKGLASS=1 on the make command line): refused" "$label"
        fi
        if [ "$tier" = breakglass ]; then
            # Whatever the stack exports: a stack without its operators (older, or a bootstrap half done) is the root's
            # to destroy too.
            if [ "${BREAKGLASS:-}" = 1 ]; then identity_say 0 "$glass" "$label"; fi
            identity_say 1 "root: $glass_only" "$label"
        fi
        if [ "$tier" = root-keys ]; then
            if [ -n "$stack_deployer" ] && [ -n "$stack_ops" ]; then
                identity_say 0 "root of stack $stack's account, which exports user/ai-env-deployer and user/ai-env-ops: the bootstrap keys" "$label"
            fi
            identity_say 1 "root: stack $stack exports no user/ai-env-deployer yet: run the bootstrap deploy first (make deploy, as the account root)" "$label"
        fi
        if [ -z "$stack_deployer" ]; then
            identity_say 0 "root: the bootstrap deploy (stack $stack exports no deployer yet: this deploy creates user/ai-env-deployer and user/ai-env-ops; then make operator-keys, as the account root, once)" "$label"
        fi
        if [ "${BREAKGLASS:-}" = 1 ]; then
            identity_say 0 "$glass" "$label"
        fi
        identity_say 1 "root: stack $stack has its deployer (user/ai-env-deployer): make deploy asks for that user's key (Strongbox); the account root only with BREAKGLASS=1 on the make command line" "$label"
        ;;
    deployer:user/ai-env-ops) identity_say 1 "user/ai-env-ops: the ops key cannot deploy: run the make target itself (not its -run target): it asks for the deployer's key" "$label" ;;
    deployer:user/ai-env-runtime) identity_say 1 "user/ai-env-runtime: the runtime key cannot deploy: make deploy asks for the deployer's key" "$label" ;;
    deployer:*) identity_say 1 "$who: not the deployer of stack $stack (user/ai-env-deployer): make deploy asks for that user's key and never uses this shell's own AWS settings (AWS_PROFILE, ~/.aws)" "$label" ;;
    ops:user/ai-env-ops) identity_say 0 "user/ai-env-ops (the operator of stack $stack)" "$label" ;;
    ops:user/ai-env-deployer) identity_say 0 "user/ai-env-deployer (the deployer of stack $stack, which covers ops)" "$label" ;;
    ops:root) identity_say 1 "root: an ops step runs as ai-env-ops or the deployer, never the account root (break-glass: make deploy BREAKGLASS=1, then the remaining steps by hand)" "$label" ;;
    ops:*) identity_say 1 "$who: not ai-env-ops or the deployer of stack $stack" "$label" ;;
    root-keys:*) identity_say 1 "$who: make operator-keys is the account root's, once, after the bootstrap deploy; the deployer rotates: make ops-key ROTATE=1, make deployer-key ROTATE=1" "$label" ;;
    breakglass:*) identity_say 1 "$who: break-glass only: the account root's, with BREAKGLASS=1 on the make command line (make destroy deletes the operator users themselves; README \"Break-glass\")" "$label" ;;
    esac
}

# stack-deployer: the stack's deployerUserName output and a newline, or nothing before the bootstrap deploy (the outputs
# hold none); exit 0. Outputs that cannot be read: stack_outputs's line, exit 1 (infra.mk's TIER keeps the deployer
# then: an unreadable stack is never taken for one without a deployer). A local read; no passphrase.
cmd_stack_deployer() {
    local outputs d
    outputs=$(stack_outputs) || exit 1
    d=$(printf '%s' "$outputs" | jsq 'j.deployerUserName') || exit 1
    if [ -n "$d" ]; then printf '%s\n' "$d"; fi
}

key_issue_usage() {
    echo "usage: ops.sh key-issue LABEL ai-env-runtime|ai-env-ops sealed [first] | key-issue LABEL ai-env-deployer handover [first]" >&2
    exit 2
}

# key_issue_undo: the delete command of the new key (the verified id, else every new one IAM lists), and the sealed
# container aws-set kept before a rotation (cmd_key_issue's locals: sid, new, old, user, bak, sealed, w).
key_issue_undo() {
    local k
    for k in $([ -n "$sid" ] && echo "$sid" || echo "$new"); do echo "  ${w}aws iam delete-access-key --user-name $user --access-key-id $k --region $region"; done
    test -n "$sid$new" || echo "  ${w}aws iam delete-access-key --user-name $user --access-key-id <the id not in (${old:-none})> --region $region"
    if [ -n "$bak" ]; then echo "  mv \"$bak\" \"$sealed\""; fi
}

# key-issue LABEL USER MODE [first] (D23: no access key ever enters Pulumi, whose state would hold its secret): a new
# access key of USER, delivered and verified, its secret crossing exactly one pipe, from create-access-key into the
# CLI that takes it (zeroized memory); this script never holds it. MODE sealed (ai-env-runtime into
# credentials/aws.env, ai-env-ops into credentials/ops.env): `ai-env creds aws-set --user USER`, then `ai-env creds
# aws-verify --user USER` (one Touch ID; it retries sts while IAM propagates); handover (ai-env-deployer): `ai-env creds
# deployer-key --account <the stack's>`, which puts the id, then the secret, on the clipboard (this Mac only,
# concealed) for the Strongbox entry, takes them pasted back and checks the key with sts. Both print `id <the full id>`
# and `arn <the ARN sts answered>` lines on stdout, which this captures. Whether a key was created is read from IAM
# afterwards, never from an exit status (the key exists even when the CLI fails writing into a sealer that already
# exited): a failure names the delete command of every new id. first (make operator-keys): only a user without a key
# gets one, so a rerun resumes; never a rotation. ROTATE=1 issues and verifies a new key, then deletes the old one last
# (under ai-env as deployer, deployer-key ROTATE=1 deletes the running key itself as its last call); when the new key
# does not verify, the undo deletes it and restores the container aws-set kept as <file>.<unix seconds>.bak (sealed),
# or says to put the Strongbox entry's previous values back (handover). LABEL is the make target, each line's prefix.
# Every `aws iam` line it prints for Mike to run starts with the runner of the identity that runs it here (as_writer:
# the deployer's, or the account root's in its own terminal): a bare `aws` has no credentials on this Mac.
# Env: ROTATE (1 or empty: the make command line's), AI_ENV_CLI (the make target's $(AI_ENV)).
cmd_key_issue() {
    local label=${1:-} user=${2:-} mode=${3:-} first=${4:-} rotate=${ROTATE:-} sealed="" acct="" outputs kept nowhere tool failed route
    local old n t0 out="" cst dst lst now new k bak f ts rc sid arn key extra undelivered verdict w
    w=$(as_writer)
    test $# -le 4 || key_issue_usage
    case "$mode:$user" in
    sealed:ai-env-runtime) sealed="${AI_ENV_BRIDGE_DIR:-$HOME/.config/ai-env/bridge}/credentials/aws.env" ;;
    sealed:ai-env-ops) sealed="${AI_ENV_BRIDGE_DIR:-$HOME/.config/ai-env/bridge}/credentials/ops.env" ;;
    handover:ai-env-deployer) ;;
    *) key_issue_usage ;;
    esac
    case "$first" in "" | first) ;; *) key_issue_usage ;; esac
    case "$label" in "" | *[!a-z0-9-]*) key_issue_usage ;; esac
    need_ai_env
    if [ -n "$first" ]; then rotate=""; fi
    if [ "$mode" = sealed ]; then
        kept="sealed" nowhere="sealed nowhere" tool="aws-set" failed="sealing failed"
    else
        kept="in Strongbox" nowhere="held nowhere" tool="deployer-key" failed="the hand-over failed"
    fi
    # The recipe's rules from here on: every status is read, nothing stops on its own.
    set +e
    old=$(aws iam list-access-keys --user-name "$user" --region "$region" --query 'AccessKeyMetadata[].AccessKeyId' --output text) || exit 1
    old=${old/None/}
    n=$(wc -w <<<"$old" | tr -d ' ')
    if [ -n "$first" ] && [ "$n" -ge 1 ]; then
        echo "$label: $user has its key already: skipped (a rerun resumes)"
        exit 0
    fi
    if [ "$n" -ge 2 ]; then
        echo "$label: $user has 2 access keys (the IAM maximum); delete the one that is not $kept first:"
        echo "  ${w}aws iam list-access-keys --user-name $user --region $region"
        echo "  ${w}aws iam delete-access-key --user-name $user --access-key-id <id> --region $region"
        exit 1
    fi
    if [ "$n" -eq 1 ] && [ "$rotate" != 1 ]; then
        if [ "$mode" = sealed ]; then
            echo "$label: $user already has a key ($old); ROTATE=1 seals a new one, then deletes it"
        else
            echo "$label: $user already has a key ($old); ROTATE=1 hands a new one over, then deletes it"
        fi
        exit 1
    fi
    if [ "$n" -eq 0 ] && [ "$rotate" = 1 ]; then
        if [ "$mode" = handover ]; then route="make operator-keys (as the account root)"; else route="make $label"; fi
        echo "$label: ROTATE=1, but $user has no key: $route"; exit 1; fi
    if [ "$mode" = handover ]; then
        # creds deployer-key checks the pasted-back key against the stack's account: never this caller's (D10).
        outputs=$(stack_outputs) && acct=$(printf '%s' "$outputs" | jsq 'j.accountId') || acct=""
        case "$acct" in
        [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;;
        *)
            echo "$label: the outputs of stack $stack name no accountId: the hand-over needs the stack's account: nothing created"
            exit 1
            ;;
        esac
    fi
    t0=$(date +%s)
    if [ "$mode" = sealed ]; then
        aws iam create-access-key --user-name "$user" --output json --region "$region" | "${ai_env[@]}" creds aws-set --user "$user"
        st=("${PIPESTATUS[@]}")
        cst=${st[0]} dst=${st[1]}
        undelivered=$([ "$dst" -ne 0 ] && echo 1)
    else
        out=$(aws iam create-access-key --user-name "$user" --output json --region "$region" | "${ai_env[@]}" creds deployer-key --account "$acct"
            printf 'status %s %s\n' "${PIPESTATUS[0]}" "${PIPESTATUS[1]}")
        cst=$(sed -n 's/^status \([0-9]*\) [0-9]*$/\1/p' <<<"$out" | tail -1)
        dst=$(sed -n 's/^status [0-9]* \([0-9]*\)$/\1/p' <<<"$out" | tail -1)
        cst=${cst:-1} dst=${dst:-1}
        # The hand-over took the key once it printed its id: from there its exit is the verdict's, below.
        sid=$(sed -n 's/^id //p' <<<"$out" | head -1)
        undelivered=$([ -z "$sid" ] && echo 1)
    fi
    now=$(aws iam list-access-keys --user-name "$user" --region "$region" --query 'AccessKeyMetadata[].AccessKeyId' --output text)
    lst=$?
    if [ "$lst" -ne 0 ]; then
        if [ -n "$undelivered" ]; then
            echo "$label: $failed (create-access-key exit $cst, $tool exit $dst) and the keys of $user cannot be listed (exit $lst): delete any key not in (${old:-none}):"
            echo "  ${w}aws iam list-access-keys --user-name $user --region $region"
            exit 1
        fi
        if [ "$mode" = sealed ]; then
            echo "$label: warning: cannot list the keys of $user after sealing (exit $lst); verifying the sealed key anyway"
        else
            echo "$label: warning: cannot list the keys of $user after the hand-over (exit $lst); judging the handed-over key anyway"
        fi
        now=""
    fi
    new=""
    for k in ${now/None/}; do case " $old " in *" $k "*) ;; *) new="${new:+$new }$k" ;; esac; done
    if [ -n "$undelivered" ]; then
        if [ -n "$new" ]; then
            echo "$label: $failed (create-access-key exit $cst, $tool exit $dst): the new key(s) $new are $nowhere. Delete them:"
            for k in $new; do echo "  ${w}aws iam delete-access-key --user-name $user --access-key-id $k --region $region"; done
        elif [ "$cst" -ne 0 ]; then
            echo "$label: create-access-key failed (exit $cst) and IAM lists no new key of $user: none was created"
        else
            echo "$label: $failed ($tool exit $dst), and IAM does not list the new key yet: delete any key of $user not in (${old:-none}):"
            echo "  ${w}aws iam list-access-keys --user-name $user --region $region"
        fi
        exit 1
    fi
    bak=""
    if [ "$mode" = sealed ] && [ "$rotate" = 1 ]; then
        for f in "$sealed".*.bak; do
            ts=${f##*.env.}
            ts=${ts%.bak}
            case "$ts" in '' | *[!0-9]*) continue ;; esac
            if [ "$ts" -ge "$t0" ]; then bak=$f; fi
        done
    fi
    if [ "$mode" = sealed ]; then
        out=$("${ai_env[@]}" creds aws-verify --user "$user")
        rc=$?
    else
        rc=$dst
    fi
    sid=$(sed -n 's/^id //p' <<<"$out" | head -1)
    arn=$(sed -n 's/^arn //p' <<<"$out" | head -1)
    key=${sid:-${new:-(not listed yet)}}
    case "$sid:$new" in :*" "*) key="one of ($new)" ;; esac
    if [ "$mode" = sealed ] && [ -n "$sid" ]; then
        case " $old " in *" $sid "*)
            echo "$label: the container ai-env creds aws-verify verified ($sealed) still holds the previous key $sid: aws-set sealed the new key somewhere else. Nothing deleted; check AI_ENV_BRIDGE_DIR, then delete the key not in (${old:-none}) by hand:"
            echo "  ${w}aws iam list-access-keys --user-name $user --region $region"
            exit 1
            ;;
        esac
    fi
    extra=""
    if [ -n "$sid" ]; then for k in $new; do test "$k" = "$sid" || extra="${extra:+$extra }$k"; done; fi
    if [ -n "$extra" ]; then
        if [ "$mode" = sealed ]; then
            echo "$label: IAM lists new key(s) sealed nowhere besides the sealed $sid (a retried create-access-key). Delete them:"
        else
            echo "$label: IAM lists new key(s) held nowhere besides the handed-over $sid (a retried create-access-key). Delete them:"
        fi
        for k in $extra; do echo "  ${w}aws iam delete-access-key --user-name $user --access-key-id $k --region $region"; done
    fi
    # The verdict: the user's own key; a key that answered as another principal or never answered (the CLI's verdict:
    # exit 9; aws-verify's exit 5 after its id line without an arn line; deployer-key's 42); or the CLI's own failure.
    verdict=failed
    case "$rc:$arn" in
    0:*:user/"$user") verdict=identified ;;
    0:* | 9:*) verdict=unverified ;;
    5:)
        if [ "$mode" = sealed ] && [ -n "$sid" ]; then verdict=unverified; fi
        ;;
    42:*)
        if [ "$mode" = handover ]; then verdict=unverified; fi
        ;;
    esac
    case "$verdict:$mode" in
    identified:sealed) echo "$label: the sealed key ...${key: -4} identifies as user/$user" ;;
    identified:handover) echo "$label: the key ...${key: -4} is in Strongbox and identifies as user/$user" ;;
    unverified:*)
        if [ -n "$bak" ]; then
            echo "$label: the sealed key $key does not identify as user/$user. $sealed now holds it; the previous key $old is still active and sealed in $bak. If it never verifies, undo the rotation:"
        elif [ "$mode" = sealed ]; then
            echo "$label: the sealed key $key does not identify as user/$user; the previous key (${old:-none}) is kept. If it never verifies, delete the new one:"
        else
            echo "$label: the key $key does not identify as user/$user; the previous key (${old:-none}) is kept. If it never verifies, delete the new one and put the previous values back in the Strongbox entry (its history keeps them):"
        fi
        key_issue_undo
        exit 1
        ;;
    failed:sealed)
        echo "$label: ai-env creds aws-verify failed (exit $rc): the sealed key $key is NOT verified and nothing was deleted. Verify it with:"
        echo "  ai-env creds aws-verify --user $user"
        if [ "$rotate" = 1 ]; then
            echo "If it identifies as user/$user, finish the rotation:"
            echo "  ${w}aws iam delete-access-key --user-name $user --access-key-id $old --region $region"
            echo "If it never does, undo the rotation:"
            key_issue_undo
        fi
        exit 1
        ;;
    failed:handover)
        echo "$label: ai-env creds deployer-key failed (exit $rc): the new key $key is held nowhere you can rely on; delete it:"
        key_issue_undo
        exit 1
        ;;
    esac
    if [ "$rotate" = 1 ]; then
        aws iam delete-access-key --user-name "$user" --access-key-id "$old" --region "$region" || exit 1
        echo "$label: rotated; deleted the old key $old"
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
plan-gate) cmd_plan_gate "$@" ;;
replace-guard) cmd_replace_guard ;;
plan-errors) cmd_plan_errors ;;
post-deploy) cmd_post_deploy "$@" ;;
identity) cmd_identity "$@" ;;
stack-deployer) cmd_stack_deployer ;;
key-issue) cmd_key_issue "$@" ;;
*) echo "usage: ops.sh snapshot <prefix> | wait | status | versions | builds [VERSION] | set-status ACTIVE|INACTIVE VERSION | prune KEEP [1] | vm-guard | delete-image | checklist | connector-wait | connector-status | connector-probe | connector-delete | plan-gate [--known-documents POLICY...] | replace-guard | plan-errors | post-deploy [--after-failure] | identity deployer|ops|root-keys|breakglass [LABEL] | stack-deployer | key-issue LABEL USER sealed|handover [first] (the plan on stdin for plan-gate, replace-guard, plan-errors)" >&2; exit 2 ;;
esac
