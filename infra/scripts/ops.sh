#!/usr/bin/env bash
# The part-B image lifecycle helpers behind infra/infra.mk (plans/s3-plan.md D26, D29): snapshots around a deploy,
# waiting for the build, versions and builds, rollback, pruning, the VM guard and the post-destroy checklist.
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
# VERSIONS_WARN, VERSIONS_QUOTA.
set -euo pipefail

region=${REGION:?}
name=${IMAGE_NAME:?IMAGE_NAME is empty: no imageName in infra/image-config.json}
out=${IMAGE_OUT:?}
stack=${STACK:-dev}

# image_arn: called as `arn=$(image_arn) || exit 1` (the exit below only leaves the substitution's subshell).
image_arn() {
    local acct
    acct=$(aws sts get-caller-identity --region "$region" --query Account --output text) || { echo "ops.sh: sts get-caller-identity failed" >&2; exit 1; }
    case "$acct" in
    [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;;
    *) echo "ops.sh: sts get-caller-identity returned no 12-digit account id" >&2; exit 1 ;;
    esac
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

# vm-guard: refuse while any VM of the image is not TERMINATED (destroy, image-delete).
cmd_vm_guard() {
    local arn alive
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
}

cmd_checklist() {
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
  8. bridge.toml [aws]: clear image_arn, execution_role_arn and budget_name by hand, and delete state/infra.toml (infra status refuses a stack without outputs, so nothing rewrites it)
  9. optional: cd infra && pulumi stack rm $stack
EOF
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
*) echo "usage: ops.sh snapshot <prefix> | wait | status | versions | builds [VERSION] | set-status ACTIVE|INACTIVE VERSION | prune KEEP [1] | vm-guard | delete-image | checklist" >&2; exit 2 ;;
esac
