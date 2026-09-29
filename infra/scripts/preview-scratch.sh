#!/usr/bin/env bash
# make preview-scratch [NEGATIVE=no-logging|no-logging-cast|region]: a full `pulumi preview` of a scratch COPY of
# infra/ against the real account, with a throwaway backend, passphrase and stack (D17; T3.2, T3.5).
#
# Why a copy: the agent must never touch Mike's backend, the dev stack or its passphrase, and the negatives edit
# the program. Everything lives under target/image/pulumi-scratch (rebuilt on every run); node_modules is
# symlinked, PULUMI_HOME is private to the scratch dir, and its plugins directory is a real one holding symlinks
# to exactly the two pinned provider plugins (so nothing, not even a .lastused stamp or a plugin install, reaches
# the real ~/.pulumi). A preview creates nothing in AWS (it only reads the caller identity). Nothing is written to
# a log file: the preview's outputs carry the account id, so they go to the terminal only.
#
# The normal run must succeed and list the expected creates: 16 in total, among them the Budget and the
# MicrovmImage. Each negative succeeds only when its expected failure happens, and prints the diagnostic that fired:
#   no-logging       the `logging` input removed: the typecheck must fail naming it
#   no-logging-cast  removed behind an `as any` cast: the typecheck passes and the SDK's generated constructor
#                    refuses it; then the SDK guard is bypassed too (a raw CustomResource of the same type) and the
#                    provider's Check must refuse it
#   region           aws-native:region eu-west-3 in the scratch stack: the program must throw the pin message
#
# Env (set by infra/infra.mk): AI_ENV_REPO_ROOT, REGION, IMAGE_JSON (absolute), SCRATCH, NEGATIVE.
set -euo pipefail

root=${AI_ENV_REPO_ROOT:?}
: "${REGION:?}"
scratch=${SCRATCH:?}
negative=${NEGATIVE:-}
real_image_json=${IMAGE_JSON:?}

case "$negative" in "" | no-logging | no-logging-cast | region) ;; *) echo "preview-scratch: unknown NEGATIVE=$negative (no-logging, no-logging-cast, region)" >&2; exit 2 ;; esac
test -d "$root/infra/node_modules" || { echo "preview-scratch: $root/infra/node_modules missing: make infra-install" >&2; exit 1; }
command -v pulumi >/dev/null || { echo "preview-scratch: pulumi not on PATH" >&2; exit 1; }

fail() { echo "preview-scratch${negative:+ NEGATIVE=$negative}: $*" >&2; exit 1; }

# ---- the scratch copy ----
rm -rf "$scratch"
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

# edit <sed expression>...: apply to image.ts (the scratch copy) through its scratch:* markers.
edit() {
    local args=() e
    for e in "$@"; do args+=(-e "$e"); done
    sed -i.orig "${args[@]}" image.ts && rm image.ts.orig
}
preview() { pulumi preview --non-interactive --diff --color never --stack scratch "$@"; }

case "$negative" in
"")
    # Captured (terminal only, never a file) so the creates can be checked; printed in full either way.
    out=$(preview 2>&1) || { echo "$out"; fail "the preview failed"; }
    echo "$out"
    for t in 'aws:budgets/budget:Budget' 'aws-native:lambda:MicrovmImage'; do
        grep -qE "^ *\+ $t: \(create\)" <<<"$out" || fail "the preview lists no create of $t"
    done
    creates=$(sed -n 's/^ *+ \([0-9][0-9]*\) to create$/\1/p' <<<"$out")
    test "$creates" = 16 || fail "the preview plans ${creates:-no} creates, expected 16"
    echo "preview-scratch: ok (16 creates, among them the Budget and the MicrovmImage)"
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
esac
