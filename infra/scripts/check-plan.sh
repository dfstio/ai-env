#!/usr/bin/env bash
# The plan check (scripts/check-plan.ts), the final word on the stack's plan: run by `make preview-scratch` over the
# scratch preview and by `make deploy` over the real stack's preview before `pulumi up`.
#
#   pulumi preview --json --show-sames --show-reads --stack <stack> \
#       | infra/scripts/check-plan.sh --mode none|firewall --account-id <12 digits> [--egress-config F] [--image-config F]
#
# --account-id is the caller's (`aws sts get-caller-identity --query Account`): the IAM documents are compared with
# the policies.ts functions' output for it. Pass it as an argument only; never write it to a file.
#
# --show-sames is required on an existing stack: its unchanged resources are in the plan only with it, and the plan
# check counts the whole inventory (without it, it fails closed: "missing from the plan").
#
# Compiles check-plan.ts alone (it and the modules it imports are Pulumi-free, like print-policies.ts) into
# $PLAN_CHECK_OUT (default <repo>/target/infra-plan), then node reads the plan from stdin. The config files default
# to this infra/'s; a later --egress-config or --image-config wins (the scratch preview passes its copy's). The plan
# carries the account id: it is never written to a file here. Exit: 0 ok, 1 the plan does not match, 2 usage.
set -euo pipefail

infra=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
out=${PLAN_CHECK_OUT:-$(dirname "$infra")/target/infra-plan}

test -x "$infra/node_modules/.bin/tsc" || { echo "check-plan: $infra/node_modules missing: make infra-install" >&2; exit 2; }
rm -rf "${out:?}"
(cd "$infra" && node_modules/.bin/tsc --strict --target es2022 --module commonjs --moduleResolution node --types node \
    --rootDir . --outDir "$out" scripts/check-plan.ts) || { echo "check-plan: compiling scripts/check-plan.ts failed" >&2; exit 2; }
exec node "$out/scripts/check-plan.js" --egress-config "$infra/egress-config.json" --image-config "$infra/image-config.json" "$@"
