#!/usr/bin/env bash
# pass-exec.sh LABEL FILE CMD...: the guard right after the unseal of the stack's sealed passphrase (infra/infra.mk's
# TIER, plans/s8-operators-contracts.md A39). TIER runs `ai-env run -f FILE -- pass-exec.sh LABEL FILE CMD...` (one
# Touch ID), and CMD is the runner, `ai-env as T --` (the deployer's paste; the account root's asks for nothing), then
# X-run, or X-run under a runner that covers its tier. The README's first setup line seals PULUMI_CONFIG_PASSPHRASE with
# no value until `ai-env edit` sets one, and Pulumi takes an empty one for the passphrase, before any
# PULUMI_CONFIG_PASSPHRASE_FILE, and refuses it only once it runs (deploy's plan check comes after the paste): a FILE
# that leaves it empty, or sets neither it nor PULUMI_CONFIG_PASSPHRASE_FILE, stops here, exit 1, before CMD. Only
# whether each is set is read, never a value. bash 3.2.
set -euo pipefail

test $# -ge 3 || { echo "usage: pass-exec.sh LABEL FILE CMD..." >&2; exit 2; }
label=$1
file=$2
shift 2
if [ -z "${PULUMI_CONFIG_PASSPHRASE:+x}" ] && { [ -n "${PULUMI_CONFIG_PASSPHRASE+x}" ] || [ -z "${PULUMI_CONFIG_PASSPHRASE_FILE:+x}" ]; }; then
    echo "$label: the passphrase sealed in $file is empty, or not there (PULUMI_CONFIG_PASSPHRASE= has no value until ai-env edit sets one): set it with ai-env edit \"$file\" (README \"Identities\"), then make $label again: nothing ran against the stack" >&2
    exit 1
fi
exec "$@"
