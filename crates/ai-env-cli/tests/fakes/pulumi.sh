#!/bin/sh
# Fake `pulumi` for the recipe tests (tests/infra/image.rs: deploy's plan gate,
# ops.sh post-deploy and connector-status, s3-preflight P6/P7): never touches a
# backend or AWS. Copied into a temp bin dir as `pulumi`. --show-secrets and
# --yes are refused everywhere (exit 3, logged as FORBIDDEN): the Makefile and
# ops.sh never pass them (D17).
#   pulumi preview ...          prints the file FAKE_PULUMI_PREVIEW (a plan the
#                               test wrote) and exits FAKE_PULUMI_PREVIEW_RC
#                               (default 0); unset: refused
#   pulumi stack output ...     prints the file FAKE_PULUMI_OUTPUTS; unset: refused
#   pulumi stack ls --json      [{"name": FAKE_PULUMI_STACK (default dev)}]
#   pulumi whoami -v            a fake backend URL
#   pulumi plugin ls --json     the two pinned resource plugins (aws 7.10.0,
#                               aws-native 1.79.0)
#   pulumi up ...               refused unless FAKE_PULUMI_ALLOW lists "up"; then
#                               runs the script FAKE_PULUMI_ON_UP when set (the
#                               test's stand-in for what the update changes) and
#                               exits FAKE_PULUMI_UP_RC (default 0)
#   anything else               (destroy, refresh, state, config, login, ...)
#                               refused (exit 1) unless FAKE_PULUMI_ALLOW lists
#                               its first word; then exit 0
# Environment:
#   FAKE_PULUMI_LOG   when set, each call is appended here as "pulumi <argv>"
set -u
if [ -n "${FAKE_PULUMI_LOG:-}" ]; then
  printf 'pulumi %s\n' "$*" >> "$FAKE_PULUMI_LOG"
fi
for a in "$@"; do
  case "$a" in
    --show-secrets|--yes|-y)
      if [ -n "${FAKE_PULUMI_LOG:-}" ]; then
        printf 'pulumi FORBIDDEN %s\n' "$a" >> "$FAKE_PULUMI_LOG"
      fi
      echo "fake pulumi: $a is never passed (D17)" >&2
      exit 3 ;;
  esac
done
allowed() {
  case " ${FAKE_PULUMI_ALLOW:-} " in
    *" $1 "*) return 0 ;;
  esac
  return 1
}
case "${1:-} ${2:-}" in
  "preview "*)
    test -n "${FAKE_PULUMI_PREVIEW:-}" || { echo "fake pulumi: preview refused (FAKE_PULUMI_PREVIEW is not set)" >&2; exit 1; }
    cat "$FAKE_PULUMI_PREVIEW"
    exit "${FAKE_PULUMI_PREVIEW_RC:-0}" ;;
  "stack output")
    test -n "${FAKE_PULUMI_OUTPUTS:-}" || { echo "fake pulumi: stack output refused (FAKE_PULUMI_OUTPUTS is not set)" >&2; exit 1; }
    cat "$FAKE_PULUMI_OUTPUTS" ;;
  "stack ls")
    printf '[\n    {\n        "name": "%s",\n        "current": false\n    }\n]\n' "${FAKE_PULUMI_STACK:-dev}" ;;
  "whoami -v")
    printf 'User: fake\nBackend URL: file://fake-backend\n' ;;
  "plugin ls")
    printf '[{"name": "aws", "kind": "resource", "version": "7.10.0"}, {"name": "aws-native", "kind": "resource", "version": "1.79.0"}]\n' ;;
  "up "*)
    allowed up || { echo "fake pulumi: up refused (FAKE_PULUMI_ALLOW does not list it)" >&2; exit 1; }
    echo "fake pulumi: up"
    if [ -n "${FAKE_PULUMI_ON_UP:-}" ]; then
      sh "$FAKE_PULUMI_ON_UP" || exit 1
    fi
    exit "${FAKE_PULUMI_UP_RC:-0}" ;;
  *)
    allowed "${1:-}" || { echo "fake pulumi: ${1:-} refused (FAKE_PULUMI_ALLOW does not list it)" >&2; exit 1; }
    echo "fake pulumi: $*" ;;
esac
