#!/bin/sh
# Fake cargo-lambda for the vm-build wiring test (tests/infra/image.rs): no
# compiler. Copied into a temp bin dir; the Makefile gets it as CARGO_LAMBDA.
#   cargo-lambda lambda --version   "cargo-lambda 1.9.2 (fake)"
#   cargo-lambda lambda build ...   copies FAKE_CL_BOOTSTRAP to
#                                   <lambda dir>/<bin>/bootstrap, where the
#                                   lambda dir is --lambda-dir / -l when given,
#                                   else $CARGO_TARGET_DIR/lambda (else
#                                   target/lambda): cargo-lambda 1.9.2's rule
#                                   (the target directory of cargo metadata),
#                                   and <bin> --bin NAME / --bin=NAME, else
#                                   ai-env (S13: the relay's ai-env-relay)
#   A build first runs `cargo metadata` as cargo-lambda 1.9.2 does (cargo_metadata):
#   through $CARGO when it is set, which must then name a program, else cargo on
#   PATH; a CARGO that names none fails with the real error text.
# Environment:
#   FAKE_CL_LOG        when set, each call's argv is appended here, one line,
#                      with (S13) " [KEY]" when an operator key, the runner's
#                      marker or the stack's passphrase is in its environment
#                      (D18), then " [CARGO]" when CARGO is set (always last)
#   FAKE_CL_BOOTSTRAP  the "fresh build" to copy
set -u
if [ -n "${FAKE_CL_LOG:-}" ]; then
  cl_key=
  for cl_n in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AI_ENV_BRIDGE_AS PULUMI_CONFIG_PASSPHRASE PULUMI_CONFIG_PASSPHRASE_FILE; do
    eval "cl_set=\${$cl_n+x}"
    test -z "$cl_set" || cl_key=" [KEY]"
  done
  printf '%s%s%s\n' "$*" "$cl_key" "${CARGO+ [CARGO]}" >> "$FAKE_CL_LOG"
fi
test "${1:-}" = lambda || { echo "fake cargo-lambda: expected 'lambda'" >&2; exit 2; }
shift
case "${1:-}" in
  --version) echo "cargo-lambda 1.9.2 (fake)"; exit 0 ;;
  build) shift ;;
  *) echo "fake cargo-lambda: unsupported: $*" >&2; exit 2 ;;
esac
if [ -n "${CARGO+x}" ] && [ ! -x "$CARGO" ]; then
  echo "Error:   × failed to start \`cargo metadata\`: No such file or directory (os error 2)" >&2
  exit 1
fi
dir=
bin=ai-env
while [ $# -gt 0 ]; do
  case "$1" in
    -l|--lambda-dir) shift; dir=${1:-} ;;
    --lambda-dir=*) dir=${1#--lambda-dir=} ;;
    --bin) shift; bin=${1:-} ;;
    --bin=*) bin=${1#--bin=} ;;
  esac
  shift
done
test -n "$dir" || dir="${CARGO_TARGET_DIR:-target}/lambda"
mkdir -p "$dir/$bin"
cp "${FAKE_CL_BOOTSTRAP:?}" "$dir/$bin/bootstrap"
