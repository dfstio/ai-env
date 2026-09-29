#!/bin/sh
# Fake cargo-lambda for the vm-build wiring test (tests/infra/image.rs): no
# compiler. Copied into a temp bin dir; the Makefile gets it as CARGO_LAMBDA.
#   cargo-lambda lambda --version   "cargo-lambda 1.9.2 (fake)"
#   cargo-lambda lambda build ...   copies FAKE_CL_BOOTSTRAP to
#                                   <lambda dir>/ai-env/bootstrap, where the
#                                   lambda dir is --lambda-dir / -l when given,
#                                   else $CARGO_TARGET_DIR/lambda (else
#                                   target/lambda): cargo-lambda 1.9.2's rule
#                                   (the target directory of cargo metadata)
# Environment:
#   FAKE_CL_LOG        when set, each call's argv is appended here, one line
#   FAKE_CL_BOOTSTRAP  the "fresh build" to copy
set -u
if [ -n "${FAKE_CL_LOG:-}" ]; then
  printf '%s\n' "$*" >> "$FAKE_CL_LOG"
fi
test "${1:-}" = lambda || { echo "fake cargo-lambda: expected 'lambda'" >&2; exit 2; }
shift
case "${1:-}" in
  --version) echo "cargo-lambda 1.9.2 (fake)"; exit 0 ;;
  build) shift ;;
  *) echo "fake cargo-lambda: unsupported: $*" >&2; exit 2 ;;
esac
dir=
while [ $# -gt 0 ]; do
  case "$1" in
    -l|--lambda-dir) shift; dir=${1:-} ;;
    --lambda-dir=*) dir=${1#--lambda-dir=} ;;
  esac
  shift
done
test -n "$dir" || dir="${CARGO_TARGET_DIR:-target}/lambda"
mkdir -p "$dir/ai-env"
cp "${FAKE_CL_BOOTSTRAP:?}" "$dir/ai-env/bootstrap"
