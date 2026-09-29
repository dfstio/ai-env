#!/bin/sh
# Fake curl for the Makefile tests (tests/infra/image.rs): never touches the
# network. Copied into a temp bin dir as `curl`.
#   curl ... -o /dev/null -w FMT URL   s3-preflight P5: prints FAKE_CURL_CODE
#                                      (default 200)
#   curl ... -o FILE URL               claude-pin: URL's last component
#                                      (manifest.json, manifest.json.sig) is
#                                      copied from FAKE_CURL_DIR; a file that
#                                      is not there is a 404 (exit 22, like -f)
# Only https URLs are served.
# Environment:
#   FAKE_CURL_LOG   when set, each call's argv is appended here, one line
#   FAKE_CURL_DIR   the directory the release files are served from
#   FAKE_CURL_CODE  the status P5 reports (default 200)
set -u
if [ -n "${FAKE_CURL_LOG:-}" ]; then
  printf '%s\n' "$*" >> "$FAKE_CURL_LOG"
fi
out=
fmt=
url=
while [ $# -gt 0 ]; do
  case "$1" in
    -o) shift; out=${1:-} ;;
    -w) shift; fmt=${1:-} ;;
    --proto|--max-time) shift ;;
    https://*) url=$1 ;;
    http://*|ftp://*|file://*) echo "curl: (1) fake curl serves https only: $1" >&2; exit 1 ;;
  esac
  shift
done
test -n "$url" || { echo "curl: (2) no URL specified" >&2; exit 2; }
if [ -n "$fmt" ]; then
  printf '%s' "${FAKE_CURL_CODE:-200}"
  exit 0
fi
src="${FAKE_CURL_DIR:-/nonexistent}/${url##*/}"
if [ ! -f "$src" ]; then
  echo "curl: (22) The requested URL returned error: 404" >&2
  exit 22
fi
test -n "$out" || { cat "$src"; exit 0; }
cp "$src" "$out"
