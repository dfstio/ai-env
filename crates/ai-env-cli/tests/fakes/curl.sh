#!/bin/sh
# Fake curl for the Makefile tests (tests/infra/image.rs): never touches the
# network. Copied into a temp bin dir as `curl`.
#   curl ... -o /dev/null -w FMT URL   s3-preflight P5: prints FAKE_CURL_CODE
#                                      (default 200)
#   curl ... -o FILE URL               claude-pin: URL's last component
#                                      (manifest.json, manifest.json.sig) is
#                                      copied from FAKE_CURL_DIR; a file that
#                                      is not there is a 404 (exit 22, like -f)
#                                      (S11: also the release's claude binary,
#                                      served the same way by its last
#                                      component)
#   --max-filesize N                   S11: as curl with the server's
#                                      Content-Length: a served file over N
#                                      bytes is refused before the transfer,
#                                      nothing written (no -o file made or
#                                      changed), `curl: (63) Maximum file size
#                                      exceeded`, exit 63; N bytes or fewer
#                                      are served whole
# Only https URLs are served.
# S11: also `ai-env claude admit` and `claude manifest`'s release curl
# (AI_ENV_BRIDGE_LAB_RELEASE_CURL), which runs with a cleared environment:
# `<this path>.knobs`, when present, is sourced before any knob is read, so
# the knobs reach it there.
# Environment (or that file):
#   FAKE_CURL_LOG      when set, each call's argv is appended here, one line
#   FAKE_CURL_DIR      the directory the release files are served from
#   FAKE_CURL_CODE     the status P5 reports (default 200)
#   FAKE_CURL_ENV_LOG  S11: when set, each call appends one line: the names of
#                      the environment it started with (before the knobs
#                      file), but the shell's own (PWD, SHLVL, OLDPWD, _),
#                      sorted, space-separated (empty for none)
set -u
started_with=$(env | sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p' | grep -vxE 'PWD|SHLVL|OLDPWD|_' | LC_ALL=C sort | tr '\n' ' ')
case $0 in
  */*)
    if [ -f "$0.knobs" ]; then
      . "$0.knobs"
    fi
    ;;
esac
if [ -n "${FAKE_CURL_ENV_LOG:-}" ]; then
  printf '%s\n' "${started_with% }" >> "$FAKE_CURL_ENV_LOG"
fi
if [ -n "${FAKE_CURL_LOG:-}" ]; then
  printf '%s\n' "$*" >> "$FAKE_CURL_LOG"
fi
out=
fmt=
url=
max_filesize=
while [ $# -gt 0 ]; do
  case "$1" in
    -o|--output) shift; out=${1:-} ;;
    -w) shift; fmt=${1:-} ;;
    --max-filesize) shift; max_filesize=${1:-} ;;
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
if [ -n "$max_filesize" ] && [ "$(($(wc -c < "$src")))" -gt "$max_filesize" ]; then
  echo "curl: (63) Maximum file size exceeded" >&2
  exit 63
fi
test -n "$out" || { cat "$src"; exit 0; }
cp "$src" "$out"
