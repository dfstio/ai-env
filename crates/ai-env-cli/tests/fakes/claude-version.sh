#!/bin/sh
# Fake `claude` for the shim tests: answers `--version` only. The shim runs
# its probe with a CLEARED environment, so the knobs come from a file next to
# this script (tests hard-link one cached copy per test directory):
#   claude-version.conf  VERSION=2.1.283   what --version prints
#                        SLEEP=0           seconds to sleep first
#                        FAIL_FIRST=0      1: the first run exits 1
#                        ID_FILE=          append "uid gid" of each run here
#                        ORPHAN=0          1: leave a 1 s orphan behind (init must reap it)
#                        SIG_FILE=         append the blocked and ignored signal masks
#                                          (Linux /proc) of each run here
dir=$(dirname "$0")
VERSION=2.1.283
SLEEP=0
FAIL_FIRST=0
ID_FILE=
ORPHAN=0
SIG_FILE=
[ -f "$dir/claude-version.conf" ] && . "$dir/claude-version.conf"
[ -n "$ID_FILE" ] && echo "$(id -u) $(id -g)" >> "$ID_FILE"
[ -n "$SIG_FILE" ] && [ -r /proc/self/status ] && echo $(grep -E '^Sig(Blk|Ign):' /proc/self/status) >> "$SIG_FILE"
[ "$ORPHAN" = 1 ] && ( sleep 1 </dev/null >/dev/null 2>&1 & )
[ "$SLEEP" != 0 ] && sleep "$SLEEP"
if [ "$FAIL_FIRST" = 1 ] && [ ! -e "$dir/claude-version.probed" ]; then
    : > "$dir/claude-version.probed"
    echo "fake claude: first run fails" >&2
    exit 1
fi
case "$1" in
    --version) echo "$VERSION (Claude Code)" ;;
    *) echo "fake claude: only --version is implemented" >&2; exit 2 ;;
esac
