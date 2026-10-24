#!/bin/sh
# Fake make for S11's admission (`ai-env claude admit`, bridge/claude/admit.rs, through
# AI_ENV_BRIDGE_LAB_ADMIT_MAKE): it runs no Docker test. POSIX sh; runs under macOS /bin/sh.
#
# The admission runs make with the lab knobs removed from its environment, so this fake's knobs come from
# `<this path>.knobs` only (every inherited FAKE_MAKE_* is unset first). It logs its argv, prints its output and
# exits:
#   FAKE_MAKE_LOG      when set, each call's argv is appended here, one line
#   FAKE_MAKE_ENV_LOG  when set, each call appends one line: the names of the environment it started with (before the
#                      knobs file), but the shell's own (PWD, SHLVL, OLDPWD, _), sorted, space-separated
#   FAKE_MAKE_OUT      printed as the run's last line (default "test result: ok. 3 passed"); a value of several lines
#                      (a cargo test failure's output) is its last lines; no backslash (macOS sh's echo reads one)
#   FAKE_MAKE_EXIT     the exit status (default 0)
#   FAKE_MAKE_SLEEP    when set, a `sleep` of that many seconds runs (a child in make's process group) before the
#                      output
#   FAKE_MAKE_PID_FILE when set with FAKE_MAKE_SLEEP, that sleep's pid is written here once it runs
# S11 (A2): make's own flags and the image's binding never reach the admission's make (admit::MAKE_ENV_DROPPED):
# one that does fails the run (exit 1, before the log lines).
started_with=$(env | sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p' | grep -vxE 'PWD|SHLVL|OLDPWD|_' | LC_ALL=C sort | tr '\n' ' ')
for v in MAKEFLAGS MFLAGS GNUMAKEFLAGS MAKEOVERRIDES MAKELEVEL MAKEFILES LOCAL_IMAGE TOOLCHAIN; do
  case " $started_with" in
    *" $v "*)
      echo "fake make: $v reached make" >&2
      exit 1
      ;;
  esac
done
for v in $(env | sed -n 's/^\(FAKE_MAKE_[A-Za-z0-9_]*\)=.*/\1/p'); do
  unset "$v"
done
case $0 in
  */*)
    if [ -f "$0.knobs" ]; then
      . "$0.knobs"
    fi
    ;;
esac
set -u
if [ -n "${FAKE_MAKE_LOG:-}" ]; then
  printf '%s\n' "$*" >> "$FAKE_MAKE_LOG"
fi
if [ -n "${FAKE_MAKE_ENV_LOG:-}" ]; then
  printf '%s\n' "${started_with% }" >> "$FAKE_MAKE_ENV_LOG"
fi
if [ -n "${FAKE_MAKE_SLEEP:-}" ]; then
  sleep "$FAKE_MAKE_SLEEP" &
  slept=$!
  if [ -n "${FAKE_MAKE_PID_FILE:-}" ]; then
    printf '%s\n' "$slept" > "$FAKE_MAKE_PID_FILE.tmp" && mv "$FAKE_MAKE_PID_FILE.tmp" "$FAKE_MAKE_PID_FILE"
  fi
  wait "$slept"
fi
echo "fake make: $*"
echo "running 3 tests"
echo "${FAKE_MAKE_OUT:-test result: ok. 3 passed}"
exit "${FAKE_MAKE_EXIT:-0}"
