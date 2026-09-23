#!/bin/sh
# Fake `claude` for the wrapper tests (T1.2). Copied into a tempdir by the
# FakeClaude harness and exec'd by ai-env-claude as the "real binary".
#   ARGV_LOG          every argument, one per line, appended here
#   FAKE_STDOUT       printed verbatim (plus a newline) when set
#   FAKE_ECHO_STDIN   =1 copies stdin to stdout after FAKE_STDOUT
#   FAKE_EXIT         exit status (default 0)
for a in "$@"; do
  printf '%s\n' "$a" >> "${ARGV_LOG:-/dev/null}"
done
if [ -n "${FAKE_STDOUT+x}" ]; then
  printf '%s\n' "$FAKE_STDOUT"
fi
if [ "${FAKE_ECHO_STDIN:-0}" = "1" ]; then
  cat
fi
exit "${FAKE_EXIT:-0}"
