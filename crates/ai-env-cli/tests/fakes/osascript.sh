#!/bin/sh
# Fake osascript for the pasteboard (src/bridge/pasteboard.rs) and the deployer
# key hand-over tests (tests/infra/handover.rs): never touches the clipboard.
# Installed by a test as <tmp>/bin/osascript and named by
# AI_ENV_BRIDGE_LAB_OSASCRIPT (debug builds only). It runs no script: it checks
# the call's shape and keeps the change count in a file.
#   osascript -l JavaScript -e SCRIPT   exactly this argv, and SCRIPT must
#       contain prepareForNewContentsWithOptions(1),
#       org.nspasteboard.ConcealedType, org.nspasteboard.TransientType and
#       AI_ENV_PB_VALUE (else bad-argv, exit 1). The operation and its operands
#       come from the environment, as the script reads them:
#   AI_ENV_PB_OP=set       the n-th set (n: the sets so far plus one): an empty
#       AI_ENV_PB_VALUE is osascript's error, exit 1; else the value is compared
#       with FAKE_PB_EXPECT_<n> (unset: unchecked), the change count rises by
#       one and is printed, exit 0
#   AI_ENV_PB_OP=clear-if  `cleared` when AI_ENV_PB_COUNT is the change count,
#       else `kept`
#   AI_ENV_PB_OP=clear     `cleared`
#   any other operation    osascript's error, exit 1
# Environment:
#   FAKE_PB_STATE   the state file "<change count> <sets so far>" (required by
#                   set and clear-if; created as "100 0")
#   FAKE_PB_TOUCH   1: another copy follows every set (the count rises by two;
#                   the set prints the count before that copy)
#   FAKE_PB_EXPECT_<n>  what the n-th set must place (compared, never printed)
#   FAKE_OSA_FAIL   space-separated words, each naming calls that fail like
#                   osascript: 1 every call; set, clear-if or clear every call
#                   of that operation; set@<n> the set of ordinal <n> only (a
#                   failed set does not count, so a retry of it fails too)
#   FAKE_OSA_LOG    one line per call: "set <n> match", "set <n> mismatch",
#                   "set <n> unchecked", "clear-if cleared", "clear-if kept",
#                   "clear cleared", "fail <op>" (FAKE_OSA_FAIL, an empty value
#                   as "fail set", an unknown operation as "fail unknown") or
#                   "bad-argv"; then " ENV=<names>" (comma-separated) when any
#                   of AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
#                   AWS_SESSION_TOKEN, AI_ENV_BRIDGE_AS reached it (none may).
#                   Never a value.
set -u
leaked=
for n in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AI_ENV_BRIDGE_AS; do
  eval "s=\${$n+x}"
  test -z "$s" || leaked="${leaked:+$leaked,}$n"
done
log() {
  if [ -n "${FAKE_OSA_LOG:-}" ]; then
    printf '%s%s\n' "$1" "${leaked:+ ENV=$leaked}" >> "$FAKE_OSA_LOG"
  fi
}
# osascript's own shape for an error thrown by a JXA script.
osa_error() {
  printf 'execution error: Error: Error: %s (-2700)\n' "$1" >&2
  exit 1
}

bad=0
if [ $# -ne 4 ] || [ "$1" != -l ] || [ "$2" != JavaScript ] || [ "$3" != -e ]; then
  bad=1
fi
script=${4:-}
for want in 'prepareForNewContentsWithOptions(1)' org.nspasteboard.ConcealedType org.nspasteboard.TransientType AI_ENV_PB_VALUE; do
  case "$script" in
    *"$want"*) ;;
    *) bad=1 ;;
  esac
done
if [ "$bad" = 1 ]; then
  log bad-argv
  echo 'fake osascript: unexpected argv or script' >&2
  exit 1
fi

op=${AI_ENV_PB_OP:-}
case "$op" in
  set|clear-if|clear) word=$op ;;
  *) word=unknown ;;
esac
fail=" ${FAKE_OSA_FAIL:-} "
failed=0
case "$fail" in
  *" 1 "*) failed=1 ;;
esac
if [ "$word" != unknown ]; then
  case "$fail" in
    *" $op "*) failed=1 ;;
  esac
fi
if [ "$failed" = 1 ]; then
  log "fail $word"
  osa_error 'setString:forType: refused'
fi
if [ "$word" = unknown ]; then
  log 'fail unknown'
  osa_error 'unknown AI_ENV_PB_OP'
fi
if [ "$op" = clear ]; then
  log 'clear cleared'
  echo cleared
  exit 0
fi

state=${FAKE_PB_STATE:-}
if [ -z "$state" ]; then
  echo 'fake osascript: FAKE_PB_STATE is not set' >&2
  exit 2
fi
test -e "$state" || printf '100 0\n' > "$state"
count=
sets=
read -r count sets < "$state" || true
case "$count" in ''|*[!0-9]*) count=bad ;; esac
case "$sets" in ''|*[!0-9]*) count=bad ;; esac
if [ "$count" = bad ]; then
  echo "fake osascript: $state does not hold \"<change count> <sets so far>\"" >&2
  exit 2
fi

if [ "$op" = clear-if ]; then
  if [ "${AI_ENV_PB_COUNT:-}" = "$count" ]; then result=cleared; else result=kept; fi
  log "clear-if $result"
  echo "$result"
  exit 0
fi

# set
n=$((sets + 1))
case "$fail" in
  *" set@$n "*)
    log 'fail set'
    osa_error 'setString:forType: refused' ;;
esac
if [ -z "${AI_ENV_PB_VALUE:-}" ]; then
  log 'fail set'
  osa_error 'no value in AI_ENV_PB_VALUE'
fi
eval "expect_set=\${FAKE_PB_EXPECT_$n+x}"
if [ -z "$expect_set" ]; then
  result=unchecked
else
  eval "expect=\$FAKE_PB_EXPECT_$n"
  if [ "$AI_ENV_PB_VALUE" = "$expect" ]; then result=match; else result=mismatch; fi
  expect=
fi
count=$((count + 1))
printed=$count
if [ "${FAKE_PB_TOUCH:-}" = 1 ]; then
  count=$((count + 1))
fi
printf '%s %s\n' "$count" "$n" > "$state"
log "set $n $result"
echo "$printed"
