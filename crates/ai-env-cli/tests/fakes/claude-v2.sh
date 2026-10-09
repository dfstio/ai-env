#!/bin/sh
# Fake `claude` v2 for the S2 pump tests (hoststate, mirror, race) and the S7
# local-scratch tests in wrapper.rs (FAKE_TOKEN_LOG). POSIX sh
# + sed; runs under macOS /bin/sh (bash 3.2 in sh mode). Hard-linked into a
# tempdir by tests/common/mod.rs and spawned by ai-env-claude as the piped
# child. It speaks just enough of the stream-json protocol: every
# control_request gets a success control_response with its request_id;
# `initialize` is answered with {"pid":<pid>} and followed (once per process)
# by a system/init frame; a user line gets its isReplay echo (when it has a
# uuid), one assistant frame and one result frame. v1 (claude.sh) stays for
# the exec tests.
#
# Every knob is optional:
#   ARGV_LOG                  append "--- gen <n>", then one argument per line
#   FAKE_STDIN_LOG            append "<gen><TAB><line>" for every stdin line
#   FAKE_ENV_LOG              append "gen <n> CLAUDE_CONFIG_DIR=<v|unset> SECURESTORAGE=<present|absent> pid=<pid>"
#   FAKE_SPAWN_COUNT          counter file: this process's generation = previous + 1
#   FAKE_SESSION_ID           the session id (default: the --resume value, else a fixed uuid)
#   FAKE_RESUME_FAIL_ONCE     marker path: with --resume and no marker, create it and fail
#                             like the CLI's resume miss (stderr line + error result, exit 1)
#                             before reading stdin
#   FAKE_RESUME_FAIL_AFTER_ACK=1  the same miss, but only after answering initialize
#   FAKE_MISS_DELAY_MS        ms: that after-ack miss waits this long first (S7: a miss
#                             later than the wrapper's grace for one)
#   FAKE_MISS_EXIT_DELAY_MS   ms: a resume miss waits this long between its result line and
#                             its exit (S7: a child still exiting when the wrapper's grace ends)
#   FAKE_MISS_AFTER_INIT=1    the same miss (stderr line + error result, exit 1) right
#                             after the init frame: the host has seen the init
#   FAKE_INIT_AT_TURN=1       the init frame, and everything that follows it below, comes
#                             with the first user turn instead of after initialize: the real
#                             CLI emits system/init once per turn
#   FAKE_IGNORE_CONTROL_GEN   in that generation control requests are logged, never answered
#   FAKE_EXIT_AFTER_INIT      <code>:<msg>: right after the init frame, msg on stderr, exit code
#   FAKE_STDOUT_FILE          cat'ed to stdout right after the init frame
#   FAKE_STREAM_LINES         n: emit {"type":"stream_event","n":<i>} for i=1..n after the init frame
#   FAKE_STREAM_PAD           bytes: each stream_event line also carries "pad":"xxx…" of that length
#   FAKE_STREAM_BG=1          the stream_event lines are written by a background subshell
#                             while the main loop keeps reading stdin (waited for at EOF)
#   FAKE_EXIT_AFTER_STREAM=1  exit (FAKE_EXIT, default 0) right after the stream_event
#                             lines, without waiting for stdin EOF
#   FAKE_OAUTH_REFRESH=1      after the init frame, one oauth_token_refresh control_request (id o1)
#   FAKE_NEW_SESSION_AFTER    n: after n user turns the session id changes to a second fixed
#                             uuid (`/clear`): the next turn starts with a new init frame
#   FAKE_IGNORE_EOF=1         at stdin EOF: sleep 30 instead of exiting
#   FAKE_IGNORE_TERM=1        trap '' TERM (inherited by the sleep above)
#   FAKE_TERM_LOG             on TERM: append "TERM" to this file, then exit 143
#   FAKE_TERM_STDERR          on TERM: print this line on stderr, then exit 143
#   FAKE_HOLD_STDERR_MS       ms: a background sleep keeps the fake's stderr open that long
#                             (it outlives the fake: its reader sees no EOF at the exit)
#   FAKE_EXIT                 exit code at stdin EOF (default 0)
#   FAKE_STDERR               printed once to stderr at start
#   FAKE_TOKEN_LOG            S7: append "gen <n> source=<fd|env|none|fd-unreadable|fd-invalid>
#                             len=<n> sha8=<first 8 hex of its sha256|-> fdvar=<n|unset|invalid>
#                             envvar=<present|absent>": the token as the CLI would take it
#                             (CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR's fd, read at start,
#                             else CLAUDE_CODE_OAUTH_TOKEN), described, never written anywhere

sleeper=""
streamer=""
on_term() {
  if [ -n "${FAKE_TERM_STDERR:-}" ]; then
    printf '%s\n' "$FAKE_TERM_STDERR" >&2
  fi
  if [ -n "${FAKE_TERM_LOG:-}" ]; then
    printf 'TERM\n' >> "$FAKE_TERM_LOG"
  fi
  if [ -n "$sleeper" ]; then
    kill "$sleeper" 2>/dev/null
  fi
  exit 143
}
term_trapped=0
if [ "${FAKE_IGNORE_TERM:-0}" = "1" ]; then
  trap '' TERM
elif [ -n "${FAKE_TERM_LOG:-}" ] || [ -n "${FAKE_TERM_STDERR:-}" ]; then
  trap on_term TERM
  term_trapped=1
fi

gen=1
if [ -n "${FAKE_SPAWN_COUNT:-}" ]; then
  prev=0
  if [ -f "$FAKE_SPAWN_COUNT" ]; then
    IFS= read -r prev < "$FAKE_SPAWN_COUNT" || true
  fi
  gen=$(( ${prev:-0} + 1 ))
  printf '%s\n' "$gen" > "$FAKE_SPAWN_COUNT"
fi

resume=""
expect_resume=0
if [ -n "${ARGV_LOG:-}" ]; then
  printf -- '--- gen %s\n' "$gen" >> "$ARGV_LOG"
fi
for a in "$@"; do
  if [ -n "${ARGV_LOG:-}" ]; then
    printf '%s\n' "$a" >> "$ARGV_LOG"
  fi
  if [ "$expect_resume" = "1" ]; then
    resume=$a
    expect_resume=0
  fi
  case "$a" in
    --resume=*) resume=${a#--resume=} ;;
    --resume) expect_resume=1 ;;
  esac
done

if [ -n "${FAKE_ENV_LOG:-}" ]; then
  if [ -n "${CLAUDE_CONFIG_DIR+x}" ]; then ccd=$CLAUDE_CONFIG_DIR; else ccd=unset; fi
  if [ -n "${CLAUDE_SECURESTORAGE_CONFIG_DIR+x}" ]; then ss=present; else ss=absent; fi
  printf 'gen %s CLAUDE_CONFIG_DIR=%s SECURESTORAGE=%s pid=%s\n' "$gen" "$ccd" "$ss" "$$" >> "$FAKE_ENV_LOG"
fi

# The token, as the CLI would take it: the descriptor first, else the variable.
# Only its source, length and a hash prefix are logged; the shell variable is
# cleared right after, and the value only ever travels through a pipe to shasum.
if [ -n "${FAKE_TOKEN_LOG:-}" ]; then
  tok=""
  src=none
  fdvar=unset
  if [ -n "${CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR+x}" ]; then
    case "$CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR" in
      ''|*[!0-9]*) src=fd-invalid; fdvar=invalid ;;
      *)
        fdvar=$CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR
        if tok=$(eval "cat <&$fdvar" 2>/dev/null); then src=fd; else src=fd-unreadable; tok=""; fi
        ;;
    esac
  elif [ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ]; then
    tok=$CLAUDE_CODE_OAUTH_TOKEN
    src=env
  fi
  if [ -n "${CLAUDE_CODE_OAUTH_TOKEN+x}" ]; then envvar=present; else envvar=absent; fi
  sha8=-
  if [ -n "$tok" ]; then
    sha8=$(printf '%s' "$tok" | shasum -a 256 2>/dev/null | cut -c1-8)
    if [ -z "$sha8" ]; then sha8=-; fi
  fi
  printf 'gen %s source=%s len=%s sha8=%s fdvar=%s envvar=%s\n' "$gen" "$src" "${#tok}" "$sha8" "$fdvar" "$envvar" >> "$FAKE_TOKEN_LOG"
  tok=""
fi

if [ -n "${FAKE_STDERR:-}" ]; then
  printf '%s\n' "$FAKE_STDERR" >&2
fi

if [ -n "${FAKE_HOLD_STDERR_MS:-}" ]; then
  hold=$FAKE_HOLD_STDERR_MS
  # Only stderr is inherited: stdin and stdout of the sleep are /dev/null.
  sleep "$((hold / 1000)).$(printf '%03d' $((hold % 1000)))" </dev/null >/dev/null &
fi

# Fixed ids, built here so no uuid literal lives in the file.
fixed_sid=$(printf '%08x-0000-4000-8000-%012x' 3054 3054)
other_sid=$(printf '%08x-0000-4000-8000-%012x' 57005 57005)
clear_sid=$(printf '%08x-0000-4000-8000-%012x' 49642 49642)
if [ -n "${FAKE_SESSION_ID:-}" ]; then
  sid=$FAKE_SESSION_ID
elif [ -n "$resume" ]; then
  sid=$resume
else
  sid=$fixed_sid
fi

pad=""
if [ -n "${FAKE_STREAM_PAD:-}" ]; then
  pad=$(printf "%${FAKE_STREAM_PAD}s" '' | tr ' ' x)
fi

# The CLI's resume miss in stream-json mode: the stderr line, then one
# error_during_execution result on stdout, then exit 1.
resume_miss() {
  printf 'No conversation found with session ID: %s\n' "$resume" >&2
  printf '{"type":"result","subtype":"error_during_execution","duration_ms":0,"duration_api_ms":0,"is_error":true,"num_turns":0,"stop_reason":null,"session_id":"%s","total_cost_usd":0,"usage":{},"modelUsage":{},"permission_denials":[],"uuid":"x","errors":["No conversation found with session ID: %s"],"result_index":0}\n' "$other_sid" "$resume"
  if [ -n "${FAKE_MISS_EXIT_DELAY_MS:-}" ]; then
    sleep "$((FAKE_MISS_EXIT_DELAY_MS / 1000)).$(printf '%03d' $((FAKE_MISS_EXIT_DELAY_MS % 1000)))"
  fi
  exit 1
}

fail_after_ack=0
if [ -n "${FAKE_RESUME_FAIL_ONCE:-}" ] && [ -n "$resume" ] && [ ! -e "$FAKE_RESUME_FAIL_ONCE" ]; then
  : > "$FAKE_RESUME_FAIL_ONCE"
  if [ "${FAKE_RESUME_FAIL_AFTER_ACK:-0}" = "1" ]; then
    fail_after_ack=1
  else
    resume_miss
  fi
fi

stream() {
  i=1
  while [ "$i" -le "$FAKE_STREAM_LINES" ]; do
    if [ -n "$pad" ]; then
      printf '{"type":"stream_event","n":%s,"pad":"%s"}\n' "$i" "$pad"
    else
      printf '{"type":"stream_event","n":%s}\n' "$i"
    fi
    i=$((i + 1))
  done
}

init_done=0
emit_init() {
  if [ "$init_done" = "1" ]; then
    return
  fi
  init_done=1
  printf '{"type":"system","subtype":"init","session_id":"%s","cwd":"%s","uuid":"init-%s"}\n' "$sid" "$(pwd)" "$gen"
  if [ "${FAKE_MISS_AFTER_INIT:-0}" = "1" ]; then
    resume_miss
  fi
  if [ -n "${FAKE_EXIT_AFTER_INIT:-}" ]; then
    printf '%s\n' "${FAKE_EXIT_AFTER_INIT#*:}" >&2
    exit "${FAKE_EXIT_AFTER_INIT%%:*}"
  fi
  if [ -n "${FAKE_STDOUT_FILE:-}" ]; then
    cat "$FAKE_STDOUT_FILE"
  fi
  if [ -n "${FAKE_STREAM_LINES:-}" ]; then
    if [ "${FAKE_STREAM_BG:-0}" = "1" ]; then
      stream &
      streamer=$!
    else
      stream
    fi
    if [ "${FAKE_EXIT_AFTER_STREAM:-0}" = "1" ]; then
      if [ -n "$streamer" ]; then
        wait "$streamer"
      fi
      exit "${FAKE_EXIT:-0}"
    fi
  fi
  if [ "${FAKE_OAUTH_REFRESH:-0}" = "1" ]; then
    printf '%s\n' '{"type":"control_request","request_id":"o1","request":{"subtype":"oauth_token_refresh"}}'
  fi
}

on_control_request() {
  if [ -n "${FAKE_IGNORE_CONTROL_GEN:-}" ] && [ "$FAKE_IGNORE_CONTROL_GEN" = "$gen" ]; then
    return
  fi
  id=$(printf '%s\n' "$1" | sed -E 's/.*"request_id":"([^"]*)".*/\1/')
  case "$1" in
    *'"subtype":"initialize"'*)
      printf '{"type":"control_response","response":{"subtype":"success","request_id":"%s","response":{"pid":%s}}}\n' "$id" "$$"
      if [ "$fail_after_ack" = "1" ]; then
        if [ -n "${FAKE_MISS_DELAY_MS:-}" ]; then
          sleep "$((FAKE_MISS_DELAY_MS / 1000)).$(printf '%03d' $((FAKE_MISS_DELAY_MS % 1000)))"
        fi
        resume_miss
      fi
      if [ "${FAKE_INIT_AT_TURN:-0}" != "1" ]; then
        emit_init
      fi
      ;;
    *)
      printf '{"type":"control_response","response":{"subtype":"success","request_id":"%s","response":{}}}\n' "$id"
      ;;
  esac
}

turns=0
on_user() {
  if [ "${FAKE_INIT_AT_TURN:-0}" = "1" ]; then
    emit_init
  fi
  turns=$((turns + 1))
  if [ -n "${FAKE_NEW_SESSION_AFTER:-}" ] && [ "$turns" -eq $((FAKE_NEW_SESSION_AFTER + 1)) ]; then
    sid=$clear_sid
    printf '{"type":"system","subtype":"init","session_id":"%s","cwd":"%s","uuid":"init-%s-clear"}\n' "$sid" "$(pwd)" "$gen"
  fi
  u=$(printf '%s\n' "$1" | sed -n -E 's/.*"uuid":"([^"]*)".*/\1/p')
  if [ -n "$u" ]; then
    printf '{"type":"user","message":{"role":"user","content":"echo"},"session_id":"%s","parent_tool_use_id":null,"uuid":"%s","isReplay":true}\n' "$sid" "$u"
  fi
  printf '{"type":"assistant","message":{"content":[{"type":"text","text":"ok"}]},"session_id":"%s"}\n' "$sid"
  if [ -n "$u" ]; then
    printf '{"type":"result","subtype":"success","is_error":false,"num_turns":1,"session_id":"%s","user_message_uuid":"%s","user_message_uuids":["%s"]}\n' "$sid" "$u" "$u"
  else
    printf '{"type":"result","subtype":"success","is_error":false,"num_turns":1,"session_id":"%s"}\n' "$sid"
  fi
}

while IFS= read -r line || [ -n "$line" ]; do
  if [ -n "${FAKE_STDIN_LOG:-}" ]; then
    printf '%s\t%s\n' "$gen" "$line" >> "$FAKE_STDIN_LOG"
  fi
  case "$line" in
    *'"type":"control_request"'*) on_control_request "$line" ;;
    *'"type":"user"'*) on_user "$line" ;;
    *) : ;;
  esac
  line=""
done

if [ -n "$streamer" ]; then
  wait "$streamer"
fi
if [ "${FAKE_IGNORE_EOF:-0}" = "1" ]; then
  if [ "$term_trapped" = "0" ]; then
    # An ignored TERM stays ignored across exec; an untrapped TERM kills the sleep.
    exec sleep 30
  fi
  # A trapped TERM must reach this shell: the trap runs as soon as `wait` is interrupted.
  sleep 30 </dev/null >/dev/null 2>&1 &
  sleeper=$!
  wait "$sleeper"
fi
exit "${FAKE_EXIT:-0}"
