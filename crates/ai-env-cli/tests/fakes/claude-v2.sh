#!/bin/sh
# Fake `claude` v2 for the S2 pump tests (hoststate, mirror, race), the S7
# local-scratch tests in wrapper.rs (FAKE_TOKEN_LOG) and S8's remote link
# (tests/common/remote.rs). POSIX sh
# + sed; runs under macOS /bin/sh (bash 3.2 in sh mode). Hard-linked into a
# tempdir by tests/common/mod.rs and spawned by ai-env-claude as the piped
# child. It speaks just enough of the stream-json protocol: every
# control_request gets a success control_response with its request_id;
# `initialize` is answered with {"pid":<pid>} and followed (once per process)
# by a system/init frame; a user line gets its isReplay echo (when it has a
# uuid), one assistant frame (S10: a tool_use one before it, with its
# tool_result, when the turn runs a tool) and one result frame. `--version`
# alone prints `2.1.302 (Claude Code)` (AUTH_TIMERS' claude, what the shim's
# probe reads) and exits before anything is logged or counted. v1 (claude.sh)
# stays for the exec tests.
#
# The init right after `initialize` is a convenience the tests start from,
# not the real CLI's shape: 2.1.x emits system/init once per turn, with the
# user line, never at engine start, so a config probe (initialize, a few
# control requests, EOF) gets none (plans/s2-measurements.md).
# FAKE_INIT_AT_TURN=1 is that shape. Each fresh CLI also gets a session id
# of its own: so does each process here after the first on a FAKE_SPAWN_COUNT
# counter (two chats on one remote rig are two sessions; the first keeps the
# fixed id, tests/common/mod.rs's fake_fixed_sid).
#
# On the remote link the shim's spawn of `claude` is this file hard-linked
# as `vm-claude`, run with the environment the shim builds (HOME, PATH,
# CLAUDE_CONFIG_DIR and the allowlisted names; nothing of the test's), so a
# file `<this path>.knobs` beside the link the shim ran, when present, is
# sourced first: the test's knobs as single-quoted export lines.
#
# Every knob is optional:
#   ARGV_LOG                  append "--- gen <n>", then one argument per line
#   FAKE_STDIN_LOG            append "<gen><TAB><line>" for every stdin line
#   FAKE_ENV_LOG              append "gen <n> CLAUDE_CONFIG_DIR=<v|unset> SECURESTORAGE=<present|absent> pid=<pid>"
#   FAKE_SPAWN_COUNT          counter file: this process's generation = previous + 1
#   FAKE_SESSION_ID           the session id (default: with --resume a fork's own id (S10,
#                             --fork-session below) or else the --resume value, else a fixed uuid
#                             for generation 1 and, for a later one, an id of its own: the
#                             uuid of 3054 + 65536 * <gen>, as tests/common/mod.rs's uuid())
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
#   FAKE_INIT_AT_TURN=1       the init frame comes with every user turn instead of once after
#                             initialize, as the real CLI's system/init does: the first turn's
#                             with everything that follows it below, each later one alone
#                             (uuid init-<gen>-<turn>; a FAKE_NEW_SESSION_AFTER turn's is its
#                             new session's); no turn, no init
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
# S8 (the remote session's knobs; the config dir below is CLAUDE_CONFIG_DIR, else
# $HOME/.claude, and <slug> is the reported cwd's with every character outside
# [A-Za-z0-9] a `-`, as the picker's, not NFC-normalised nor shortened past 200):
#   FAKE_CWD                  the cwd the init frames, the slug and the transcript entries
#                             report (default: the real one). On the remote link the
#                             workspace's VM path, which the shim's fs_root prefixes
#   FAKE_CONFIG_DIR           the config dir the transcript_mirror frames name (default: the
#                             real one). On the remote link the VM path of the agent's
#                             (the Mac's ~/.claude), which the rig keeps elsewhere
#   FAKE_RESUME_NEEDS_FILE=1  with --resume: unless <config dir>/projects/<slug>/<the
#                             --resume uuid>.jsonl exists, the CLI's resume miss (as
#                             FAKE_RESUME_FAIL_ONCE's, after initialize with
#                             FAKE_RESUME_FAIL_AFTER_ACK=1); FAKE_ENV_LOG gets
#                             "gen <n> resumed lines=<lines in that file|missing>"
#   FAKE_WRITE_TRANSCRIPT=1   each turn appends a user and an assistant entry to its own
#                             transcript, <config dir>/projects/<slug>/<session id>.jsonl, as
#                             the CLI does; with --session-mirror one transcript_mirror frame
#                             per turn carries the same two entries (filePath under
#                             FAKE_CONFIG_DIR), so the Mac's mirror can be compared with that
#                             file byte for byte, but the api-request lines below, which no
#                             mirror frame carries (S9: compare with `common::mirrored` of it)
#   FAKE_API_REQUEST          1 (the default, as 2.1.302 writes): with FAKE_WRITE_TRANSCRIPT=1
#                             each turn's user entry is followed, in the file only, by
#                             {"type":"api-request","requestId":"req_fake_<turn>_<gen>",
#                             "sessionId":"<sid>","timestamp":"2026-10-17T00:00:00.000Z"} and
#                             {"type":"api-request-blob","requestId":"req_fake_<turn>_<gen>",
#                             "blob":"ZmFrZQ=="}; 0: none (2.1.296 and earlier)
#   FAKE_EDIT                 <rel>:<text>: each turn writes <text> and a newline over <rel>
#                             under the real cwd (parents created) and leaves it uncommitted
#   FAKE_COMMIT               <msg>: each turn, after FAKE_EDIT, commits in the real cwd
#                             (`git add -A`, then `git commit --allow-empty -m <msg>` as
#                             claude-agent, no hooks, no signing): with FAKE_EDIT the edit is
#                             in the commit
#   FAKE_WIP_EDIT             <rel>:<text>: as FAKE_EDIT, but after FAKE_COMMIT: the turn's
#                             result finds it uncommitted beside the turn's commit (the
#                             per-result code-out's box/* and box/wip/* from one turn)
#   FAKE_WRITE_SETTINGS       [local:|user:|both:]<json>: each turn writes <json> as the cwd's
#                             .claude/settings.local.json (local, the default: what "don't ask
#                             again" writes) and/or <config dir>/settings.json (user)
#   FAKE_RATE_LIMIT_EVENT=1   each turn, between its assistant frame and its result, prints
#                             {"type":"rate_limit_event","rate_limit_info":{"status":"allowed"}}
#                             (tests/fixtures/claude/valid-stream-json-2.1.296.jsonl's line)
#   FAKE_FINAL_MIRROR_MS      ms: that long after stdin EOF, one last transcript_mirror frame
#                             (a summary entry, also appended to the transcript with
#                             FAKE_WRITE_TRANSCRIPT=1)
#   FAKE_EXIT_DELAY_MS        ms: the wait between stdin EOF and the exit (counted from EOF,
#                             FAKE_FINAL_MIRROR_MS's wait included): the CLI's own 0.5 to 1.1 s
#   FAKE_ONBOARDING=1         an onboarding-like stall: one stderr line, then every stdin line
#                             is logged and nothing is ever answered (no control response, no
#                             init, no turn); exit 1 at stdin EOF
#   FAKE_ENV_NAMES_LOG        append "gen <n> CLAUDE_CODE_ENTRYPOINT=<v|unset> names=<every name
#                             of the environment, sorted, comma-separated>": what the CLI was
#                             started with (fresh-claude-json's spawn), no other value
#   FAKE_VERSION              the version `--version` prints (default 2.1.302): another claude
#                             than AUTH_TIMERS measured (S8: the shim's probe names it)
#   FAKE_ENV_DUMP             append "--- gen <n>", then every exported variable the process
#                             started with as NAME=value, sorted, but the knobs file's names
#                             and the shell's own (PWD, SHLVL, OLDPWD, _): what a remote
#                             spawn's environment holds in the VM (S8)
# S10 (the continuity engine's and the parking's tests, plans/s10-contracts.md §8.4;
# tests/continuity/rig.rs checks them):
#   FAKE_ASK                  <tool>[:<cmd>]: turn FAKE_ASK_TURN asks for its tool: after the
#                             echo, an assistant tool_use frame (that tool, input
#                             {"command":<cmd>}, or {} with no cmd), then the control_request
#                             can_use_tool (request_id perm-<gen>-<turn>; tool_name, input,
#                             tool_use_id, permission_suggestions []); the turn is held: every
#                             line is logged, control requests are answered (an interrupt
#                             withdraws the request, control_cancel_request, and ends the turn
#                             with an error result), user lines are queued and run after the
#                             turn, asking nothing; stdin EOF while holding exits. The host's
#                             control_response to that id releases it: allowed, the
#                             tool_result (FAKE_ASK_RESULT), then the reply, the turn's effects
#                             and the result; denied or answered with an error, an error
#                             tool_result, the reply and the result, and none of FAKE_EDIT,
#                             FAKE_WRITE_SETTINGS, FAKE_COMMIT, FAKE_WIP_EDIT or FAKE_SUBAGENTS
#                             (the tool never ran)
#   FAKE_ASK_TURN             n: the turn FAKE_ASK asks in (default 1; each process counts its own)
#   FAKE_ASK_RESULT           the tool_result text after an allow (default ok)
#   FAKE_PERMISSION_LOG       append "gen <g> turn <t> perm-<g>-<t> allow|deny|error" per answer
#   FAKE_SUBAGENTS            n: each turn writes n subagent transcripts in the session's subtree,
#                             <config dir>/projects/<slug>/<session id>/subagents/agent-<g>-<t>-<k>.jsonl
#                             (k = 1..n), two sidechain lines each (isSidechain true, agentId
#                             <g>-<t>-<k>), as a tool's effect
#   FAKE_SUBTREE_LOG=1        at each turn's start, FAKE_ENV_LOG gets "gen <g> turn <t>
#                             subagents=<n>": the files that subagents directory holds then
#                             (what a restore put there)
#   FAKE_TURN_MS              ms: each turn runs a long tool: an assistant tool_use frame (Bash),
#                             the mark below, a wait that long (a trapped TERM ends it:
#                             FAKE_TERM_LOG, FAKE_TERM_STDERR), its tool_result, then the reply
#                             and the result (in FAKE_ASK's turn, once allowed)
#   FAKE_TURN_MARK            the long tool's mark: "gen <g> turn <t>" appended as its wait starts
# S10: every assistant frame carries "parent_tool_use_id":null and the uuid its transcript
# entry gets (written or not, FAKE_WRITE_TRANSCRIPT): a turn's reply
# <turn, %08x>-0000-4000-a000-<gen, %012x>, a tool's tool_use the same with b000; the tool's
# result is a user frame (c000). With FAKE_WRITE_TRANSCRIPT, one the transcript it writes into
# already holds (a process of the same generation wrote it: another rig's, or one with no
# FAKE_SPAWN_COUNT) is <turn, %08x>-0000-4000-a000-<k, %04x><gen, %08x> with the first free k,
# as the CLI's uuids never repeat. A turn with a tool writes its user entry and the tool_use as
# the tool starts, its tool_result and its reply at its end; a turn without one, both entries
# at its end.
# S10: two flags of the CLI, in either form (`--flag value`, `--flag=value`; ARGV_LOG logs
# them as given):
#   --resume-session-at       <uuid>: FAKE_ENV_LOG gets "gen <n> cut at=<uuid> found|missing"
#                             (a message of the --resume transcript, or not); found, this
#                             process's entries chain from it; missing with
#                             FAKE_RESUME_NEEDS_FILE=1, the CLI's cut miss: "No message found
#                             with message.uuid of: <uuid>" on stderr and as an error result,
#                             exit 1, where a resume miss comes (before stdin is read, or
#                             after initialize with FAKE_RESUME_FAIL_AFTER_ACK=1)
#   --session-id              <sid>: the session id (over FAKE_SESSION_ID, and over --resume
#                             with --fork-session); FAKE_ENV_LOG gets "gen <n> session-id=<sid>";
#                             then, as the CLI refuses it, beside --resume (-r) or --continue
#                             (-c) without --fork-session, "Error: --session-id can only be used
#                             with --continue or --resume if --fork-session is also specified."
#                             on stderr, exit 1; with <config dir>/projects/<slug>/<sid>.jsonl
#                             there, "Error: Session ID <sid> is already in use." on stderr,
#                             exit 1; both before stdin is read and before a resume or cut miss
#                             (nothing on stdout)
#   --fork-session            beside --resume <X>: a session of its own that starts from X's
#                             history: without --session-id (or FAKE_SESSION_ID) its id is
#                             <gen, %08x>-0000-4000-f000-<gen, %012x>; FAKE_ENV_LOG gets
#                             "gen <n> forked from=<X>"; its first transcript write
#                             (FAKE_WRITE_TRANSCRIPT) first copies X's user and assistant lines
#                             into its own transcript (with --session-mirror one mirror frame of
#                             them); X's file is left as it is. The copy is this fake's model:
#                             part B records what the CLI writes
# S10: a resumed session's entries continue its chain, as the CLI's do (a second resume then
# keeps the history): the first one's parent is the cut (--resume-session-at, found), else the
# --resume transcript's last user or assistant entry that is no sidechain's (none there: null).
# The shim answers park and unpark (S10), never the fake.

# The remote link's knobs (see above), before anything reads one.
case $0 in
  */*)
    if [ -f "$0.knobs" ]; then
      . "$0.knobs"
    fi
    ;;
esac

if [ "$#" -eq 1 ] && [ "$1" = "--version" ]; then
  printf '%s (Claude Code)\n' "${FAKE_VERSION:-2.1.302}"
  exit 0
fi

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
cut_at=""
session_flag=""
continued=0
fork_session=0
expect=""
session_mirror=0
if [ -n "${ARGV_LOG:-}" ]; then
  printf -- '--- gen %s\n' "$gen" >> "$ARGV_LOG"
fi
for a in "$@"; do
  if [ -n "${ARGV_LOG:-}" ]; then
    printf '%s\n' "$a" >> "$ARGV_LOG"
  fi
  # The value of the flag before it (S10: --resume-session-at and --session-id take one too).
  case "$expect" in
    resume) resume=$a ;;
    cut) cut_at=$a ;;
    session) session_flag=$a ;;
  esac
  expect=""
  case "$a" in
    --resume=*) resume=${a#--resume=} ;;
    --resume|-r) expect=resume ;;
    --continue|-c) continued=1 ;;
    --fork-session) fork_session=1 ;;
    --resume-session-at=*) cut_at=${a#--resume-session-at=} ;;
    --resume-session-at) expect=cut ;;
    --session-id=*) session_flag=${a#--session-id=} ;;
    --session-id) expect=session ;;
    --session-mirror) session_mirror=1 ;;
  esac
done

if [ -n "${FAKE_ENV_DUMP:-}" ]; then
  knob_names=""
  case $0 in
    */*)
      if [ -f "$0.knobs" ]; then
        knob_names=$(sed -n 's/^export \([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p' "$0.knobs")
      fi
      ;;
  esac
  printf -- '--- gen %s\n' "$gen" >> "$FAKE_ENV_DUMP"
  env | LC_ALL=C sort | while IFS= read -r kv; do
    name=${kv%%=*}
    case "$name" in
      PWD|SHLVL|OLDPWD|_) continue ;;
    esac
    knob=0
    for k in $knob_names; do
      if [ "$k" = "$name" ]; then knob=1; fi
    done
    if [ "$knob" = "0" ]; then
      printf '%s\n' "$kv" >> "$FAKE_ENV_DUMP"
    fi
  done
fi

if [ -n "${FAKE_ENV_LOG:-}" ]; then
  if [ -n "${CLAUDE_CONFIG_DIR+x}" ]; then ccd=$CLAUDE_CONFIG_DIR; else ccd=unset; fi
  if [ -n "${CLAUDE_SECURESTORAGE_CONFIG_DIR+x}" ]; then ss=present; else ss=absent; fi
  printf 'gen %s CLAUDE_CONFIG_DIR=%s SECURESTORAGE=%s pid=%s\n' "$gen" "$ccd" "$ss" "$$" >> "$FAKE_ENV_LOG"
fi
if [ -n "${FAKE_ENV_NAMES_LOG:-}" ]; then
  if [ -n "${CLAUDE_CODE_ENTRYPOINT+x}" ]; then ep=$CLAUDE_CODE_ENTRYPOINT; else ep=unset; fi
  names=$(env | sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p' | LC_ALL=C sort | tr '\n' ',')
  printf 'gen %s CLAUDE_CODE_ENTRYPOINT=%s names=%s\n' "$gen" "$ep" "${names%,}" >> "$FAKE_ENV_NAMES_LOG"
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
if [ -n "$session_flag" ]; then
  # S10: --session-id names the session.
  sid=$session_flag
elif [ -n "${FAKE_SESSION_ID:-}" ]; then
  sid=$FAKE_SESSION_ID
elif [ -n "$resume" ] && [ "$fork_session" = "1" ]; then
  # S10: a fork of the resumed session, under an id of its own.
  sid=$(printf '%08x-0000-4000-f000-%012x' "$gen" "$gen")
elif [ -n "$resume" ]; then
  sid=$resume
elif [ "$gen" -gt 1 ]; then
  # A later process on the counter: a fresh CLI's id of its own.
  own=$((3054 + 65536 * gen))
  sid=$(printf '%08x-0000-4000-8000-%012x' "$own" "$own")
else
  sid=$fixed_sid
fi

# The cwd the frames report and its slug; the config dir the transcript lives
# in, and the one the mirror frames name.
cwd=${FAKE_CWD:-$(pwd)}
slug=$(printf '%s\n' "$cwd" | LC_ALL=en_US.UTF-8 sed 's/[^ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789]/-/g')
config_dir=${CLAUDE_CONFIG_DIR:-$HOME/.claude}
shown_config_dir=${FAKE_CONFIG_DIR:-$config_dir}

# S10: --session-id starts a session under that id, which the CLI refuses
# beside a resume or a continue that forks nothing, and once that session's
# transcript exists: before anything else is checked, so a refused argv
# never reaches a resume or cut miss (nothing on stdout).
if [ -n "$session_flag" ]; then
  if [ -n "${FAKE_ENV_LOG:-}" ]; then
    printf 'gen %s session-id=%s\n' "$gen" "$session_flag" >> "$FAKE_ENV_LOG"
  fi
  if { [ -n "$resume" ] || [ "$continued" = "1" ]; } && [ "$fork_session" != "1" ]; then
    printf 'Error: --session-id can only be used with --continue or --resume if --fork-session is also specified.\n' >&2
    exit 1
  fi
  if [ -f "$config_dir/projects/$slug/$session_flag.jsonl" ]; then
    printf 'Error: Session ID %s is already in use.\n' "$session_flag" >&2
    exit 1
  fi
fi

# S10: a fork of the --resume session (--fork-session): X, whose history its
# transcript starts from (fork_history, at its first write).
forked_from=""
if [ -n "$resume" ] && [ "$fork_session" = "1" ]; then
  forked_from=$resume
  if [ -n "${FAKE_ENV_LOG:-}" ]; then
    printf 'gen %s forked from=%s\n' "$gen" "$forked_from" >> "$FAKE_ENV_LOG"
  fi
fi

# Wait `$1` ms in a background sleep, so a trapped TERM interrupts the wait.
sleep_ms() {
  sleep "$(($1 / 1000)).$(printf '%03d' $(($1 % 1000)))" </dev/null >/dev/null 2>&1 &
  sleeper=$!
  wait "$sleeper"
  sleeper=""
}

pad=""
if [ -n "${FAKE_STREAM_PAD:-}" ]; then
  pad=$(printf "%${FAKE_STREAM_PAD}s" '' | tr ' ' x)
fi

# The CLI's print-path failure in stream-json mode, $1 its text: the stderr
# line, then one error_during_execution result on stdout carrying it, then
# exit 1. The resume miss, and (S10) the cut miss.
print_miss() {
  printf '%s\n' "$1" >&2
  printf '{"type":"result","subtype":"error_during_execution","duration_ms":0,"duration_api_ms":0,"is_error":true,"num_turns":0,"stop_reason":null,"session_id":"%s","total_cost_usd":0,"usage":{},"modelUsage":{},"permission_denials":[],"uuid":"x","errors":["%s"],"result_index":0}\n' "$other_sid" "$1"
  if [ -n "${FAKE_MISS_EXIT_DELAY_MS:-}" ]; then
    sleep "$((FAKE_MISS_EXIT_DELAY_MS / 1000)).$(printf '%03d' $((FAKE_MISS_EXIT_DELAY_MS % 1000)))"
  fi
  exit 1
}
resume_miss() {
  print_miss "No conversation found with session ID: $resume"
}
# S10: --resume-session-at named no message of the transcript.
cut_miss() {
  print_miss "No message found with message.uuid of: $cut_at"
}

# The miss that comes after initialize is answered (FAKE_RESUME_FAIL_AFTER_ACK): its function, none when empty.
fail_after_ack=""
if [ -n "${FAKE_RESUME_FAIL_ONCE:-}" ] && [ -n "$resume" ] && [ ! -e "$FAKE_RESUME_FAIL_ONCE" ]; then
  : > "$FAKE_RESUME_FAIL_ONCE"
  if [ "${FAKE_RESUME_FAIL_AFTER_ACK:-0}" = "1" ]; then
    fail_after_ack=resume_miss
  else
    resume_miss
  fi
fi

# A resume finds its transcript on this disk, or misses (the remote link's
# upload before the spawn is what puts it there).
if [ "${FAKE_RESUME_NEEDS_FILE:-0}" = "1" ] && [ -n "$resume" ]; then
  resumed="$config_dir/projects/$slug/$resume.jsonl"
  if [ -f "$resumed" ]; then
    lines=$(wc -l < "$resumed" | tr -d ' ')
  else
    lines=missing
  fi
  if [ -n "${FAKE_ENV_LOG:-}" ]; then
    printf 'gen %s resumed lines=%s\n' "$gen" "$lines" >> "$FAKE_ENV_LOG"
  fi
  if [ "$lines" = "missing" ]; then
    if [ "${FAKE_RESUME_FAIL_AFTER_ACK:-0}" = "1" ]; then
      fail_after_ack=resume_miss
    else
      resume_miss
    fi
  fi
fi

# S10: the cut (--resume-session-at), a message of the --resume transcript or
# not. Found, this process's entries chain from it, as the CLI's do from the
# message it resumed at; missing, the cut miss where the transcript must be
# on this disk, at the resume miss's moment.
cut_parent=""
if [ -n "$cut_at" ]; then
  cut_found=missing
  if [ -n "$resume" ] && grep -qF "\"uuid\":\"$cut_at\"" "$config_dir/projects/$slug/$resume.jsonl" 2>/dev/null; then
    cut_found=found
    cut_parent=$cut_at
  fi
  if [ -n "${FAKE_ENV_LOG:-}" ]; then
    printf 'gen %s cut at=%s %s\n' "$gen" "$cut_at" "$cut_found" >> "$FAKE_ENV_LOG"
  fi
  if [ "$cut_found" = "missing" ] && [ "${FAKE_RESUME_NEEDS_FILE:-0}" = "1" ] && [ -n "$resume" ] && [ -z "$fail_after_ack" ]; then
    if [ "${FAKE_RESUME_FAIL_AFTER_ACK:-0}" = "1" ]; then
      fail_after_ack=cut_miss
    else
      cut_miss
    fi
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
  printf '{"type":"system","subtype":"init","session_id":"%s","cwd":"%s","uuid":"init-%s"}\n' "$sid" "$cwd" "$gen"
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
      if [ -n "$fail_after_ack" ]; then
        if [ -n "${FAKE_MISS_DELAY_MS:-}" ]; then
          sleep "$((FAKE_MISS_DELAY_MS / 1000)).$(printf '%03d' $((FAKE_MISS_DELAY_MS % 1000)))"
        fi
        "$fail_after_ack"
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

# The transcript file of the current session, and the path a mirror frame names for it.
transcript() {
  printf '%s/projects/%s/%s.jsonl' "$config_dir" "$slug" "$sid"
}
shown_transcript() {
  printf '%s/projects/%s/%s.jsonl' "$shown_config_dir" "$slug" "$sid"
}

# The user and assistant lines of transcript $1 that are no sidechain's
# (none when it is missing): what a resume continues, and what a fork copies.
chain_lines() {
  grep -E '"type":"(user|assistant)"' "$1" 2>/dev/null | grep -v '"isSidechain":true'
}

# FAKE_WRITE_TRANSCRIPT: a turn's entries appended to the transcript as the
# CLI appends them, and with --session-mirror the frame that carries each
# write's. A turn with no tool writes its user entry and its reply at its
# end; one with a tool (S10) its user entry and the tool_use as the tool
# starts, its tool_result and its reply at its end. The first parent: a cut
# found (--resume-session-at), else (S10) the --resume transcript's last
# user or assistant entry, as the CLI continues the resumed chain; none, null.
last_entry=$cut_parent
if [ -z "$last_entry" ] && [ -n "$resume" ]; then
  last_entry=$(chain_lines "$config_dir/projects/$slug/$resume.jsonl" | sed -n -E 's/.*"uuid":"([^"]*)".*/\1/p' | tail -n 1)
fi

# S10: a fork's first write (--fork-session, its transcript not there yet):
# the --resume transcript's user and assistant lines start the fork's own,
# with --session-mirror in one frame of their own. This fake's model of the
# CLI's copy (part B records it); X's file is left as it is.
fork_history() {
  if [ -z "$forked_from" ] || [ -e "$1" ]; then
    return
  fi
  copied=$(chain_lines "$config_dir/projects/$slug/$forked_from.jsonl")
  if [ -z "$copied" ]; then
    return
  fi
  printf '%s\n' "$copied" > "$1"
  if [ "$session_mirror" = "1" ]; then
    joined=$(printf '%s\n' "$copied" | tr '\n' ',')
    printf '{"type":"transcript_mirror","filePath":"%s","entries":[%s]}\n' "$(shown_transcript)" "${joined%,}"
  fi
}

# Append entries $1 and $2 to the transcript, with FAKE_API_REQUEST the
# api-request lines between them when $1 is the turn's user entry ($3 1),
# and send their mirror frame.
write_entries() {
  file=$(transcript)
  mkdir -p "${file%/*}"
  fork_history "$file"
  if [ "$3" = "1" ] && [ "${FAKE_API_REQUEST:-1}" = "1" ]; then
    rq="req_fake_${turns}_${gen}"
    rr=$(printf '{"type":"api-request","requestId":"%s","sessionId":"%s","timestamp":"2026-10-17T00:00:00.000Z"}' "$rq" "$sid")
    rb=$(printf '{"type":"api-request-blob","requestId":"%s","blob":"ZmFrZQ=="}' "$rq")
    printf '%s\n%s\n%s\n%s\n' "$1" "$rr" "$rb" "$2" >> "$file"
  else
    printf '%s\n%s\n' "$1" "$2" >> "$file"
  fi
  if [ "$session_mirror" = "1" ]; then
    printf '{"type":"transcript_mirror","filePath":"%s","entries":[%s,%s]}\n' "$(shown_transcript)" "$1" "$2"
  fi
}

# This turn's user entry, chained to the last entry written.
user_entry() {
  if [ -n "$last_entry" ]; then
    parent="\"$last_entry\""
  else
    parent=null
  fi
  printf '{"parentUuid":%s,"isSidechain":false,"type":"user","message":{"role":"user","content":"turn %s"},"uuid":"%s","sessionId":"%s","cwd":"%s"}' "$parent" "$turns" "$uu" "$sid" "$cwd"
}

# S10: a tool turn's first write, as the tool starts: its user entry and the tool_use.
write_tool_start() {
  ue=$(user_entry)
  be=$(printf '{"parentUuid":"%s","isSidechain":false,"type":"assistant","message":{"role":"assistant","content":[%s]},"uuid":"%s","sessionId":"%s","cwd":"%s"}' "$uu" "$tool_block" "$bu" "$sid" "$cwd")
  last_entry=$bu
  write_entries "$ue" "$be" 1
}

# The turn's end: its tool_result and its reply after a tool, else its user entry and its reply.
write_transcript() {
  if [ -n "$tool" ]; then
    te=$(printf '{"parentUuid":"%s","isSidechain":false,"type":"user","message":{"role":"user","content":[%s]},"uuid":"%s","sessionId":"%s","cwd":"%s"}' "$bu" "$result_block" "$cu" "$sid" "$cwd")
    ae=$(printf '{"parentUuid":"%s","isSidechain":false,"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"ok"}]},"uuid":"%s","sessionId":"%s","cwd":"%s"}' "$cu" "$au" "$sid" "$cwd")
    last_entry=$au
    write_entries "$te" "$ae" 0
  else
    ue=$(user_entry)
    ae=$(printf '{"parentUuid":"%s","isSidechain":false,"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"ok"}]},"uuid":"%s","sessionId":"%s","cwd":"%s"}' "$uu" "$au" "$sid" "$cwd")
    last_entry=$au
    write_entries "$ue" "$ae" 1
  fi
}

# FAKE_FINAL_MIRROR_MS: the last mirror frame, after stdin EOF.
final_mirror() {
  if [ -n "$last_entry" ]; then
    leaf="\"$last_entry\""
  else
    leaf=null
  fi
  fe=$(printf '{"type":"summary","summary":"fake final entry","leafUuid":%s}' "$leaf")
  if [ "${FAKE_WRITE_TRANSCRIPT:-0}" = "1" ]; then
    file=$(transcript)
    mkdir -p "${file%/*}"
    fork_history "$file"
    printf '%s\n' "$fe" >> "$file"
  fi
  printf '{"type":"transcript_mirror","filePath":"%s","entries":[%s]}\n' "$(shown_transcript)" "$fe"
}

# S10: FAKE_SUBAGENTS, this turn's subagent transcripts in the session's subtree.
write_subagents() {
  subdir="$config_dir/projects/$slug/$sid/subagents"
  mkdir -p "$subdir"
  k=1
  while [ "$k" -le "$FAKE_SUBAGENTS" ]; do
    agent="$gen-$turns-$k"
    su=$(printf '%08x-%04x-4000-d000-%012x' "$turns" "$k" "$gen")
    sa=$(printf '%08x-%04x-4000-e000-%012x' "$turns" "$k" "$gen")
    {
      printf '{"parentUuid":null,"isSidechain":true,"type":"user","message":{"role":"user","content":"subagent %s"},"uuid":"%s","sessionId":"%s","agentId":"%s","cwd":"%s"}\n' "$agent" "$su" "$sid" "$agent" "$cwd"
      printf '{"parentUuid":"%s","isSidechain":true,"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"ok"}]},"uuid":"%s","sessionId":"%s","agentId":"%s","cwd":"%s"}\n' "$su" "$sa" "$sid" "$agent" "$cwd"
    } > "$subdir/agent-$agent.jsonl"
    k=$((k + 1))
  done
}

# S10: FAKE_SUBTREE_LOG, the files the session's subagents directory holds as the turn starts.
log_subtree() {
  subs=0
  for f in "$config_dir/projects/$slug/$sid/subagents"/*; do
    if [ -f "$f" ]; then
      subs=$((subs + 1))
    fi
  done
  if [ -n "${FAKE_ENV_LOG:-}" ]; then
    printf 'gen %s turn %s subagents=%s\n' "$gen" "$turns" "$subs" >> "$FAKE_ENV_LOG"
  fi
}

# What a turn does besides its frames, before its result (the per-result
# code-out finds it there): FAKE_EDIT, FAKE_WRITE_SETTINGS, FAKE_COMMIT,
# FAKE_WIP_EDIT and (S10) FAKE_SUBAGENTS, the tool's effects, which a denied
# FAKE_ASK never has; then the transcript, the rate limit line. Nothing of
# git's reaches stdout.
turn_effects() {
  if [ "$outcome" = "allow" ]; then
    if [ -n "${FAKE_EDIT:-}" ]; then
      rel=${FAKE_EDIT%%:*}
      case "$rel" in
        */*) mkdir -p "${rel%/*}" ;;
      esac
      printf '%s\n' "${FAKE_EDIT#*:}" > "$rel"
    fi
    if [ -n "${FAKE_WRITE_SETTINGS:-}" ]; then
      case "$FAKE_WRITE_SETTINGS" in
        local:*) where=local; json=${FAKE_WRITE_SETTINGS#local:} ;;
        user:*) where=user; json=${FAKE_WRITE_SETTINGS#user:} ;;
        both:*) where=both; json=${FAKE_WRITE_SETTINGS#both:} ;;
        *) where=local; json=$FAKE_WRITE_SETTINGS ;;
      esac
      if [ "$where" != "user" ]; then
        mkdir -p .claude
        printf '%s\n' "$json" > .claude/settings.local.json
      fi
      if [ "$where" != "local" ]; then
        mkdir -p "$config_dir"
        printf '%s\n' "$json" > "$config_dir/settings.json"
      fi
    fi
    if [ -n "${FAKE_COMMIT:-}" ]; then
      if ! { git add -A && git -c user.name=claude-agent -c user.email=claude-agent@ai-env.invalid -c commit.gpgsign=false -c core.hooksPath=/dev/null commit -q --allow-empty -m "$FAKE_COMMIT"; } >/dev/null 2>&1; then
        printf 'fake claude: FAKE_COMMIT: git commit failed in %s\n' "$(pwd)" >&2
      fi
    fi
    if [ -n "${FAKE_WIP_EDIT:-}" ]; then
      rel=${FAKE_WIP_EDIT%%:*}
      case "$rel" in
        */*) mkdir -p "${rel%/*}" ;;
      esac
      printf '%s\n' "${FAKE_WIP_EDIT#*:}" > "$rel"
    fi
    if [ -n "${FAKE_SUBAGENTS:-}" ]; then
      write_subagents
    fi
  fi
  if [ "${FAKE_WRITE_TRANSCRIPT:-0}" = "1" ]; then
    write_transcript
  fi
  if [ "${FAKE_RATE_LIMIT_EVENT:-0}" = "1" ]; then
    printf '%s\n' '{"type":"rate_limit_event","rate_limit_info":{"status":"allowed"}}'
  fi
}

# Every stdin line to FAKE_STDIN_LOG, as "<gen><TAB><line>".
log_stdin() {
  if [ -n "${FAKE_STDIN_LOG:-}" ]; then
    printf '%s\t%s\n' "$gen" "$1" >> "$FAKE_STDIN_LOG"
  fi
}

# $1 as the text of a JSON string: backslashes and double quotes escaped (the
# tests' texts hold no control character).
json_text() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

# S10: FAKE_ASK, the turn's tool asked for (perm-<gen>-<turn>), then the turn
# held until the host answers it (outcome allow, deny or error, logged),
# interrupts it (interrupt) or ends stdin (eof). Every line read is logged,
# control requests are answered, user lines queued for after the turn.
ask_permission() {
  perm="perm-$gen-$turns"
  printf '{"type":"control_request","request_id":"%s","request":{"subtype":"can_use_tool","tool_name":"%s","input":%s,"tool_use_id":"%s","permission_suggestions":[]}}\n' "$perm" "$tool_name" "$tool_input" "$tid"
  outcome=""
  while [ -z "$outcome" ]; do
    held=""
    if ! IFS= read -r held && [ -z "$held" ]; then
      outcome=eof
      return
    fi
    log_stdin "$held"
    case "$held" in
      *'"type":"control_response"'*)
        case "$held" in
          *"\"request_id\":\"$perm\""*)
            case "$held" in
              *'"subtype":"error"'*) outcome=error ;;
              *'"behavior":"allow"'*) outcome=allow ;;
              *'"behavior":"deny"'*) outcome=deny ;;
              *) outcome=error ;;
            esac
            if [ -n "${FAKE_PERMISSION_LOG:-}" ]; then
              printf 'gen %s turn %s %s %s\n' "$gen" "$turns" "$perm" "$outcome" >> "$FAKE_PERMISSION_LOG"
            fi
            ;;
        esac
        ;;
      *'"type":"control_request"'*)
        on_control_request "$held"
        case "$held" in
          *'"subtype":"interrupt"'*) outcome=interrupt ;;
        esac
        ;;
      *'"type":"user"'*) queued="$queued$held$nl" ;;
    esac
  done
}

# S10: the turn's tool: its tool_use frame (with FAKE_WRITE_TRANSCRIPT the
# turn's first entries), FAKE_ASK's prompt, then, allowed, FAKE_TURN_MS's
# run and the tool's result; denied or answered with an error, an error
# result; interrupted or at stdin's end, none.
run_tool() {
  tid="toolu_fake_${gen}_${turns}"
  tool_block=$(printf '{"type":"tool_use","id":"%s","name":"%s","input":%s}' "$tid" "$tool_name" "$tool_input")
  printf '{"type":"assistant","message":{"content":[%s]},"parent_tool_use_id":null,"session_id":"%s","uuid":"%s"}\n' "$tool_block" "$sid" "$bu"
  if [ "${FAKE_WRITE_TRANSCRIPT:-0}" = "1" ]; then
    write_tool_start
  fi
  if [ "$asked" = "1" ]; then
    ask_permission
  fi
  case "$outcome" in
    allow)
      if [ -n "${FAKE_TURN_MS:-}" ]; then
        if [ -n "${FAKE_TURN_MARK:-}" ]; then
          printf 'gen %s turn %s\n' "$gen" "$turns" >> "$FAKE_TURN_MARK"
        fi
        sleep_ms "$FAKE_TURN_MS"
      fi
      text=ok
      if [ "$asked" = "1" ]; then
        text=${FAKE_ASK_RESULT:-ok}
      fi
      result_block=$(printf '{"tool_use_id":"%s","type":"tool_result","content":"%s"}' "$tid" "$(json_text "$text")")
      ;;
    deny|error)
      result_block=$(printf '{"tool_use_id":"%s","type":"tool_result","content":"not allowed: %s","is_error":true}' "$tid" "$outcome")
      ;;
    *)
      return
      ;;
  esac
  printf '{"type":"user","message":{"role":"user","content":[%s]},"parent_tool_use_id":null,"session_id":"%s","uuid":"%s"}\n' "$result_block" "$sid" "$cu"
}

# Whether a transcript this process writes into holds an entry with uuid $1:
# the session's own, and a fork's --resume one, whose lines it copies.
holds_uuid() {
  if grep -qF "\"uuid\":\"$1\"" "$(transcript)" 2>/dev/null; then
    return 0
  fi
  [ -n "$forked_from" ] && grep -qF "\"uuid\":\"$1\"" "$config_dir/projects/$slug/$forked_from.jsonl" 2>/dev/null
}

# S10: this turn's uuid of kind $1 (9000, a000, b000, c000):
# <turn, %08x>-0000-4000-<$1>-<k, %04x><gen, %08x>, k 0 (the header's
# <gen, %012x>), else, with FAKE_WRITE_TRANSCRIPT, the first k whose uuid
# that transcript does not hold yet. The CLI's uuids never repeat; this
# fake's would where a process of the same generation (another rig's, or
# one with no FAKE_SPAWN_COUNT) writes into a chat an earlier one wrote,
# and two entries of one uuid in a continued chain leave it no leaf.
own_uuid() {
  uuid_k=0
  while :; do
    uuid_try=$(printf '%08x-0000-4000-%s-%04x%08x' "$turns" "$1" "$uuid_k" "$gen")
    if [ "${FAKE_WRITE_TRANSCRIPT:-0}" != "1" ] || ! holds_uuid "$uuid_try"; then
      printf '%s' "$uuid_try"
      return
    fi
    uuid_k=$((uuid_k + 1))
  done
}

turns=0
# S10: whether a turn may ask (FAKE_ASK): not one a held turn queued.
asking=1
# S10: the user lines a held turn queued, each ended by a newline.
queued=""
nl='
'
# S10: how the last turn's tool fared: allow (a turn with no tool too), deny, error, interrupt or eof.
outcome=allow
on_user() {
  clearing=0
  if [ -n "${FAKE_NEW_SESSION_AFTER:-}" ] && [ "$((turns + 1))" -eq $((FAKE_NEW_SESSION_AFTER + 1)) ]; then
    clearing=1
  fi
  if [ "${FAKE_INIT_AT_TURN:-0}" = "1" ]; then
    if [ "$init_done" = "0" ]; then
      emit_init
    elif [ "$clearing" = "0" ]; then
      # Every later turn's own init, the session's id again (a `/clear` turn's is the new session's, below).
      printf '{"type":"system","subtype":"init","session_id":"%s","cwd":"%s","uuid":"init-%s-%s"}\n' "$sid" "$cwd" "$gen" "$((turns + 1))"
    fi
  fi
  turns=$((turns + 1))
  if [ "$clearing" = "1" ]; then
    sid=$clear_sid
    printf '{"type":"system","subtype":"init","session_id":"%s","cwd":"%s","uuid":"init-%s-clear"}\n' "$sid" "$cwd" "$gen"
  fi
  u=$(printf '%s\n' "$1" | sed -n -E 's/.*"uuid":"([^"]*)".*/\1/p')
  # The turn's ids: its user entry's (the line's uuid, else one of its own),
  # its reply's and (S10) a tool's tool_use and tool_result.
  uu=$u
  if [ -z "$uu" ]; then
    uu=$(own_uuid 9000)
  fi
  au=$(own_uuid a000)
  bu=$(own_uuid b000)
  cu=$(own_uuid c000)
  if [ "${FAKE_SUBTREE_LOG:-0}" = "1" ]; then
    log_subtree
  fi
  if [ -n "$u" ]; then
    printf '{"type":"user","message":{"role":"user","content":"echo"},"session_id":"%s","parent_tool_use_id":null,"uuid":"%s","isReplay":true}\n' "$sid" "$u"
  fi
  # S10: the turn's tool, FAKE_ASK's in its turn, else FAKE_TURN_MS's long Bash run.
  tool=""
  asked=0
  outcome=allow
  if [ -n "${FAKE_ASK:-}" ] && [ "$asking" = "1" ] && [ "$turns" -eq "${FAKE_ASK_TURN:-1}" ]; then
    asked=1
    tool_name=$(json_text "${FAKE_ASK%%:*}")
    case "$FAKE_ASK" in
      *:*) tool_input=$(printf '{"command":"%s"}' "$(json_text "${FAKE_ASK#*:}")") ;;
      *) tool_input='{}' ;;
    esac
    tool=$tool_name
  elif [ -n "${FAKE_TURN_MS:-}" ]; then
    tool_name=Bash
    tool_input='{"command":"sleep"}'
    tool=$tool_name
  fi
  if [ -n "$tool" ]; then
    run_tool
    case "$outcome" in
      eof)
        return
        ;;
      interrupt)
        # The CLI withdraws its prompt, then ends the turn.
        printf '{"type":"control_cancel_request","request_id":"%s"}\n' "$perm"
        if [ -n "$u" ]; then
          printf '{"type":"result","subtype":"error_during_execution","is_error":true,"num_turns":1,"session_id":"%s","user_message_uuid":"%s","user_message_uuids":["%s"],"errors":["interrupted"]}\n' "$sid" "$u" "$u"
        else
          printf '{"type":"result","subtype":"error_during_execution","is_error":true,"num_turns":1,"session_id":"%s","errors":["interrupted"]}\n' "$sid"
        fi
        return
        ;;
    esac
  fi
  printf '{"type":"assistant","message":{"content":[{"type":"text","text":"ok"}]},"parent_tool_use_id":null,"session_id":"%s","uuid":"%s"}\n' "$sid" "$au"
  turn_effects
  if [ -n "$u" ]; then
    printf '{"type":"result","subtype":"success","is_error":false,"num_turns":1,"session_id":"%s","user_message_uuid":"%s","user_message_uuids":["%s"]}\n' "$sid" "$u" "$u"
  else
    printf '{"type":"result","subtype":"success","is_error":false,"num_turns":1,"session_id":"%s"}\n' "$sid"
  fi
}

# S10: the user lines a held turn queued, each a turn of its own after it, asking nothing.
run_queued() {
  while [ -n "$queued" ]; do
    next=${queued%%"$nl"*}
    queued=${queued#*"$nl"}
    asking=0
    on_user "$next"
    asking=1
  done
}

if [ "${FAKE_ONBOARDING:-0}" = "1" ]; then
  printf 'fake claude: onboarding (FAKE_ONBOARDING): waiting for an answer on a terminal; nothing is answered\n' >&2
  while IFS= read -r line || [ -n "$line" ]; do
    if [ -n "${FAKE_STDIN_LOG:-}" ]; then
      printf '%s\t%s\n' "$gen" "$line" >> "$FAKE_STDIN_LOG"
    fi
    line=""
  done
  exit 1
fi

while IFS= read -r line || [ -n "$line" ]; do
  log_stdin "$line"
  case "$line" in
    *'"type":"control_request"'*) on_control_request "$line" ;;
    *'"type":"user"'*)
      on_user "$line"
      if [ "$outcome" != "eof" ]; then
        run_queued
      fi
      ;;
    *) : ;;
  esac
  line=""
done

if [ -n "$streamer" ]; then
  wait "$streamer"
fi
# After stdin EOF: the last mirror frame, then the rest of the exit's delay.
waited=0
if [ -n "${FAKE_FINAL_MIRROR_MS:-}" ]; then
  sleep_ms "$FAKE_FINAL_MIRROR_MS"
  waited=$FAKE_FINAL_MIRROR_MS
  final_mirror
fi
if [ -n "${FAKE_EXIT_DELAY_MS:-}" ] && [ "$FAKE_EXIT_DELAY_MS" -gt "$waited" ]; then
  sleep_ms $((FAKE_EXIT_DELAY_MS - waited))
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
