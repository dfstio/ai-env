#!/bin/sh
# The fake claude of `ai-env creds account check` (A1, tests/accounts_check.rs):
# one `-p` turn in stream-json, as claude 2.1.305 prints it for each outcome the
# check judges. The check clears its environment (PATH, HOME, CLAUDE_CONFIG_DIR,
# DISABLE_AUTOUPDATER, TZ and the token's variable only), so nothing steers this
# fake through it: what it needs lies beside it, in its own directory.
#   --version   prints `2.1.305 (Claude Code)`
#   a turn      reads the token from fd 3 (CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR=3)
#               or from CLAUDE_CODE_OAUTH_TOKEN, and appends to `claude.log` beside
#               it: `pid <pid>`, `argv` and each word bracketed, `env` and the
#               names of its environment (never a value), `token` and how it came
#               (fd or env) and the first 8 hex digits of its sha256: never the
#               token. Its tail picks the outcome:
#     ok        the init line, a reply, a rate_limit_event (`rate_limit_info.json`
#               beside it when there is one, else one with both unified windows,
#               5h 23% and 7d 81%), the answered result; exit 0
#     limited   a `rejected` rate_limit_event (seven_day, resetting in 3 days),
#               then B2's usage-limit result (api_error usage_limit_reached,
#               429, its keys alphabetical); exit 1
#     refused   B7's lines (`refused.jsonl` beside it: two api_retry 401s, the
#               <synthetic> reply, the result with api_error_status 401); exit 1
#     hang      the init line, then waits to be ended
#     noresult  the init line, then exit 0 with no result
set -u
here=$(dirname "$0")
log="$here/claude.log"
if [ "${1:-}" = --version ]; then
  echo "2.1.305 (Claude Code)"
  exit 0
fi
if [ "${CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR:-}" = 3 ]; then
  tok=$(cat <&3)
  how=fd
else
  tok=${CLAUDE_CODE_OAUTH_TOKEN:-}
  how=env
fi
sha=$(printf '%s' "$tok" | shasum -a 256 | cut -c1-8)
{
  printf 'pid %s\n' "$$"
  printf 'argv'
  for a in "$@"; do printf ' [%s]' "$a"; done
  printf '\n'
  printf 'env %s\n' "$(env | cut -d= -f1 | sort | tr '\n' ' ')"
  printf 'token %s %s\n' "$how" "$sha"
} >> "$log"
now=$(date +%s)
init='{"type":"system","subtype":"init","session_id":"0a403528-1afc-4bdf-97a7-d9a67c42d89a","tools":[],"model":"claude-haiku-4-5","claude_code_version":"2.1.305"}'
case "$tok" in
  *ok)
    printf '%s\n' "$init"
    printf '%s\n' '{"type":"assistant","message":{"model":"claude-haiku-4-5","id":"msg_01","type":"message","role":"assistant","content":[{"type":"text","text":"OK"}]},"parent_tool_use_id":null,"session_id":"0a403528-1afc-4bdf-97a7-d9a67c42d89a"}'
    if [ -f "$here/rate_limit_info.json" ]; then
      info=$(cat "$here/rate_limit_info.json")
    else
      info="{\"status\":\"allowed\",\"unifiedWindows\":{\"five_hour\":{\"utilization\":0.23,\"resetsAt\":$((now + 7200))},\"seven_day\":{\"utilization\":0.81,\"resetsAt\":$((now + 259200))}}}"
    fi
    printf '{"type":"rate_limit_event","rate_limit_info":%s,"uuid":"5e1b0c2e-0000-4000-8000-000000000001","session_id":"0a403528-1afc-4bdf-97a7-d9a67c42d89a"}\n' "$info"
    printf '%s\n' '{"type":"result","subtype":"success","is_error":false,"duration_ms":912,"num_turns":1,"result":"OK","session_id":"0a403528-1afc-4bdf-97a7-d9a67c42d89a"}'
    exit 0 ;;
  *limited)
    printf '%s\n' "$init"
    printf '{"type":"rate_limit_event","rate_limit_info":{"status":"rejected","rateLimitType":"seven_day","resetsAt":%s},"uuid":"5e1b0c2e-0000-4000-8000-000000000002","session_id":"0a403528-1afc-4bdf-97a7-d9a67c42d89a"}\n' "$((now + 259200))"
    printf '%s\n' '{"api_error":"usage_limit_reached","api_error_status":429,"duration_api_ms":0,"duration_ms":1361,"is_error":true,"num_turns":1,"result":"You'"'"'ve hit your weekly limit · resets 10am (UTC)","session_id":"0a403528-1afc-4bdf-97a7-d9a67c42d89a","subtype":"success","type":"result"}'
    exit 1 ;;
  *refused)
    cat "$here/refused.jsonl"
    exit 1 ;;
  *hang)
    printf '%s\n' "$init"
    while : ; do sleep 1; done ;;
  *noresult)
    printf '%s\n' "$init"
    exit 0 ;;
esac
echo "fake claude: no outcome for this token's tail" >&2
exit 2
