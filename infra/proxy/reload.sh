#!/bin/bash
# ai-env-proxy-reload (S5): the proxy's only config path (boot unit; `ai-env
# egress reload` via SSM). Fetches the 4 parameters, validates every byte and
# line, stages the lists in /etc/squid/ai-env/<hash> (@DIR@), parses, renames
# squid.conf in last; reconfigures squid, or restarts it (tunnels close) when
# a host left or squid.conf changed; unconfirmed, the old set returns.
# --if-changed, --status, exits 0-3: contract 4. No value is logged.
set -euo pipefail
export LC_ALL=C AWS_PAGER="" PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 022

SELF=ai-env-proxy-reload
LIST_DIR=/etc/squid/ai-env
CONF=/etc/squid/squid.conf
PREV=/etc/squid/.squid.conf.prev
CACHE_LOG=/var/log/squid/cache.log
STATE=/var/lib/ai-env-proxy
APPLIED=$STATE/applied
PENDING=$STATE/pending
LOCK=/run/ai-env-proxy-reload.lock
PARAMS=(squid.conf allow extras suspended)
LISTS=(allow extras suspended)
TAB=$(printf '\t')
# \$ in double quotes: a dollar before a quote is special to JS replace().
HOST_RE="^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?[.])+[a-z]([a-z0-9-]{0,61}[a-z0-9])?\$"
SLUG_RE="^[A-Za-z0-9._-]{1,64}\$"
PREFIX_RE="^(/[A-Za-z0-9_.-]+)+\$"
REGION_RE="^[a-z]{2}(-[a-z]+)+-[0-9]+\$"
NS_RE="^dns_nameservers( ([0-9]{1,3}[.]){3}[0-9]{1,3}| [0-9a-f]*:[0-9a-f:]*)+\$"
VMS_RE="^acl vms src( [0-9a-f.:/]+)+\$"
OK_WARN="WARNING: (empty ACL: acl (allowed|extras|suspended) dstdomain|HTTP requires the use of Via)"
SYSTEMD=0
[ ! -d /run/systemd/system ] || SYSTEMD=1
JOURNAL=1
[ -z "${JOURNAL_STREAM:-}" ] || [ "$(stat -L -c '%d:%i' /proc/self/fd/2 || true)" != "$JOURNAL_STREAM" ] || JOURNAL=0

log() {
  printf '%s: %s\n' "$SELF" "$*" >&2
  if [ "$JOURNAL" = 1 ] && command -v logger > /dev/null; then
    logger -t "$SELF" -- "$*" 2> /dev/null || true
  fi
}

valid_host() {
  [ "${#1}" -le 253 ] && [[ $1 =~ $HOST_RE ]]
}

valid_slug() {
  [[ $1 =~ $SLUG_RE ]] && [ "$1" != . ] && [ "$1" != .. ]
}

# hosts_of PARAM FILE: hosts on stdout; a bad line: its number logged, 1.
hosts_of() {
  local param=$1 n=0 line host rest slug seen=' '
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    line=${line#"${line%%[![:space:]]*}"}
    line=${line%"${line##*[![:space:]]}"}
    case $line in '' | '#'*) continue ;; esac
    host=$line
    if [ "$param" = extras ]; then
      case $line in
        *"$TAB"*) host=${line%%"$TAB"*} ;;
        *) log "extras line $n is not host<TAB>slug[,slug]"; return 1 ;;
      esac
    fi
    valid_host "$host" || { log "$param line $n is not a valid host"; return 1; }
    if [ "$param" = extras ]; then
      rest=${line#*"$TAB"}
      while :; do
        slug=${rest%%,*}
        valid_slug "$slug" || { log "extras line $n has an invalid workspace slug"; return 1; }
        [ "$slug" = "$rest" ] && break
        rest=${rest#*,}
      done
      case $seen in *" $host "*) log "extras line $n repeats a host"; return 1 ;; esac
      seen="$seen$host "
    fi
    printf '%s\n' "$host"
  done < "$2"
  return 0
}

# clean PARAM FILE: printable ASCII, TAB, CR, LF only (`read` drops NUL).
clean() {
  [ "$(tr -d '\11\12\15\40-\176' < "$2" | wc -c)" = 0 ] || { log "$1 holds a byte outside printable ASCII, TAB, CR and LF"; return 1; }
}

count() {
  grep -cvE '^[[:space:]]*(#|$)' "$STAGE/$1.value" || true
}

same() {
  [ -f "$1" ] && [ -f "$2" ] && [ "$(sha256sum < "$1")" = "$(sha256sum < "$2")" ]
}

same_lists() {
  local p
  for p in "${LISTS[@]}"; do same "$STAGE/lists/$p.txt" "$1/$p.txt" || return 1; done
}

read_env() {
  local f=${AI_ENV_PROXY_ENV:-/etc/ai-env-proxy/env} k v
  PARAM_PREFIX='' REGION=''
  [ -r "$f" ] || { log "cannot read $f"; return 1; }
  while IFS='=' read -r k v || [ -n "$k" ]; do
    case $k in
      PARAM_PREFIX) PARAM_PREFIX=$v ;;
      REGION) REGION=$v ;;
    esac
  done < "$f"
  [[ $PARAM_PREFIX =~ $PREFIX_RE ]] && [[ $REGION =~ $REGION_RE ]] || { log "$f: PARAM_PREFIX or REGION is missing or malformed"; return 1; }
}

# Exact values: jq -j writes the decoded JSON string byte for byte.
fetch() {
  local try=0 p names=()
  for p in "${PARAMS[@]}"; do names+=("$PARAM_PREFIX/$p"); done
  until timeout 60 aws ssm get-parameters --names "${names[@]}" --region "$REGION" --endpoint-url "https://ssm.$REGION.amazonaws.com" --output json > "$STAGE/answer.json" 2> "$STAGE/aws.err"; do
    try=$((try + 1))
    log "aws ssm get-parameters failed (try $try of 5): $(tail -n 1 "$STAGE/aws.err")"
    [ "$try" -lt 5 ] || return 1
    sleep "$try"
  done
  for p in "${PARAMS[@]}"; do
    jq -ej --arg n "$PARAM_PREFIX/$p" 'first(.Parameters[] | select(.Name == $n) | .Value | strings)' "$STAGE/answer.json" > "$STAGE/$p.value" 2> /dev/null || { log "no value for $PARAM_PREFIX/$p"; return 1; }
  done
}

render() {
  sed "s|@DIR@|$1|g" "$STAGE/squid.conf.value"
}

parse_ok() {
  local out rc=0 bad
  out=$(squid -k parse -f "$1" 2>&1) || rc=$?
  # squid 6 exits 0 on some ERRORs; only expected WARNINGs pass.
  bad=$(grep -E 'FATAL|ERROR|unrecognized|Bungled|WARNING' <<< "$out" | grep -vE "$OK_WARN" || true)
  [ "$rc" = 0 ] && [ -z "$bad" ] || { log "squid -k parse failed (exit $rc; squid.conf lines: $(sed -nE 's/.*[(]([0-9]+)[)]:.*/\1/p' <<< "$bad" | tr '\n' ' '))"; return 1; }
}

stage() {
  local p f=$STAGE/squid.conf
  mkdir -p "$STAGE/lists"
  for p in "${PARAMS[@]}"; do clean "$p" "$STAGE/$p.value" || return 1; done
  for p in "${LISTS[@]}"; do
    hosts_of "$p" "$STAGE/$p.value" > "$STAGE/$p.hosts" || return 1
    sort -u "$STAGE/$p.hosts" > "$STAGE/lists/$p.txt"
  done
  VERSION=$(for p in "${LISTS[@]}"; do echo "$p"; cat "$STAGE/lists/$p.txt"; done | sha256sum | cut -c 1-16)
  render "$LIST_DIR/$VERSION" > "$f"
  render "$STAGE/lists" > "$STAGE/parse.conf"
  ! grep -qE '@[A-Z_]+@' "$f" || { log "squid.conf still has an unrendered placeholder"; return 1; }
  [ "$(grep -c '^dns_nameservers ' "$f" || true)" = 1 ] && grep -qE "$NS_RE" "$f" && grep -qE "$VMS_RE" "$f" || { log "squid.conf needs one dns_nameservers line of IPs and a non-empty acl vms src"; return 1; }
  parse_ok "$STAGE/parse.conf"
}

squid_active() {
  if [ "$SYSTEMD" = 1 ]; then systemctl is-active --quiet squid.service; else squid -k check -f "$CONF" > /dev/null 2>&1; fi
}

is_applied() {
  [ -f "$APPLIED" ] && [ "$(cat "$APPLIED")" = "$SUMS" ] && same "$STAGE/squid.conf" "$CONF" && same_lists "$LIST_DIR/$VERSION" && squid_active
}

effective() {
  sort -u "$1/allow.txt" "$1/extras.txt" | comm -23 - "$1/suspended.txt"
}

# Restart (a reconfigure keeps tunnels): a host left, the conf changed, or unknown.
shrinks() {
  local old
  old=$(sed -nE 's|^acl allowed dstdomain -n "(.*)/allow[.]txt"|\1|p' "$CONF" 2> /dev/null | head -n 1)
  [ -f "$old/allow.txt" ] && [ -f "$old/extras.txt" ] && [ -f "$old/suspended.txt" ] || return 0
  [ "$(render "$old" | sha256sum)" = "$(sha256sum < "$CONF")" ] || return 0
  [ -n "$(comm -23 <(effective "$old") <(effective "$STAGE/lists"))" ]
}

mark() {
  stat -c '%i %s' "$CACHE_LOG" 2> /dev/null || echo '0 0'
}

# squid is active and opened its port after mark $1.
confirm() {
  local i
  for i in $(seq 30); do
    squid_active && { if [ "$(stat -c %i "$CACHE_LOG" 2> /dev/null)" = "${1% *}" ]; then tail -c +$((${1#* } + 1)) "$CACHE_LOG"; else cat "$CACHE_LOG"; fi; } 2> /dev/null | grep -q 'Accepting HTTP Socket connections' && return 0
    sleep 0.5
  done
  return 1
}

# Under systemd the lock goes first: a squid start may rerun the boot unit.
squid_do() {
  local i
  if [ "$1" = reconfigure ]; then
    squid -k reconfigure -f "$CONF"
  elif [ "$SYSTEMD" = 1 ]; then
    exec 9>&-
    timeout 300 systemctl "$1" squid.service
  else
    if [ "$1" != start ]; then
      squid -k shutdown -f "$CONF" 2> /dev/null || true
      for i in $(seq 30); do
        squid -k check -f "$CONF" > /dev/null 2>&1 || break
        sleep 0.5
      done
    fi
    [ "$1" = stop ] || squid -f "$CONF" 9>&-
  fi
}

record() {
  mkdir -p "$STATE" && printf '%s\n' "$SUMS" > "$1.new" && mv -f "$1.new" "$1"
}

undo_dir() {
  [ "$created" = 0 ] || rm -rf -- "${new:?}"
  [ "$aside" = 0 ] || mv -T "$new.bad" "$new"
}

# 0, 1 (rolled back) or 3. errexit is off in here: each step is checked.
apply() {
  local action=start was=0 ok=0 m created=0 aside=0 new=$LIST_DIR/$VERSION d
  rm -f "$APPLIED" "$PENDING"
  if squid_active; then
    was=1 action=reconfigure
    ! shrinks || action=restart
  fi
  # This hash's directory with other bytes (edited on disk) goes aside.
  if [ -d "$new" ] && ! same_lists "$new"; then
    rm -rf -- "${new:?}.bad" && mv -T "$new" "$new.bad" && aside=1 || return 1
  fi
  if [ ! -d "$new" ]; then
    { mkdir -p "$LIST_DIR" && rm -rf -- "${new:?}.new" && cp -r "$STAGE/lists" "$new.new" && chmod -R a+rX "$LIST_DIR" && mv -T "$new.new" "$new"; } || { log "cannot write $new"; return 1; }
    created=1
  fi
  if ! parse_ok "$STAGE/squid.conf" || ! { if [ -e "$CONF" ]; then ln -f "$CONF" "$PREV"; else rm -f "$PREV"; fi && chmod 0644 "$STAGE/squid.conf" && mv -f "$STAGE/squid.conf" "$CONF"; }; then
    undo_dir
    return 1
  fi
  HOW=${action/%e/}ed
  # squid.service's ExecStartPost turns pending into applied.
  [ "$action$SYSTEMD" != start1 ] || record "$PENDING"
  if [ "$action$SYSTEMD" = start1 ] && [ -n "${AI_ENV_PROXY_BOOT:-}" ]; then
    # The boot unit: squid starts once it exits.
    HOW='start queued'
    systemctl start --no-block squid.service && ok=1
  else
    m=$(mark)
    squid_do "$action" && confirm "$m" && record "$APPLIED" && rm -f "$PENDING" && ok=1
  fi
  if [ "$ok" = 1 ]; then
    rm -f "$PREV"
    for d in "$LIST_DIR"/*; do
      [ "$d" = "$new" ] || rm -rf -- "${d:?}"
    done
    return 0
  fi
  log "squid did not confirm the new set ($action); restoring the previous one"
  if [ -e "$PREV" ]; then mv -f "$PREV" "$CONF"; else rm -f "$CONF"; fi
  undo_dir
  rm -f "$PENDING"
  m=$(mark)
  if [ "$was" = 1 ]; then
    if squid_active; then squid_do reconfigure; else squid_do start; fi && confirm "$m" && return 1
  elif ! squid_active || squid_do stop; then
    return 1
  fi
  return 3
}

main() {
  local mode=apply p state=inactive parse=ok applied=no rc=0
  case "$#:${1:-}" in
    0:) ;; 1:--if-changed) mode=if-changed ;; 1:--status) mode=status ;;
    *) echo "usage: $SELF [--if-changed | --status]" >&2; exit 1 ;;
  esac
  read_env || exit 2
  if [ "$mode" != status ]; then
    exec 9> "$LOCK"
    flock -w 120 9 || { log "another reload still holds $LOCK; nothing changed"; exit 1; }
  fi
  # On the live files' filesystem: atomic renames.
  STAGE=$(mktemp -d /etc/squid/.ai-env-stage.XXXXXX)
  trap 'rm -rf -- "${STAGE:?}"' EXIT
  fetch || { log "fetch failed; nothing changed"; exit 2; }
  SUMS=$(for p in "${PARAMS[@]}"; do printf 'sha256_%s=%s ' "$p" "$(sha256sum < "$STAGE/$p.value" | cut -d ' ' -f 1)"; done)
  SUMS=${SUMS% }
  if [ "$mode" = status ]; then
    stage || parse=failed
    ! squid_active || state=active
    [ "$parse" = failed ] || ! is_applied || applied=yes
    printf 'squid=%s allowed=%s extras=%s suspended=%s %s parse=%s applied=%s\n' "$state" "$(count allow)" "$(count extras)" "$(count suspended)" "$SUMS" "$parse" "$applied"
    exit 0
  fi
  stage || { log "refused; the running config is unchanged"; exit 1; }
  if [ "$mode" = if-changed ] && is_applied; then
    log "unchanged since the last apply; nothing to do"
    exit 0
  fi
  apply || rc=$?
  case $rc in
    0) log "applied ($HOW): allowed=$(count allow) extras=$(count extras) suspended=$(count suspended)" ;;
    1) log "refused; the previous set is in place" ;;
    *) log "the install and its rollback failed: state unknown (make proxy-stop to fail closed)" ;;
  esac
  exit "$rc"
}

# Sourced (the Docker test): definitions only.
if ! (return 0 2> /dev/null); then
  main "$@"
fi
