#!/bin/sh
# Fake relay client (S13, plans/s13-contracts.md §V-vm.9): what the shim starts
# for a relay session, as `<this> serve --leader <pid> --socket <path>
# --agent-uid <uid>`. It binds nothing. It records, next to <path>:
#   <path>.argv     its arguments, one a line
#   <path>.ids      <id -u>:<id -g>
#   <path>.fds      descriptors 3 to 254 open at its start, comma-separated
#                   (`-` for none)
#   <path>.env      its environment's names, sorted (the shell's own PWD,
#                   SHLVL, OLDPWD and _ left out)
#   <path>.sid      `leader` when it leads its own session, else `member`
#   <path>.session  fd 3's bytes (0600; a test's tempdir, the token a test's
#                   run-time value)
# then, by RELAYFAKE_MODE from `<this path>.knobs` only (every inherited
# RELAYFAKE_* is unset first; the shim clears the environment anyway):
#   serve (default)  `ai-env-relay-client: ready (fake)` on stderr, then sleeps
#                    until TERM, writes <path>.term, exits 0
#   exit             `ai-env-relay-client: refused: session token` on stderr,
#                    exits 2 at once
#   hang             writes <path>.term-ignored at each TERM, sleeps until KILL
fds=''
for n in $(seq 3 254); do [ -e "/dev/fd/$n" ] && fds="$fds$n,"; done
fds=${fds%,}
[ -n "$fds" ] || fds=-
env_names=$(env | sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p' | grep -vxE 'PWD|SHLVL|OLDPWD|_' | LC_ALL=C sort)
unset RELAYFAKE_MODE
case $0 in
  */*) if [ -f "$0.knobs" ]; then . "$0.knobs"; fi ;;
esac
sock=''
prev=''
for a in "$@"; do
  [ "$prev" = --socket ] && sock=$a
  prev=$a
done
[ -n "$sock" ] || { echo "fake relay client: no --socket" >&2; exit 64; }
mode=${RELAYFAKE_MODE:-serve}
case $mode in
  serve) trap 'touch "$sock.term"; exit 0' TERM ;;
  hang) trap 'touch "$sock.term-ignored"' TERM ;;
  exit) ;;
  *) echo "fake relay client: unknown RELAYFAKE_MODE" >&2; exit 64 ;;
esac
printf '%s\n' "$@" > "$sock.argv"
echo "$(id -u):$(id -g)" > "$sock.ids"
echo "$fds" > "$sock.fds"
printf '%s\n' "$env_names" > "$sock.env"
sid=$(ps -o sess= -p $$ 2>/dev/null | tr -d ' ')
if [ "$sid" = "$$" ]; then echo leader; else echo member; fi > "$sock.sid"
(umask 077; cat <&3 > "$sock.session.tmp"; mv "$sock.session.tmp" "$sock.session")
case $mode in
  exit)
    echo 'ai-env-relay-client: refused: session token' >&2
    exit 2
    ;;
  serve)
    echo 'ai-env-relay-client: ready (fake)' >&2
    ;;
esac
while :; do sleep 0.1; done
