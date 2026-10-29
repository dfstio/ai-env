#!/bin/bash
# ai-env relay bootstrap (S13, plans/s13-contracts.md §I-infra.4.5), rendered by infra/relay-spec.ts: no secret here
# (the reload unit fetches the parameters and the binary). Safe to run twice.
set -euo pipefail

# Swap first: without it dnf is OOM-killed at t4g.nano memory.
if [ ! -f /swapfile ]; then
  dd if=/dev/zero of=/swapfile.new bs=1M count=512 status=none
  chmod 0600 /swapfile.new
  mkswap /swapfile.new > /dev/null
  mv /swapfile.new /swapfile
fi
swapon --show=NAME --noheadings | grep -qx /swapfile || swapon /swapfile
grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap defaults 0 0' >> /etc/fstab

# The relay's user first: its guard resolves the name when it loads.
getent passwd ai-env-relay >/dev/null || useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /sbin/nologin ai-env-relay
# The relay reads live/ and writes requests/ alone: no root write goes where it can plant a symlink.
install -d -m 0755 -o root -g root /etc/ai-env-relay /usr/local/libexec/ai-env-relay /var/log/ai-env-relay /etc/systemd/system/logrotate.timer.d
install -d -m 0750 -o root -g ai-env-relay /var/lib/ai-env-relay /var/lib/ai-env-relay/live
install -d -m 0700 -o root -g root /var/lib/ai-env-relay/stage
install -d -m 0750 -o ai-env-relay -g ai-env-relay /var/log/ai-env-relay/requests
printf 'PARAM_PREFIX=%s\nREGION=%s\n' '@PARAM_PREFIX@' '@REGION@' > /etc/ai-env-relay/reload.env
printf '%s\n' 'AI_ENV_RELAY_PUBLIC_ADDR=0.0.0.0:443' 'AI_ENV_RELAY_PRIVATE_ADDR=@RELAY_IP@:@RELAY_PORT@' 'AI_ENV_RELAY_PRIVATE_PEERS=@VM_SUBNET_CIDR@' \
  'AI_ENV_RELAY_LIVE_DIR=/var/lib/ai-env-relay/live' 'AI_ENV_RELAY_REQUEST_LOG=/var/log/ai-env-relay/requests/requests.log' > /etc/ai-env-relay/relay.env
chmod 0644 /etc/ai-env-relay/reload.env /etc/ai-env-relay/relay.env

# The reload unit (infra/relay/reload.py, gzipped; pipefail makes a bad decode fatal) and the weekly patch.
base64 -d <<'AIENV_RELAY_RELOAD_EOF' | python3 -I -c 'import gzip,sys; sys.stdout.buffer.write(gzip.decompress(sys.stdin.buffer.read()))' > /usr/local/sbin/ai-env-relay-reload
@RELOAD_PY_GZ@
AIENV_RELAY_RELOAD_EOF
cat > /usr/local/sbin/ai-env-relay-patch <<'AIENV_RELAY_PATCH_EOF'
#!/bin/bash
# ai-env-relay-patch (S13): the security updates, then the relay restarted, or a reboot when dnf says one is needed.
set -uo pipefail
L=/var/log/ai-env-relay/patch.log
say() { echo "$(date -u +%FT%TZ) ai-env-relay-patch: $*" | tee -a "$L" >&2; }
timeout -k 30 1740 dnf -y upgrade --security --releasever=latest >> "$L" 2>&1 || { say "FAILED: dnf upgrade --security: nothing restarted"; exit 1; }
out=$(dnf needs-restarting -r 2>&1); rc=$?
echo "$out" >> "$L"
if [ "$rc" = 1 ] && echo "$out" | grep -qi 'reboot is required'; then say "a reboot is required: rebooting"; systemctl reboot; exit 0; fi
[ "$rc" = 0 ] || say "dnf needs-restarting -r exited $rc, no reboot: the relay restarts"
systemctl try-restart ai-env-relay.service
AIENV_RELAY_PATCH_EOF
chmod 0755 /usr/local/sbin/ai-env-relay-reload /usr/local/sbin/ai-env-relay-patch

# R's unit and guard as they are; the reload's and the patch's units and timers; logrotate hourly.
cat > /etc/systemd/system/ai-env-relay.service <<'AIENV_RELAY_UNIT_EOF'
@RELAY_UNIT@
AIENV_RELAY_UNIT_EOF
cat > /etc/systemd/system/ai-env-relay-guard.service <<'AIENV_RELAY_UNIT_EOF'
@GUARD_UNIT@
AIENV_RELAY_UNIT_EOF
cat > /etc/ai-env-relay/guard.nft <<'AIENV_RELAY_UNIT_EOF'
@GUARD_NFT@
AIENV_RELAY_UNIT_EOF
cat > /etc/systemd/system/ai-env-relay-reload.service <<'AIENV_RELAY_UNIT_EOF'
[Unit]
Description=ai-env relay: its parameters and binary
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/ai-env-relay/reload.env
ExecStart=/usr/local/sbin/ai-env-relay-reload
TimeoutStartSec=300
Nice=5
AIENV_RELAY_UNIT_EOF
cat > /etc/systemd/system/ai-env-relay-reload.timer <<'AIENV_RELAY_UNIT_EOF'
[Unit]
Description=ai-env relay: the reload, every minute

[Timer]
OnBootSec=15s
OnCalendar=*-*-* *:*:00
AccuracySec=1s

[Install]
WantedBy=timers.target
AIENV_RELAY_UNIT_EOF
cat > /etc/systemd/system/ai-env-relay-patch.service <<'AIENV_RELAY_UNIT_EOF'
[Unit]
Description=ai-env relay: the security updates

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/ai-env-relay-patch
TimeoutStartSec=1800
AIENV_RELAY_UNIT_EOF
cat > /etc/systemd/system/ai-env-relay-patch.timer <<'AIENV_RELAY_UNIT_EOF'
[Unit]
Description=ai-env relay: the security updates, weekly

[Timer]
OnCalendar=Sun *-*-* 03:30:00 UTC
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
AIENV_RELAY_UNIT_EOF
cat > /etc/systemd/system/logrotate.timer.d/ai-env.conf <<'AIENV_RELAY_UNIT_EOF'
[Timer]
OnCalendar=
OnCalendar=hourly
AIENV_RELAY_UNIT_EOF
chmod 0644 /etc/ai-env-relay/guard.nft
systemctl daemon-reload

# nftables: the guard's nft; dnf-plugins-core: needs-restarting. Only the AL2023 repositories.
for try in 1 2 3; do
  dnf -y install amazon-cloudwatch-agent logrotate nftables dnf-plugins-core && break
  [ "$try" = 3 ] || sleep $((try * 10))
done
rpm -q amazon-cloudwatch-agent logrotate nftables dnf-plugins-core > /dev/null
# The request log rotates as the relay's user, whose directory it is.
cat > /etc/logrotate.d/ai-env-relay <<'AIENV_RELAY_LOGROTATE_EOF'
/var/log/ai-env-relay/*.log {
    size 20M
    rotate 5
    copytruncate
    compress
    delaycompress
    missingok
    notifempty
}
/var/log/ai-env-relay/requests/*.log {
    su ai-env-relay ai-env-relay
    size 20M
    rotate 5
    copytruncate
    compress
    delaycompress
    missingok
    notifempty
}
AIENV_RELAY_LOGROTATE_EOF
# The reload unit starts the relay once tls.pem exists; its Requires= starts the guard first.
systemctl enable ai-env-relay-guard.service ai-env-relay.service
systemctl enable --now ai-env-relay-reload.timer ai-env-relay-patch.timer logrotate.timer

# Never fatal: the CloudWatch agent (root: it reads the request log too).
cat > /etc/ai-env-relay/cloudwatch-agent.json <<'AIENV_RELAY_CW_EOF'
@CW_AGENT_JSON@
AIENV_RELAY_CW_EOF
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/etc/ai-env-relay/cloudwatch-agent.json || logger -s -t ai-env-relay-user-data 'the CloudWatch agent did not start; the relay serves without log shipping' || true
