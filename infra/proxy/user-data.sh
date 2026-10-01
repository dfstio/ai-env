#!/bin/bash
# ai-env egress proxy bootstrap (S5), rendered by infra/egress.ts. squid.conf
# and the allowlist come from SSM (ai-env-proxy-reload). Safe to run twice.
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

# Before the RPM (it keeps a squid.conf: noreplace): a deny-all squid.conf
# and the units, so squid never runs the package default.
install -d -m 0755 /etc/ai-env-proxy /etc/squid /etc/systemd/system/squid.service.d /etc/systemd/system/logrotate.timer.d
printf 'PARAM_PREFIX=%s\nREGION=%s\nLOG_GROUP=%s\n' '@PARAM_PREFIX@' '@REGION@' '@LOG_GROUP@' > /etc/ai-env-proxy/env
cat > /usr/local/sbin/ai-env-proxy-reload <<'AIENV_RELOAD_EOF'
@RELOAD_SH@
AIENV_RELOAD_EOF
chmod 0755 /usr/local/sbin/ai-env-proxy-reload
if ! grep -qs '^# ai-env egress proxy' /etc/squid/squid.conf; then
  printf '%s\n' '# ai-env: deny-all until ai-env-proxy-reload installs the allowlist' 'http_port 127.0.0.1:3128' 'http_access deny all' > /etc/squid/squid.conf
fi
# Every boot: the reload, then squid (exit 2 retries; 1 waits).
cat > /etc/systemd/system/ai-env-proxy-reload.service <<'AIENV_UNIT_EOF'
[Unit]
Description=ai-env egress proxy: the allowlist from SSM, before squid
Wants=network-online.target
After=network-online.target
Before=squid.service

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=AI_ENV_PROXY_BOOT=1
ExecStart=/usr/local/sbin/ai-env-proxy-reload
Restart=on-failure
RestartSec=30
RestartPreventExitStatus=1
TimeoutStartSec=600

[Install]
WantedBy=multi-user.target
AIENV_UNIT_EOF
cat > /etc/systemd/system/squid.service.d/ai-env.conf <<'AIENV_DROPIN_EOF'
[Unit]
Requires=ai-env-proxy-reload.service
After=ai-env-proxy-reload.service

[Service]
ExecStartPost=-+/usr/bin/mv -f /var/lib/ai-env-proxy/pending /var/lib/ai-env-proxy/applied
Restart=on-failure
RestartSec=5
AIENV_DROPIN_EOF
# Hourly logrotate, squid's logs at 100 MB: a VM cannot fill the disk.
printf '%s\n' '[Timer]' 'OnCalendar=' 'OnCalendar=hourly' > /etc/systemd/system/logrotate.timer.d/ai-env.conf
systemctl daemon-reload

for try in 1 2 3; do
  dnf -y install squid amazon-cloudwatch-agent jq logrotate && break
  sleep $((try * 10))
done
rpm -q squid amazon-cloudwatch-agent jq logrotate > /dev/null
cat > /etc/logrotate.d/squid <<'AIENV_LOGROTATE_EOF'
/var/log/squid/*.log {
    daily
    maxsize 100M
    rotate 5
    compress
    delaycompress
    missingok
    notifempty
    nocreate
    sharedscripts
    postrotate
        /usr/sbin/squid -k rotate 2> /dev/null || true
    endscript
}
AIENV_LOGROTATE_EOF
systemctl enable logrotate.timer ai-env-proxy-reload.service squid.service
systemctl start --no-block logrotate.timer squid.service

# Never fatal: the CloudWatch agent (root: access.log is 0640 squid).
cat > /etc/ai-env-proxy/cloudwatch-agent.json <<'AIENV_CW_EOF'
@CW_AGENT_JSON@
AIENV_CW_EOF
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/etc/ai-env-proxy/cloudwatch-agent.json || logger -s -t ai-env-user-data 'the CloudWatch agent did not start; squid serves without log shipping' || true
