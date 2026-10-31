#!/bin/bash
set -euo pipefail

if [ ! -f /swapfile ]; then
  dd if=/dev/zero of=/swapfile.new bs=1M count=512 status=none
  chmod 0600 /swapfile.new
  mkswap /swapfile.new > /dev/null
  mv /swapfile.new /swapfile
fi
swapon --show=NAME --noheadings | grep -qx /swapfile || swapon /swapfile
grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap defaults 0 0' >> /etc/fstab

boot=/root/ai-env-relay-boot.sh
stop=$(($(date +%s) + 300))
until timeout 60 aws s3api get-object --bucket '@BUCKET@' --key '@BOOT_KEY@' --region '@REGION@' --endpoint-url 'https://s3.@REGION@.amazonaws.com' "$boot" > /dev/null; do
  if [ "$(date +%s)" -ge "$stop" ]; then
    echo 'ai-env-relay-user-data: s3://@BUCKET@/@BOOT_KEY@ could not be fetched in 5 minutes: nothing run' >&2
    exit 1
  fi
  sleep 10
done
got=$(sha256sum "$boot" | cut -d' ' -f1)
if [ "$got" != '@BOOT_HASH@' ]; then
  echo "ai-env-relay-user-data: s3://@BUCKET@/@BOOT_KEY@ has SHA-256 $got, not the pinned @BOOT_HASH@: nothing run" >&2
  exit 1
fi
exec /bin/bash "$boot"
