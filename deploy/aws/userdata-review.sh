#!/bin/bash
# Ubuntu 24.04 amd64 user data; derived from the real 2026-10-25 deployment.
# Review the public template before --apply; it contains no provider credentials.
# REQUIRED AT LAUNCH: InstanceInitiatedShutdownBehavior=terminate;
# root gp3 volume DeleteOnTermination=true; public IPv4 (not Elastic IP).
# Creates a persistent 48-hour OS expiry before installing anything else.
# An OS timer is not an independent AWS-side spending cap.
set -euo pipefail
umask 077

guard_dir=/var/lib/safeguard-zetaris-expiry
install -d -m 0700 "$guard_dir"
if [ ! -s "$guard_dir/deadline-epoch" ]; then
  date -u -d '+48 hours' +%s > "$guard_dir/deadline-epoch"
fi
deadline_epoch=$(cat "$guard_dir/deadline-epoch")
case "$deadline_epoch" in
  ''|*[!0-9]*) echo 'Invalid expiry state; stop setup and review.' >&2; exit 1 ;;
esac
deadline_utc=$(date -u -d "@$deadline_epoch" '+%Y-%m-%d %H:%M:%S UTC')
if [ "$(date -u +%s)" -ge "$deadline_epoch" ]; then
  /usr/sbin/shutdown -P now
  exit 0
fi

cat > /etc/systemd/system/safeguard-zetaris-expiry.service <<'SERVICE'
[Unit]
Description=End the temporary Zetaris evaluation instance
[Service]
Type=oneshot
ExecStart=/usr/sbin/shutdown -P now
SERVICE

cat > /etc/systemd/system/safeguard-zetaris-expiry.timer <<TIMER
[Unit]
Description=Absolute expiry for the temporary Zetaris evaluation instance
[Timer]
OnCalendar=$deadline_utc
Persistent=true
AccuracySec=1min
Unit=safeguard-zetaris-expiry.service
[Install]
WantedBy=timers.target
TIMER

systemctl daemon-reload
systemctl enable --now safeguard-zetaris-expiry.timer
systemctl is-active --quiet safeguard-zetaris-expiry.timer
printf 'Expiry guard armed for %s\n' "$deadline_utc"

# Docker's official Ubuntu apt repository. No platform credentials or AWS keys.
. /etc/os-release
if [ "${ID:-}" != ubuntu ] || [ "${VERSION_ID:-}" != 24.04 ]; then
  echo 'This reviewed bootstrap expects Ubuntu 24.04; expiry remains armed.' >&2
  exit 1
fi
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl unzip
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
cat > /etc/apt/sources.list.d/docker.sources <<DOCKER_SOURCE
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: ${UBUNTU_CODENAME:-$VERSION_CODENAME}
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
DOCKER_SOURCE
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
docker version --format '{{.Server.Version}}'
docker compose version
systemctl list-timers safeguard-zetaris-expiry.timer --no-pager
echo 'Docker ready. Install the authorized Zetaris bundle separately; do not print its .env or registry credentials.'
