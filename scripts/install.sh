#!/usr/bin/env bash
set -Eeuo pipefail

[[ $EUID -eq 0 ]] || { echo 'Run: sudo bash scripts/install.sh' >&2; exit 1; }
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

for program in iptables ip ip6tables flock systemctl; do
  command -v "$program" >/dev/null 2>&1 || {
    echo "Missing $program. On Ubuntu/Debian: sudo apt update && sudo apt install -y iptables iproute2 util-linux" >&2
    exit 1
  }
done

install -Dm 0755 "$ROOT/scripts/torrent-guard.sh" /usr/local/sbin/torrent-guard
if [[ ! -e /etc/torrent-guard.conf ]]; then
  install -Dm 0600 "$ROOT/config/torrent-guard.conf.example" /etc/torrent-guard.conf
  echo 'Created /etc/torrent-guard.conf (review its options before production use).'
else
  echo 'Preserved existing /etc/torrent-guard.conf.'
fi
install -Dm 0644 "$ROOT/systemd/torrent-guard.service" /etc/systemd/system/torrent-guard.service
systemctl daemon-reload
systemctl enable torrent-guard.service
# A restart invokes ExecStop (temporary filter removal). Reload instead on upgrades.
if systemctl is-active --quiet torrent-guard.service; then
  systemctl reload torrent-guard.service
else
  systemctl start torrent-guard.service
fi
systemctl --no-pager --full status torrent-guard.service
printf '\nCommands: sudo torrent-guard status | preview | apply | remove\n'
