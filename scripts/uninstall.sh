#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run: sudo bash scripts/uninstall.sh' >&2; exit 1; }

if systemctl cat torrent-guard.service >/dev/null 2>&1; then
  systemctl disable --now torrent-guard.service || true
fi
if [[ -x /usr/local/sbin/torrent-guard ]]; then
  /usr/local/sbin/torrent-guard remove
fi
rm -f /etc/systemd/system/torrent-guard.service /usr/local/sbin/torrent-guard
systemctl daemon-reload
printf 'TorrentGuard program and rules removed. /etc/torrent-guard.conf kept.\n'
