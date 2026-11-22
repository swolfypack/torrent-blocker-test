#!/usr/bin/env bash
# Bootstrap installer for swolfypack/torrent-blocker-test (flat repository layout).
# Usage: curl -fsSL https://raw.githubusercontent.com/swolfypack/torrent-blocker-test/main/install.sh | sudo bash
set -Eeuo pipefail
umask 077

REPO='swolfypack/torrent-blocker-test'
BRANCH='main'
ARCHIVE_URL="https://codeload.github.com/${REPO}/tar.gz/refs/heads/${BRANCH}"
ROOT_NAME="torrent-blocker-test-${BRANCH}"

log() { printf '[TorrentGuard] %s\n' "$*"; }
die() { printf '[TorrentGuard] ERROR: %s\n' "$*" >&2; exit 1; }

(( EUID == 0 )) || die 'Run as root: curl -fsSL <URL> | sudo bash'

# The loader itself needs curl, tar and a temporary directory.
for program in curl tar mktemp bash; do
  command -v "$program" >/dev/null 2>&1 || die "Missing dependency: ${program}"
done
command -v systemctl >/dev/null 2>&1 || die 'systemd/systemctl is required'

# Install the packages used by scripts/install.sh when they are missing.
missing=()
for program in iptables ip6tables ip flock; do
  if ! command -v "$program" >/dev/null 2>&1; then
    missing+=("$program")
  fi
done

if (( ${#missing[@]} > 0 )); then
  if command -v apt-get >/dev/null 2>&1; then
    log "Missing: ${missing[*]}. Installing Ubuntu/Debian dependencies..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends iptables iproute2 util-linux
  else
    die "Missing: ${missing[*]}. Install iptables, iproute2 and util-linux using your package manager."
  fi
fi

# Check the dependencies again before making any firewall changes.
for program in iptables ip6tables ip flock; do
  command -v "$program" >/dev/null 2>&1 || die "Dependency still missing: ${program}"
done

TEMP_DIR="$(mktemp -d /tmp/torrent-guard-setup.XXXXXXXX)"
cleanup() { rm -rf -- "$TEMP_DIR"; }
trap cleanup EXIT

log "Downloading ${REPO} (${BRANCH})..."
curl --fail --location --silent --show-error \
  --retry 3 --connect-timeout 15 --max-time 180 \
  "$ARCHIVE_URL" --output "$TEMP_DIR/source.tar.gz"

# Abort if download is HTML, incomplete or otherwise not a valid tarball.
tar -tzf "$TEMP_DIR/source.tar.gz" > /dev/null || die 'Downloaded archive is invalid'

tar -xzf "$TEMP_DIR/source.tar.gz" -C "$TEMP_DIR"
PROJECT_DIR="$TEMP_DIR/$ROOT_NAME"

# The repo must have the flat layout shown in README and GitHub; no torrent-guard/ subfolder.
for required in \
  'scripts/install.sh' \
  'scripts/torrent-guard.sh' \
  'config/torrent-guard.conf.example' \
  'systemd/torrent-guard.service'; do
  [[ -f "$PROJECT_DIR/$required" ]] || die "Missing ${required} at repository root. Keep config/, scripts/ and systemd/ in the root."
done

log 'Running the project installer...'
bash "$PROJECT_DIR/scripts/install.sh"
log 'Installation completed. Check with: sudo torrent-guard status'
