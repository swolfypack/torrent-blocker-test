#!/usr/bin/env bash
# TorrentGuard: lightweight, reversible BitTorrent signature filtering (not DPI).
set -Eeuo pipefail

VERSION='1.1.0'
CONFIG_FILE="${TORRENT_GUARD_CONFIG:-/etc/torrent-guard.conf}"
IPTABLES_BIN="${IPTABLES_BIN:-iptables}"
IP6TABLES_BIN="${IP6TABLES_BIN:-ip6tables}"

ENABLE_IPV6=1
FILTER_OUTPUT=1
FILTER_FORWARD=1
FILTER_DOCKER_USER=1
FILTER_INPUT=0
ENABLE_PORTS=1
ENABLE_DHT=1
ENABLE_HANDSHAKE=1
ENABLE_UDP_TRACKER=1
ENABLE_CONNLIMIT=0
CONNLIMIT_MAX=100
ENABLE_LOG=0
EGRESS_IFACE='auto'
IPV6_EGRESS_IFACE='auto'
TCP_PORTS='6881:6889 51413 6969'
UDP_PORTS='6881:6889 51413 6969'

# Two rule generations allow building the new rules before switching hooks.
# v1.0 chains are recognized for safe migration/removal.
legacy_chains=(TG_EGRESS TG_INPUT TG_LIMIT TG_DROP)
hooks=(OUTPUT FORWARD DOCKER-USER INPUT)

log()  { printf '[TorrentGuard] %s\n' "$*"; }
warn() { printf '[TorrentGuard] WARNING: %s\n' "$*" >&2; }
die()  { printf '[TorrentGuard] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
TorrentGuard v1.1.0 — signature-based, not a guarantee against encrypted BitTorrent
Usage: sudo torrent-guard <apply|remove|status|preview|help>
  apply    Build and switch managed rules (no global firewall flush)
  remove   Delete only TorrentGuard hooks and chains
  status   Show active hooks, counters and warnings
  preview  Show validated configuration without modifying firewall
  help     This help
Configuration: /etc/torrent-guard.conf
USAGE
}

require_root() { (( EUID == 0 )) || die 'Run as root (sudo).'; }
load_config() {
  if [[ -f "$CONFIG_FILE" ]]; then
    # This is executable Bash: only root-owned/trusted config files are safe.
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
  fi
}
validate_flag() {
  local name="$1" value="${!1}"
  [[ "$value" == 0 || "$value" == 1 ]] || die "$name must be 0 or 1"
}
validate_ports() {
  local label="$1" value="$2" token low high
  local -a tokens=()
  value="${value//,/ }"
  read -r -a tokens <<< "$value"
  for token in "${tokens[@]}"; do
    [[ "$token" =~ ^([0-9]{1,5})(:([0-9]{1,5}))?$ ]] || die "Invalid $label port: $token"
    low="${BASH_REMATCH[1]}"
    high="${BASH_REMATCH[3]:-${BASH_REMATCH[1]}}"
    (( 10#$low >= 1 && 10#$low <= 65535 && 10#$high >= 1 && 10#$high <= 65535 && 10#$low <= 10#$high )) || die "Port out of range: $token"
  done
}
validate_config() {
  local flag
  for flag in ENABLE_IPV6 FILTER_OUTPUT FILTER_FORWARD FILTER_DOCKER_USER FILTER_INPUT ENABLE_PORTS ENABLE_DHT ENABLE_HANDSHAKE ENABLE_UDP_TRACKER ENABLE_CONNLIMIT ENABLE_LOG; do
    validate_flag "$flag"
  done
  [[ "$CONNLIMIT_MAX" =~ ^[0-9]+$ ]] && (( CONNLIMIT_MAX >= 1 && CONNLIMIT_MAX <= 1000000 )) || die 'CONNLIMIT_MAX must be 1..1000000'
  validate_ports TCP_PORTS "$TCP_PORTS"
  validate_ports UDP_PORTS "$UDP_PORTS"
  [[ "$EGRESS_IFACE" == auto || -z "$EGRESS_IFACE" || "$EGRESS_IFACE" =~ ^[a-zA-Z0-9_.:@-]{1,15}$ ]] || die 'Invalid EGRESS_IFACE'
  [[ "$IPV6_EGRESS_IFACE" == auto || -z "$IPV6_EGRESS_IFACE" || "$IPV6_EGRESS_IFACE" =~ ^[a-zA-Z0-9_.:@-]{1,15}$ ]] || die 'Invalid IPV6_EGRESS_IFACE'
}
resolve_interfaces() {
  if [[ "$EGRESS_IFACE" == auto || "$IPV6_EGRESS_IFACE" == auto ]]; then
    command -v ip >/dev/null 2>&1 || die 'Install iproute2 to autodetect the outgoing interface.'
  fi
  if [[ "$EGRESS_IFACE" == auto ]]; then
    EGRESS_IFACE="$(ip -4 route show default | awk '$1=="default" { for (i=1;i<=NF;i++) if ($i=="dev") { print $(i+1); exit } }')"
    [[ -n "$EGRESS_IFACE" ]] || die "No IPv4 default interface; set EGRESS_IFACE explicitly (or to '')."
  fi
  if [[ "$IPV6_EGRESS_IFACE" == auto ]]; then
    IPV6_EGRESS_IFACE="$(ip -6 route show default | awk '$1=="default" { for (i=1;i<=NF;i++) if ($i=="dev") { print $(i+1); exit } }')"
    if [[ -z "$IPV6_EGRESS_IFACE" ]]; then
      IPV6_EGRESS_IFACE="$EGRESS_IFACE"
      warn "No IPv6 default route; using interface '${IPV6_EGRESS_IFACE:-all}' for IPv6. Re-apply if IPv6 routing changes."
    fi
  fi
  local iface
  for iface in "$EGRESS_IFACE" "$IPV6_EGRESS_IFACE"; do
    [[ -z "$iface" || -d "/sys/class/net/$iface" ]] || warn "Network interface $iface does not exist at present."
  done
}

has_family() { command -v "$1" >/dev/null 2>&1 && "$1" -w 5 -t filter -S >/dev/null 2>&1; }
ipt() { local bin="$1"; shift; "$bin" -w 5 -t filter "$@"; }
chain_exists() { ipt "$1" -S "$2" >/dev/null 2>&1; }
hook_exists() { chain_exists "$1" "$2"; }

chain_name() {
  local gen="$1" role="$2"
  case "$role" in
    egress) printf 'TG_EG_%s' "$gen" ;;
    input)  printf 'TG_IN_%s' "$gen" ;;
    limit)  printf 'TG_LM_%s' "$gen" ;;
    drop)   printf 'TG_DP_%s' "$gen" ;;
    *) die "Unknown chain role $role" ;;
  esac
}

unlink_hook() {
  local bin="$1" hook="$2" chain="$3"
  hook_exists "$bin" "$hook" || return 0
  while ipt "$bin" -C "$hook" -j "$chain" >/dev/null 2>&1; do
    ipt "$bin" -D "$hook" -j "$chain"
  done
}
link_hook() {
  local bin="$1" hook="$2" chain="$3"
  if ! hook_exists "$bin" "$hook"; then
    [[ "$hook" == DOCKER-USER ]] && warn "$bin: DOCKER-USER is absent; check Docker firewall backend."
    return 0
  fi
  if ! ipt "$bin" -C "$hook" -j "$chain" >/dev/null 2>&1; then
    ipt "$bin" -I "$hook" 1 -j "$chain"
  fi
}

# Do not flush/delete a generation while it is attached to a hook.
generation_linked() {
  local bin="$1" gen="$2" hook role chain
  for hook in "${hooks[@]}"; do
    hook_exists "$bin" "$hook" || continue
    for role in egress input limit; do
      chain="$(chain_name "$gen" "$role")"
      if ipt "$bin" -C "$hook" -j "$chain" >/dev/null 2>&1; then return 0; fi
    done
  done
  return 1
}

remove_generation() {
  local bin="$1" gen="$2" role chain
  # First clear references from egress/input/limit to the drop target.
  for role in egress input limit; do
    chain="$(chain_name "$gen" "$role")"
    chain_exists "$bin" "$chain" && ipt "$bin" -F "$chain"
  done
  chain="$(chain_name "$gen" drop)"
  chain_exists "$bin" "$chain" && ipt "$bin" -F "$chain"
  for role in egress input limit drop; do
    chain="$(chain_name "$gen" "$role")"
    chain_exists "$bin" "$chain" && ipt "$bin" -X "$chain"
  done
  return 0
}

remove_legacy() {
  local bin="$1" chain
  for chain in TG_EGRESS TG_INPUT TG_LIMIT; do
    for hook in "${hooks[@]}"; do unlink_hook "$bin" "$hook" "$chain"; done
  done
  for chain in TG_EGRESS TG_INPUT TG_LIMIT; do
    chain_exists "$bin" "$chain" && ipt "$bin" -F "$chain"
  done
  chain_exists "$bin" TG_DROP && ipt "$bin" -F TG_DROP
  for chain in "${legacy_chains[@]}"; do
    chain_exists "$bin" "$chain" && ipt "$bin" -X "$chain"
  done
  return 0
}

# Build an *unlinked* generation completely before switching hooks.
build_generation() {
  local bin="$1" family="$2" gen="$3" iface="$4" role chain port
  local egress input limit drop
  egress="$(chain_name "$gen" egress)"
  input="$(chain_name "$gen" input)"
  limit="$(chain_name "$gen" limit)"
  drop="$(chain_name "$gen" drop)"
  local -a tcp_list=() udp_list=() egress_iface=() input_iface=()
  read -r -a tcp_list <<< "${TCP_PORTS//,/ }"
  read -r -a udp_list <<< "${UDP_PORTS//,/ }"
  [[ -z "$iface" ]] || { egress_iface=(-o "$iface"); input_iface=(-i "$iface"); }

  for role in egress input limit drop; do
    chain="$(chain_name "$gen" "$role")"
    if chain_exists "$bin" "$chain"; then ipt "$bin" -F "$chain"; else ipt "$bin" -N "$chain"; fi
  done
  if [[ "$ENABLE_LOG" == 1 ]]; then
    ipt "$bin" -A "$drop" -m limit --limit 5/min --limit-burst 10 -j LOG --log-prefix 'TorrentGuard: ' --log-level 4
  fi
  ipt "$bin" -A "$drop" -j DROP

  if [[ "$ENABLE_PORTS" == 1 ]]; then
    for port in "${tcp_list[@]}"; do
      ipt "$bin" -A "$egress" -p tcp --dport "$port" "${egress_iface[@]}" -j "$drop"
      ipt "$bin" -A "$input" -p tcp --dport "$port" "${input_iface[@]}" -j "$drop"
    done
    for port in "${udp_list[@]}"; do
      ipt "$bin" -A "$egress" -p udp --dport "$port" "${egress_iface[@]}" -j "$drop"
      ipt "$bin" -A "$input" -p udp --dport "$port" "${input_iface[@]}" -j "$drop"
    done
  fi
  if [[ "$ENABLE_DHT" == 1 ]]; then
    for pattern in '1:q9:find_node' '1:q9:get_peers' '1:q13:announce_peer'; do
      ipt "$bin" -A "$egress" -p udp -m string --algo kmp --string "$pattern" "${egress_iface[@]}" -j "$drop"
    done
  fi
  if [[ "$ENABLE_UDP_TRACKER" == 1 ]]; then
    # BEP 15: UDP tracker connection-request protocol_id = 0x0000041727101980.
    ipt "$bin" -A "$egress" -p udp -m string --algo kmp --hex-string '|00 00 04 17 27 10 19 80|' "${egress_iface[@]}" -j "$drop"
  fi
  if [[ "$ENABLE_HANDSHAKE" == 1 ]]; then
    # BEP 3: pstrlen (0x13) followed by 'BitTorrent protocol'.
    # Fragmented TCP streams or encrypted sessions are NOT reassembled here.
    ipt "$bin" -A "$egress" -p tcp -m string --algo kmp --hex-string '|13|BitTorrent protocol' "${egress_iface[@]}" -j "$drop"
  fi
  if [[ "$ENABLE_CONNLIMIT" == 1 ]]; then
    local mask=32
    [[ "$family" == 6 ]] && mask=128
    ipt "$bin" -A "$limit" -p tcp --syn -m connlimit --connlimit-above "$CONNLIMIT_MAX" --connlimit-mask "$mask" "${egress_iface[@]}" -j "$drop"
  fi
}

switch_hooks() {
  local bin="$1" gen="$2" egress input limit hook chain oldgen
  egress="$(chain_name "$gen" egress)"
  input="$(chain_name "$gen" input)"
  limit="$(chain_name "$gen" limit)"

  # New rules go FIRST. Remove old hooks only after replacements are installed.
  [[ "$FILTER_OUTPUT" == 1 ]] && link_hook "$bin" OUTPUT "$egress"
  [[ "$FILTER_FORWARD" == 1 && "$ENABLE_CONNLIMIT" == 1 ]] && link_hook "$bin" FORWARD "$limit"
  [[ "$FILTER_DOCKER_USER" == 1 && "$ENABLE_CONNLIMIT" == 1 ]] && link_hook "$bin" DOCKER-USER "$limit"
  [[ "$FILTER_FORWARD" == 1 ]] && link_hook "$bin" FORWARD "$egress"
  [[ "$FILTER_DOCKER_USER" == 1 ]] && link_hook "$bin" DOCKER-USER "$egress"
  [[ "$FILTER_INPUT" == 1 && "$ENABLE_PORTS" == 1 ]] && link_hook "$bin" INPUT "$input"

  for oldgen in A B; do
    [[ "$oldgen" == "$gen" ]] && continue
    for chain in "$(chain_name "$oldgen" egress)" "$(chain_name "$oldgen" input)" "$(chain_name "$oldgen" limit)"; do
      for hook in "${hooks[@]}"; do unlink_hook "$bin" "$hook" "$chain"; done
    done
  done
  for chain in TG_EGRESS TG_INPUT TG_LIMIT; do
    for hook in "${hooks[@]}"; do unlink_hook "$bin" "$hook" "$chain"; done
  done
}

apply_family() {
  local bin="$1" family="$2" iface="$3" activeA=0 activeB=0 gen old
  generation_linked "$bin" A && activeA=1
  generation_linked "$bin" B && activeB=1
  if [[ "$activeA" == 1 && "$activeB" == 1 ]]; then
    die "$bin: both generations have active hooks (partial previous update). Run 'torrent-guard remove' then 'torrent-guard apply' in maintenance window."
  fi
  if [[ "$activeA" == 1 ]]; then gen=B; old=A; else gen=A; old=B; fi
  # Do not rebuild a chain still in use, even after an interrupted prior update.
  generation_linked "$bin" "$gen" && die "$bin: refusing to rebuild active generation $gen"
  build_generation "$bin" "$family" "$gen" "$iface"
  switch_hooks "$bin" "$gen"
  remove_generation "$bin" "$old"
  remove_legacy "$bin"
  log "$bin: active generation $gen; outgoing interface ${iface:-all}"
}

remove_family() {
  local bin="$1" gen chain hook
  has_family "$bin" || return 0
  for gen in A B; do
    for chain in "$(chain_name "$gen" egress)" "$(chain_name "$gen" input)" "$(chain_name "$gen" limit)"; do
      for hook in "${hooks[@]}"; do unlink_hook "$bin" "$hook" "$chain"; done
    done
  done
  for gen in A B; do remove_generation "$bin" "$gen"; done
  remove_legacy "$bin"
}

lock_changes() {
  command -v flock >/dev/null 2>&1 || die 'flock from util-linux is required.'
  exec 9>/run/torrent-guard.lock
  flock -x 9
}

apply_rules() {
  require_root
  validate_config
  resolve_interfaces
  has_family "$IPTABLES_BIN" || die "Missing IPv4 iptables: $IPTABLES_BIN"
  # Check IPv6 BEFORE any firewall changes to avoid IPv4-only partial application.
  if [[ "$ENABLE_IPV6" == 1 ]] && ! has_family "$IP6TABLES_BIN" && [[ -s /proc/net/if_inet6 ]]; then
    die 'IPv6 is enabled but ip6tables is unavailable. Install iptables or disable IPv6 egress at the OS level.'
  fi
  lock_changes
  [[ "$ENABLE_CONNLIMIT" == 1 ]] && warn 'connlimit can block legitimate users sharing source IPs on VPN nodes.'
  apply_family "$IPTABLES_BIN" 4 "$EGRESS_IFACE"
  if [[ "$ENABLE_IPV6" == 1 && -n "$(command -v "$IP6TABLES_BIN" 2>/dev/null || true)" ]] && has_family "$IP6TABLES_BIN"; then
    apply_family "$IP6TABLES_BIN" 6 "$IPV6_EGRESS_IFACE"
  elif [[ "$ENABLE_IPV6" == 0 ]]; then
    remove_family "$IP6TABLES_BIN"
  else
    warn 'No IPv6 firewall stack detected. Skipped IPv6.'
  fi
  log 'Applied. This is NOT deep-packet inspection.'
}
remove_rules() {
  require_root
  lock_changes
  remove_family "$IPTABLES_BIN"
  remove_family "$IP6TABLES_BIN"
  log 'Removed managed rules only; unrelated firewall chains untouched.'
}
show_preview() {
  validate_config
  resolve_interfaces
  cat <<PREVIEW
TorrentGuard $VERSION — configuration only (no firewall modifications)
Config file:            $CONFIG_FILE
IPv4 egress interface:  ${EGRESS_IFACE:-all}
IPv6 egress interface:  ${IPV6_EGRESS_IFACE:-all}
IPv6 enabled:          $ENABLE_IPV6
OUTPUT / FORWARD:      $FILTER_OUTPUT / $FILTER_FORWARD
DOCKER-USER / INPUT:   $FILTER_DOCKER_USER / $FILTER_INPUT
Known-port blocking:   $ENABLE_PORTS (TCP: $TCP_PORTS; UDP: $UDP_PORTS)
DHT / UDP tracker:     $ENABLE_DHT / $ENABLE_UDP_TRACKER
Plain TCP handshake:   $ENABLE_HANDSHAKE
Connlimit:             $ENABLE_CONNLIMIT (max $CONNLIMIT_MAX)
Rate-limited logging:  $ENABLE_LOG
NOTE: encrypted, tunneled and fragmented BitTorrent may bypass this filter.
PREVIEW
}
status_family() {
  local bin="$1" title="$2" chain hook gen role
  printf '\n=== %s (%s) ===\n' "$title" "$bin"
  if ! has_family "$bin"; then printf 'Unavailable\n'; return 0; fi
  for hook in "${hooks[@]}"; do
    if hook_exists "$bin" "$hook"; then
      ipt "$bin" -S "$hook" | grep -E -- '-j TG_(EG_|IN_|LM_|EGRESS|INPUT|LIMIT)' || true
    fi
  done
  for gen in A B; do
    for role in egress input limit drop; do
      chain="$(chain_name "$gen" "$role")"
      chain_exists "$bin" "$chain" && ipt "$bin" -L "$chain" -n -v -x
    done
  done
  for chain in "${legacy_chains[@]}"; do
    chain_exists "$bin" "$chain" && ipt "$bin" -L "$chain" -n -v -x
  done
  if [[ "$FILTER_OUTPUT" == 1 ]] && ! (ipt "$bin" -S OUTPUT | grep -qE -- '-j TG_EG_[AB]'); then
    warn "$title: OUTPUT selected but TorrentGuard hook not active!"
  fi
  if [[ "$FILTER_DOCKER_USER" == 1 ]] && ! hook_exists "$bin" DOCKER-USER; then
    warn "$title: Docker chain absent. If using Docker bridge, verify FORWARD path."
  fi
}
main() {
  case "${1:-help}" in
    help|-h|--help) usage ;;
    apply) load_config; apply_rules ;;
    remove) remove_rules ;;
    preview) load_config; show_preview ;;
    status) require_root; load_config; show_preview; status_family "$IPTABLES_BIN" IPv4; status_family "$IP6TABLES_BIN" IPv6 ;;
    *) usage; die "Unknown command: ${1:-}" ;;
  esac
}
main "$@"
