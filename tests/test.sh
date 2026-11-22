#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $EUID == 0 ]] || { echo 'Run mock-only tests as root: sudo bash tests/test.sh' >&2; exit 1; }
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
ln -s "$ROOT/tests/mock_iptables.sh" "$TMP/iptables"
ln -s "$ROOT/tests/mock_iptables.sh" "$TMP/ip6tables"
cp "$ROOT/config/torrent-guard.conf.example" "$TMP/config"
sed -i -e "s/^EGRESS_IFACE=.*/EGRESS_IFACE='' /" -e "s/^IPV6_EGRESS_IFACE=.*/IPV6_EGRESS_IFACE='' /" "$TMP/config"
export IPTABLES_BIN="$TMP/iptables" IP6TABLES_BIN="$TMP/ip6tables"
export TORRENT_GUARD_CONFIG="$TMP/config" TG_MOCK_STATE="$TMP/mock"

bash -n "$ROOT"/scripts/*.sh "$ROOT"/tests/*.sh
"$ROOT/scripts/torrent-guard.sh" preview >/dev/null
# An unrelated firewall rule must survive all operations.
"$IPTABLES_BIN" -A OUTPUT -p tcp --dport 22 -j ACCEPT
"$ROOT/scripts/torrent-guard.sh" apply
for family in 4 6; do
  [[ $(grep -Fxc -- '-j TG_EG_A' "$TMP/mock/$family/OUTPUT") == 1 ]]
  [[ $(wc -l < "$TMP/mock/$family/TG_EG_A") == 11 ]]
  grep -Fq -- '--algo kmp --hex-string |13|BitTorrent protocol' "$TMP/mock/$family/TG_EG_A"
  grep -Fq -- '--hex-string |00 00 04 17 27 10 19 80|' "$TMP/mock/$family/TG_EG_A"
done
echo 'PASS: generation A, IPv4/IPv6, KMP, plaintext handshake, UDP tracker'

# A second apply switches generation rather than flushing the live generation.
"$ROOT/scripts/torrent-guard.sh" apply
for family in 4 6; do
  [[ ! -e "$TMP/mock/$family/TG_EG_A" ]]
  [[ $(grep -Fxc -- '-j TG_EG_B' "$TMP/mock/$family/OUTPUT") == 1 ]]
  [[ $(grep -Fxc -- '-j TG_EG_B' "$TMP/mock/$family/FORWARD") == 1 ]]
  [[ $(grep -Fxc -- '-j TG_EG_B' "$TMP/mock/$family/DOCKER-USER") == 1 ]]
  [[ ! -s "$TMP/mock/$family/INPUT" ]]
done
echo 'PASS: updates switch generations and keep only one hook'

# Simulate failure to add a rule during an update: old active hooks survive.
if TG_MOCK_FAIL_ON='|13|BitTorrent protocol' "$ROOT/scripts/torrent-guard.sh" apply >/dev/null 2>&1; then
  echo 'FAIL: expected mock firewall error' >&2
  exit 1
fi
[[ $(grep -Fxc -- '-j TG_EG_B' "$TMP/mock/4/OUTPUT") == 1 ]]
[[ $(grep -Fxc -- '-j TG_EG_B' "$TMP/mock/4/FORWARD") == 1 ]]
echo 'PASS: failed rule build does not detach previous active hooks'

# Apply succeeds after failed update and cleans incomplete generation.
sed -i -e 's/^FILTER_FORWARD=1/FILTER_FORWARD=0/' -e 's/^FILTER_DOCKER_USER=1/FILTER_DOCKER_USER=0/' -e 's/^ENABLE_IPV6=1/ENABLE_IPV6=0/' "$TMP/config"
"$ROOT/scripts/torrent-guard.sh" apply
[[ $(grep -Fxc -- '-j TG_EG_A' "$TMP/mock/4/OUTPUT") == 1 ]]
[[ ! -e "$TMP/mock/6/TG_EG_A" ]]
[[ ! -e "$TMP/mock/6/TG_EG_B" ]]
! grep -q -- 'TG_EG_' "$TMP/mock/4/FORWARD"
! grep -q -- 'TG_EG_' "$TMP/mock/4/DOCKER-USER"
echo 'PASS: config change, IPv6 cleanup, recovery from failed staging'

sed -i -e 's/^ENABLE_CONNLIMIT=0/ENABLE_CONNLIMIT=1/' -e 's/^ENABLE_LOG=0/ENABLE_LOG=1/' -e 's/^FILTER_INPUT=0/FILTER_INPUT=1/' -e 's/^FILTER_FORWARD=0/FILTER_FORWARD=1/' "$TMP/config"
"$ROOT/scripts/torrent-guard.sh" apply
[[ $(wc -l < "$TMP/mock/4/TG_LM_B") == 1 ]]
[[ $(wc -l < "$TMP/mock/4/TG_DP_B") == 2 ]]
[[ $(grep -Fxc -- '-j TG_IN_B' "$TMP/mock/4/INPUT") == 1 ]]
[[ $(grep -Fxc -- '-j TG_LM_B' "$TMP/mock/4/FORWARD") == 1 ]]
echo 'PASS: optional INPUT, connection limit and logging'

# Legacy v1.0.0 chain migration, without flushing unrelated rules.
"$IPTABLES_BIN" -N TG_EGRESS
"$IPTABLES_BIN" -N TG_DROP
"$IPTABLES_BIN" -A TG_DROP -j DROP
"$IPTABLES_BIN" -A TG_EGRESS -j TG_DROP
"$IPTABLES_BIN" -I OUTPUT 1 -j TG_EGRESS
"$ROOT/scripts/torrent-guard.sh" apply
[[ ! -e "$TMP/mock/4/TG_EGRESS" && ! -e "$TMP/mock/4/TG_DROP" ]]
[[ $(grep -Fxc -- '-j TG_EG_A' "$TMP/mock/4/OUTPUT") == 1 ]]
echo 'PASS: automatic migration from original v1.0.0 managed chains'

"$ROOT/scripts/torrent-guard.sh" status >/dev/null
"$ROOT/scripts/torrent-guard.sh" remove
for family in 4 6; do
  for chain in TG_EG_A TG_EG_B TG_IN_A TG_IN_B TG_LM_A TG_LM_B TG_DP_A TG_DP_B TG_EGRESS TG_INPUT TG_LIMIT TG_DROP; do
    [[ ! -e "$TMP/mock/$family/$chain" ]]
  done
done
[[ $(grep -Fxc -- '-p tcp --dport 22 -j ACCEPT' "$TMP/mock/4/OUTPUT") == 1 ]]
echo 'PASS: removal leaves unrelated firewall rule unchanged'

sed -i "s/^TCP_PORTS=.*/TCP_PORTS='70000'/" "$TMP/config"
if "$ROOT/scripts/torrent-guard.sh" preview >/dev/null 2>&1; then
  echo 'FAIL: accepted invalid port' >&2
  exit 1
fi
echo 'PASS: validation rejects invalid port'
