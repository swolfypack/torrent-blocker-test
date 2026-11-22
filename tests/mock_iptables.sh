#!/usr/bin/env bash
# Mock iptables that never modifies the real kernel rules.
set -euo pipefail
family=4
[[ "${0##*/}" == ip6tables ]] && family=6
base="${TG_MOCK_STATE:?}/$family"
mkdir -p "$base"
for builtin in INPUT OUTPUT FORWARD DOCKER-USER; do
  [[ -f "$base/$builtin" ]] || : > "$base/$builtin"
done

[[ "${1:-}" == '-w' ]] && shift 2
[[ "${1:-}" == '-t' ]] && shift 2
cmd="${1:-}"; shift || true
chain="${1:-}"
[[ $# == 0 ]] || shift
file="$base/$chain"
rule="$*"
if [[ "${TG_MOCK_FAIL_ON:-}" != '' && "$cmd" == '-A' && "$rule" == *"$TG_MOCK_FAIL_ON"* ]]; then
  echo "Simulated iptables insert failure: $TG_MOCK_FAIL_ON" >&2
  exit 42
fi
case "$cmd" in
  -S)
    if [[ -z "$chain" ]]; then
      for f in "$base"/*; do printf -- '-N %s\n' "${f##*/}"; done
    else
      [[ -e "$file" ]] || exit 1
      printf -- '-N %s\n' "$chain"
      while IFS= read -r line; do printf -- '-A %s %s\n' "$chain" "$line"; done < "$file"
    fi
    ;;
  -N) [[ ! -e "$file" ]] || exit 1; : > "$file" ;;
  -F) [[ -e "$file" ]] || exit 1; : > "$file" ;;
  -X) [[ -e "$file" && ! -s "$file" ]] || exit 1; rm "$file" ;;
  -A) [[ -e "$file" ]] || exit 1; printf '%s\n' "$rule" >> "$file" ;;
  -I)
    [[ -e "$file" ]] || exit 1
    [[ "${rule%% *}" == 1 ]] && rule="${rule#* }"
    { printf '%s\n' "$rule"; cat "$file"; } > "$file.tmp"
    mv "$file.tmp" "$file"
    ;;
  -C) [[ -e "$file" ]] && grep -Fqx -- "$rule" "$file" ;;
  -D)
    [[ -e "$file" ]] || exit 1
    grep -Fqx -- "$rule" "$file" || exit 1
    grep -Fvx -- "$rule" "$file" > "$file.tmp" || true
    mv "$file.tmp" "$file"
    ;;
  -L) [[ -e "$file" ]] || exit 1; printf 'Chain %s\n' "$chain"; cat "$file" ;;
  *) echo "Unsupported fake command: $cmd" >&2; exit 2 ;;
esac
