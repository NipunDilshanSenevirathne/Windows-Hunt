#!/usr/bin/env bash
# scope_gate.sh — authorization enforcement for Windows Hunt. FAILS CLOSED.
#
#   scope_gate.sh target <path|name|sha256>   # may I analyse this binary/installer?
#   scope_gate.sh host   <host|url>           # may I send a LIVE request here?
#   scope_gate.sh action <verb>               # may I perform this intrusive action?
#
# Exit 0 = authorized. Exit 1 = REFUSED. Deny entries ('!' prefix) always beat allows.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TGT="${TARGETS_FILE:-$HERE/scope/authorized_targets.txt}"
HOSTS="${HOSTS_FILE:-$HERE/scope/authorized_hosts.txt}"
ACTS="${ACTIONS_FILE:-$HERE/scope/authorized_actions.txt}"
kind="${1:-}"; target="${2:-}"
[ -z "$kind" ] || [ -z "$target" ] && { echo "usage: scope_gate.sh target|host|action <value>"; exit 1; }
norm(){ printf '%s' "$1" | tr 'A-Z' 'a-z' | tr -d '[:space:]'; }

match_target(){
  local v="$1" e="$2"
  # entry forms: product name, file basename, sha256, or path prefix ending in /
  case "$e" in
    */) [[ "$v" == "$e"* ]] && return 0 ;;
    *)  [ "$v" = "$e" ] && return 0
        [[ "$(basename "$v")" == "$e" ]] && return 0
        # sha256 entry matches if the value IS that digest
        [[ "$e" =~ ^[0-9a-f]{64}$ && "$v" == "$e" ]] && return 0 ;;
  esac
  return 1
}

if [ "$kind" = "target" ]; then
  v="$(norm "$target")"
  [ -s "$TGT" ] || { echo "scope_gate: $TGT empty — add authorized targets. REFUSING '$v'."; exit 1; }
  while IFS= read -r raw; do
    e="$(norm "${raw%%#*}")"; [ -z "$e" ] && continue
    case "$e" in '!'*) if match_target "$v" "${e#\!}"; then
        echo "OUT-OF-SCOPE-TARGET (EXCLUSION '${e#\!}'): $target — REFUSED."; exit 1; fi ;;
    esac
  done < "$TGT"
  while IFS= read -r raw; do
    e="$(norm "${raw%%#*}")"; [ -z "$e" ] && continue
    case "$e" in '!'*) continue ;; esac
    if match_target "$v" "$e"; then echo "AUTHORIZED-TARGET ($e): $target"; exit 0; fi
  done < "$TGT"
  echo "UNAUTHORIZED-TARGET: $target — not in $TGT. REFUSED."; exit 1
fi

if [ "$kind" = "host" ]; then
  full="$(norm "$target")"
  host="$target"; host="${host#*://}"; host="${host%%/*}"; host="${host##*@}"; host="${host%%:*}"
  host="$(norm "$host")"
  [ -s "$HOSTS" ] || { echo "scope_gate: $HOSTS empty — no live request authorized. REFUSING '$host'."; exit 1; }
  while IFS= read -r raw; do
    e="$(norm "${raw%%#*}")"; [ -z "$e" ] && continue
    case "$e" in
      '!path:'*) p="${e#\!path:}"; [[ "$full" == *"$p"* ]] && { echo "OUT-OF-SCOPE-HOST (PATH EXCLUSION '$p'): $target — REFUSED."; exit 1; } ;;
      '!*'*)     s="${e#\!\*}";   [[ "$host" == *"$s" ]]   && { echo "OUT-OF-SCOPE-HOST (EXCLUSION '*$s'): $host — REFUSED."; exit 1; } ;;
      '!'*)      s="${e#\!}";     { [ "$host" = "$s" ] || [[ "$host" == *".$s" ]]; } && { echo "OUT-OF-SCOPE-HOST (EXCLUSION '$s'): $host — REFUSED."; exit 1; } ;;
    esac
  done < "$HOSTS"
  while IFS= read -r raw; do
    e="$(norm "${raw%%#*}")"; [ -z "$e" ] && continue
    case "$e" in '!'*) continue ;; esac
    if [ "$host" = "$e" ] || [[ "$host" == *".$e" ]]; then echo "IN-SCOPE-HOST ($e): $host"; exit 0; fi
  done < "$HOSTS"
  echo "OUT-OF-SCOPE-HOST: $host — not in $HOSTS. REFUSED."; exit 1
fi

if [ "$kind" = "action" ]; then
  v="$(norm "$target")"
  [ -s "$ACTS" ] || { echo "scope_gate: $ACTS empty — only passive static analysis authorized. REFUSING '$v'."; exit 1; }
  while IFS= read -r raw; do
    e="$(norm "${raw%%#*}")"; [ -z "$e" ] && continue
    case "$e" in '!'*) [ "$v" = "${e#\!}" ] && { echo "FORBIDDEN-ACTION: $v — REFUSED."; exit 1; } ;; esac
  done < "$ACTS"
  while IFS= read -r raw; do
    e="$(norm "${raw%%#*}")"; [ -z "$e" ] && continue
    case "$e" in '!'*) continue ;; esac
    [ "$v" = "$e" ] && { echo "AUTHORIZED-ACTION: $v"; exit 0; }
  done < "$ACTS"
  echo "UNAUTHORIZED-ACTION: $v — not in $ACTS. REFUSED."; exit 1
fi
echo "scope_gate: unknown kind '$kind' (use target|host|action)"; exit 1
