#!/usr/bin/env bash
# =============================================================================
# Cerberus Pi — iptables block helper (Phase 5.3)
# Invoked ONLY through the restricted sudoers entry by the Django service user.
# Adds a DROP for the given IP to a dedicated, auditable CERBERUS-BLOCK chain.
#
#   sudo /opt/cerberus/scripts/block_ip.sh <ip>
#   sudo /opt/cerberus/scripts/block_ip.sh --unblock <ip>
#   sudo /opt/cerberus/scripts/block_ip.sh --list
# =============================================================================
set -euo pipefail

CHAIN="CERBERUS-BLOCK"

ensure_chain() {
  iptables -L "$CHAIN" -n >/dev/null 2>&1 || {
    iptables -N "$CHAIN"
    # Hook the chain into INPUT and FORWARD once.
    iptables -C INPUT -j "$CHAIN" 2>/dev/null || iptables -I INPUT 1 -j "$CHAIN"
    iptables -C FORWARD -j "$CHAIN" 2>/dev/null || iptables -I FORWARD 1 -j "$CHAIN"
  }
}

valid_ip() {
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || [[ "$1" =~ : ]]
}

case "${1:-}" in
  --list)
    ensure_chain
    iptables -L "$CHAIN" -n --line-numbers
    ;;
  --unblock)
    ip="${2:?usage: --unblock <ip>}"
    valid_ip "$ip" || { echo "invalid ip: $ip" >&2; exit 2; }
    ensure_chain
    iptables -D "$CHAIN" -s "$ip" -j DROP 2>/dev/null && echo "unblocked $ip" || echo "$ip not blocked"
    ;;
  "")
    echo "usage: block_ip.sh <ip> | --unblock <ip> | --list" >&2
    exit 2
    ;;
  *)
    ip="$1"
    valid_ip "$ip" || { echo "invalid ip: $ip" >&2; exit 2; }
    ensure_chain
    # Idempotent: only add if not already present.
    iptables -C "$CHAIN" -s "$ip" -j DROP 2>/dev/null || iptables -A "$CHAIN" -s "$ip" -j DROP
    echo "blocked $ip"
    ;;
esac
