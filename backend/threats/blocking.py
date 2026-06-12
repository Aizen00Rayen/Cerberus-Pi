"""
Source-IP blocking via iptables (Phase 5.3 — POST /api/threats/{id}/block/).

The Django service user has no sudo; blocking is delegated to a tiny setuid-free
helper invoked through a restricted sudoers entry that ONLY permits the exact
block command. See systemd/sudoers.d-cerberus in the repo.

We append a DROP rule to a dedicated CERBERUS-BLOCK chain so blocks are auditable
and reversible (iptables -F CERBERUS-BLOCK clears them).
"""
from __future__ import annotations

import ipaddress
import logging
import subprocess

logger = logging.getLogger("cerberus.blocking")

_BLOCK_CMD = ["/usr/bin/sudo", "-n", "/opt/cerberus/scripts/block_ip.sh"]


def _valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def block_source_ip(ip: str) -> tuple[bool, str]:
    """Block an IP. Returns (success, message). Validates input to avoid injection."""
    if not _valid_ip(ip):
        return False, f"Refusing to block invalid IP: {ip!r}"
    try:
        result = subprocess.run(
            [*_BLOCK_CMD, ip],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if result.returncode == 0:
            return True, f"{ip} blocked via CERBERUS-BLOCK chain."
        logger.error("block_ip.sh failed rc=%s: %s", result.returncode, result.stderr.strip())
        return False, f"Block helper failed: {result.stderr.strip() or 'unknown error'}"
    except FileNotFoundError:
        return False, "Block helper not installed (scripts/block_ip.sh)."
    except subprocess.TimeoutExpired:
        return False, "Block helper timed out."
