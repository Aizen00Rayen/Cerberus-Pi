"""
Scan-target validation (security-critical).

The scan `target` comes from the dashboard and is handed to nmap / arp-scan.
Without validation it is an argument-injection vector (e.g. a "target" of
'127.0.0.1 -oN /etc/passwd' or '--script=...' would inject nmap flags) and an
abuse vector (scanning arbitrary internet hosts from the appliance).

Policy: accept only the literal keyword "localnet" or a syntactically valid
IPv4 address / CIDR that falls inside a private, loopback, or link-local range.
Everything else is rejected. This kills both injection and external-scan abuse.
"""
from __future__ import annotations

import ipaddress

from rest_framework import serializers

LOCALNET = "localnet"


def _is_local(net: ipaddress.IPv4Network | ipaddress.IPv4Address) -> bool:
    return bool(net.is_private or net.is_loopback or net.is_link_local)


def validate_target(value: str) -> str:
    """Return a safe target string or raise serializers.ValidationError."""
    value = (value or "").strip()
    if value == LOCALNET:
        return value

    # No whitespace, dashes, or shell/arg metacharacters may reach the scanner.
    if any(c in value for c in " \t\n\r;|&$`'\"\\<>()") or value.startswith("-"):
        raise serializers.ValidationError(
            "Invalid target. Use 'localnet' or a private IPv4 address/CIDR."
        )

    try:
        if "/" in value:
            net = ipaddress.IPv4Network(value, strict=False)
        else:
            net = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        raise serializers.ValidationError(
            "Target must be a valid IPv4 address or CIDR (e.g. 192.168.1.0/24)."
        )

    if not _is_local(net):
        raise serializers.ValidationError(
            "Refusing to scan a non-local target. Only private/loopback/link-local "
            "ranges (RFC1918, 127.0.0.0/8, 169.254.0.0/16) are permitted."
        )
    return value


def is_safe_target(value: str) -> bool:
    """Non-raising variant for use deep in the worker as a second line of defence."""
    try:
        validate_target(value)
        return True
    except serializers.ValidationError:
        return False
