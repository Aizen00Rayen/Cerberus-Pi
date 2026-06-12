"""
Engine control (Phase 5.3 — POST /api/engine/restart/).

Like IP blocking, the unprivileged Django user controls systemd units through a
narrow sudoers entry that ONLY allows `systemctl <action> cerberus-<engine>.service`.
See systemd/sudoers.d-cerberus.
"""
from __future__ import annotations

import logging
import subprocess

logger = logging.getLogger("cerberus.engine.control")

_ALLOWED_ENGINES = {"suricata", "snort"}
_ALLOWED_ACTIONS = {"start", "stop", "restart", "status"}


def control_engine(engine: str, action: str) -> tuple[bool, str]:
    if engine not in _ALLOWED_ENGINES:
        return False, f"Unknown engine: {engine!r}"
    if action not in _ALLOWED_ACTIONS:
        return False, f"Unknown action: {action!r}"
    unit = f"cerberus-{engine}.service"
    try:
        result = subprocess.run(
            ["/usr/bin/sudo", "-n", "/usr/bin/systemctl", action, unit],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if result.returncode == 0:
            return True, f"{action} {unit} OK"
        return False, result.stderr.strip() or f"systemctl {action} failed"
    except FileNotFoundError:
        return False, "systemctl/sudo not available"
    except subprocess.TimeoutExpired:
        return False, "systemctl timed out"
