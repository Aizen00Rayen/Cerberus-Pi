"""Raspberry Pi system health (Phase 6.2 Settings page)."""
from __future__ import annotations

import os
import shutil
from pathlib import Path


def _cpu_percent() -> float | None:
    """Approximate CPU load via 1-minute loadavg / core count."""
    try:
        load1, _, _ = os.getloadavg()
        cores = os.cpu_count() or 1
        return round(min(load1 / cores * 100, 100), 1)
    except (OSError, AttributeError):
        return None


def _mem() -> dict:
    info = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, _, v = line.partition(":")
            info[k] = int(v.strip().split()[0])  # kB
        total = info.get("MemTotal", 0)
        avail = info.get("MemAvailable", 0)
        used = total - avail
        return {
            "total_mb": total // 1024,
            "used_mb": used // 1024,
            "percent": round(used / total * 100, 1) if total else None,
        }
    except (OSError, ValueError, ZeroDivisionError):
        return {"total_mb": None, "used_mb": None, "percent": None}


def _disk() -> dict:
    try:
        total, used, free = shutil.disk_usage("/")
        return {
            "total_gb": total // 2**30, "used_gb": used // 2**30,
            "free_gb": free // 2**30, "percent": round(used / total * 100, 1),
        }
    except OSError:
        return {}


def _temperature_c() -> float | None:
    """Pi CPU temperature from the thermal zone."""
    for p in ("/sys/class/thermal/thermal_zone0/temp",):
        try:
            return round(int(Path(p).read_text().strip()) / 1000, 1)
        except (OSError, ValueError):
            continue
    return None


def system_health() -> dict:
    return {
        "cpu_percent": _cpu_percent(),
        "memory": _mem(),
        "disk": _disk(),
        "temperature_c": _temperature_c(),
    }
