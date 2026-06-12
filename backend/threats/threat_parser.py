"""
Phase 5.4 — Threat Parser.

Tails the Suricata EVE JSON log and Snort JSON alerts in real time, normalises
each alert into the unified Threat model, deduplicates repeats (same signature +
src/dst within 60s), assigns severity, generates advice, and pushes the new
threat to the /ws/threats/ WebSocket channel.

Run as a long-lived process (see threats/management/commands/run_parser.py or the
cerberus-backend service). Pure-stdlib tailing so it has no extra deps.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("cerberus.parser")

# Suricata "alert.severity" (1=highest) → our Severity enum.
_SURICATA_SEVERITY = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}
# Snort priority (1=highest) → our Severity enum.
_SNORT_PRIORITY = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}

DEDUP_WINDOW_SECONDS = 60


def _parse_ts(value) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        # Suricata uses ISO8601 with offset, e.g. 2026-06-12T09:15:00.123456+0000
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _dedup_key(signature: str, src_ip, dst_ip, ts: datetime) -> str:
    bucket = int(ts.timestamp()) // DEDUP_WINDOW_SECONDS
    raw = f"{signature}|{src_ip}|{dst_ip}|{bucket}"
    return hashlib.sha256(raw.encode()).hexdigest()[:64]


def normalise_suricata(evt: dict) -> dict | None:
    """Map a Suricata EVE 'alert' event to Threat fields. Returns None for non-alerts."""
    if evt.get("event_type") != "alert":
        return None
    alert = evt.get("alert", {})
    ts = _parse_ts(evt.get("timestamp"))
    severity = _SURICATA_SEVERITY.get(alert.get("severity", 3), "MEDIUM")
    return {
        "timestamp": ts,
        "engine": "suricata",
        "severity": severity,
        "category": alert.get("category", "") or "",
        "src_ip": evt.get("src_ip"),
        "dst_ip": evt.get("dest_ip"),
        "src_port": evt.get("src_port"),
        "dst_port": evt.get("dest_port"),
        "protocol": evt.get("proto", ""),
        "signature": alert.get("signature", "") or "",
        "description": alert.get("signature", "") or "",
        "raw_alert": evt,
    }


def normalise_snort(evt: dict) -> dict | None:
    """Map a Snort 3 JSON alert to Threat fields."""
    # Snort 3 alert_json plugin emits flat records with these keys.
    if "msg" not in evt and "sig_id" not in evt:
        return None
    ts = _parse_ts(evt.get("timestamp") or evt.get("ts"))
    severity = _SNORT_PRIORITY.get(int(evt.get("priority", 3) or 3), "MEDIUM")
    return {
        "timestamp": ts,
        "engine": "snort",
        "severity": severity,
        "category": evt.get("class") or evt.get("classification", "") or "",
        "src_ip": evt.get("src_addr") or evt.get("src_ap", "").split(":")[0] or None,
        "dst_ip": evt.get("dst_addr") or evt.get("dst_ap", "").split(":")[0] or None,
        "src_port": _safe_int(evt.get("src_port")),
        "dst_port": _safe_int(evt.get("dst_port")),
        "protocol": evt.get("proto", ""),
        "signature": evt.get("msg", "") or "",
        "description": evt.get("msg", "") or "",
        "raw_alert": evt,
    }


def _safe_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def persist_and_broadcast(fields: dict):
    """Create a Threat (deduped), attach advice, and push to the WS channel."""
    from threats.models import Threat
    from threats.advice_engine import get_advice

    ts = fields["timestamp"]
    key = _dedup_key(fields.get("signature", ""), fields.get("src_ip"), fields.get("dst_ip"), ts)

    # Dedup: skip if an identical alert already exists in this 60s bucket.
    if Threat.objects.filter(dedup_key=key).exists():
        return None

    fields["dedup_key"] = key
    fields["advice"] = get_advice(
        fields.get("category", ""),
        fields.get("signature", ""),
        severity=fields.get("severity", "MEDIUM"),
        src_ip=fields.get("src_ip"),
    )
    threat = Threat.objects.create(**fields)
    _broadcast(threat)
    return threat


def _broadcast(threat):
    """Push the new threat to the /ws/threats/ group."""
    try:
        from asgiref.sync import async_to_sync
        from channels.layers import get_channel_layer
        from threats.serializers import ThreatSerializer

        layer = get_channel_layer()
        if layer is None:
            return
        async_to_sync(layer.group_send)(
            "threats",
            {"type": "threat.new", "data": ThreatSerializer(threat).data},
        )
    except Exception as exc:  # noqa: BLE001 — broadcast failure must not lose the alert
        logger.warning("WS broadcast failed: %s", exc)


def tail(path: Path, normaliser, poll: float = 0.5):
    """Generator yielding normalised dicts from a growing JSON-lines file."""
    path = Path(path)
    while not path.exists():
        logger.info("Waiting for %s to appear...", path)
        time.sleep(2)
    with path.open("r", errors="replace") as fh:
        fh.seek(0, os.SEEK_END)  # start at end — only new alerts
        inode = os.fstat(fh.fileno()).st_ino
        while True:
            line = fh.readline()
            if not line:
                # Handle log rotation: reopen if the inode changed.
                try:
                    if os.stat(path).st_ino != inode:
                        fh.close()
                        return  # caller restarts the tail
                except FileNotFoundError:
                    pass
                time.sleep(poll)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue
            fields = normaliser(evt)
            if fields:
                yield fields


def run(eve_path: Path, snort_glob: Path):
    """
    Single-threaded multiplexed tail. For production the cerberus-backend service
    runs two `run_parser` commands (one per engine) so each can restart on rotation.
    This function tails Suricata; Snort is handled by a sibling invocation.
    """
    logger.info("Threat parser tailing %s", eve_path)
    while True:
        try:
            for fields in tail(eve_path, normalise_suricata):
                persist_and_broadcast(fields)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Parser loop error, restarting in 3s: %s", exc)
            time.sleep(3)
