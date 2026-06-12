"""
Phase 11.6.1 — Integration hook called by the existing threat parser.

This is the ONLY coupling to the threats app: threats.threat_parser calls
run_ml_analysis(threat, payload) AFTER it has already saved the Threat. It never
modifies existing parsing logic, and any failure here is swallowed so the core
IDS pipeline is never affected by ML.
"""
from __future__ import annotations

import logging

logger = logging.getLogger("cerberus.intelligence")


def extract_payload_from_alert(raw_alert: dict, signature: str = "") -> str:
    """Best-effort reconstruction of an HTTP payload string from a Suricata event."""
    if not isinstance(raw_alert, dict):
        return signature or ""
    http = raw_alert.get("http", {}) or {}
    parts = [
        http.get("url", ""),
        http.get("http_user_agent", ""),
        http.get("hostname", ""),
        raw_alert.get("payload_printable", ""),
    ]
    joined = " ".join(p for p in parts if p)
    return joined or signature or ""


def get_recent_auth_events(ip: str, window_seconds: int = 60) -> list:
    """Recent auth attempts for an IP, from the Phase 10 LoginAudit table."""
    try:
        from django.utils import timezone
        from auth_audit.models import LoginAudit
        since = timezone.now() - timezone.timedelta(seconds=window_seconds)
        rows = LoginAudit.objects.filter(ip_address=ip, timestamp__gte=since)
        return [{"success": r.success, "username": r.username,
                 "endpoint": "/api/auth/login/", "timestamp": r.timestamp} for r in rows]
    except Exception:  # noqa: BLE001
        return []


def run_ml_analysis(threat_obj, raw_payload: str = ""):
    """
    Run the relevant ML detector for a freshly-created Threat and, if it fires,
    create a linked AnomalyDetection + push it to the WebSocket feed.
    """
    try:
        from intelligence.ml.detector import CerberusDetector
        from intelligence.models import AnomalyDetection, MLModel
        from intelligence.realtime import broadcast_detection

        detector = CerberusDetector()
        category = (threat_obj.category or "").lower()
        signature = (getattr(threat_obj, "signature", "") or "").lower()
        haystack = f"{category} {signature}"
        payload = raw_payload or extract_payload_from_alert(
            getattr(threat_obj, "raw_alert", {}), threat_obj.signature)

        result = None
        if "sql" in haystack:
            result = detector.detect_sqli(payload)
        elif "xss" in haystack or "cross-site" in haystack or "script" in haystack:
            result = detector.detect_xss(payload)
        elif "brute" in haystack or "auth" in haystack or "login" in haystack:
            result = detector.detect_bruteforce(
                threat_obj.src_ip, get_recent_auth_events(threat_obj.src_ip))

        if not result or not result.get("detected"):
            return None

        model = MLModel.objects.filter(attack_type=result["attack_type"], status="active").first()
        det = AnomalyDetection.objects.create(
            attack_type=result["attack_type"],
            confidence_score=result.get("confidence", 0.0),
            anomaly_score=result.get("anomaly_score"),
            src_ip=threat_obj.src_ip,
            dst_ip=threat_obj.dst_ip,
            src_port=getattr(threat_obj, "src_port", None),
            dst_port=getattr(threat_obj, "dst_port", None),
            payload_sample=(payload or "")[:500],
            features_triggered=result.get("features_triggered", []),
            model_version=model,
            linked_threat=threat_obj,
            raw_features=result.get("raw_features", {}),
        )
        broadcast_detection(det)
        return det
    except Exception as exc:  # noqa: BLE001 — ML must never break the parser
        logger.warning("run_ml_analysis failed: %s", exc)
        return None
