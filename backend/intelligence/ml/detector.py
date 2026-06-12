"""
Phase 11.4 — Central inference engine.

Models are loaded once into a class-level cache at Django startup
(IntelligenceConfig.ready) and never reloaded per request — the Pi cannot absorb
that I/O. All detection paths are fully offline (no external calls). The TFLite
interpreter (DoS LSTM) is guarded by a threading.Lock.

Every detector degrades gracefully: if a model artifact is missing (e.g. during
the 72h baseline phase before first training) the detector returns
{'detected': False, ...} so callers can fall back to rule-based behaviour.
"""
from __future__ import annotations

import json
import logging
import math
import threading

from .feature_extractor import (
    SQLiFeatureExtractor, XSSFeatureExtractor, BruteForceFeatureExtractor,
    DoSFeatureExtractor, combine_text_features,
)
from . import artifacts as A

logger = logging.getLogger("cerberus.intelligence")

# Default thresholds (Phase 11.4). Admin overrides are stored in Redis and merged
# at read time so changes take effect without a restart.
DETECTION_THRESHOLDS = {
    "sqli": 0.65,
    "xss": 0.70,
    "bruteforce": -0.10,
    "dos_pps": 3.0,
    "dos_bps": 3.0,
    "dos_syn_ratio": 10.0,
    "dos_lstm": 0.75,
}
_REDIS_KEY = "cerberus:intelligence:thresholds"

# In-process threshold cache. The detection hot path must NOT hit Redis per call
# (that adds a network round-trip — or a multi-second hang if Redis is down).
# We refresh from Redis at most once per _THRESHOLD_TTL seconds; admin updates
# refresh the cache immediately via set_thresholds.
_threshold_cache: dict | None = None
_threshold_loaded_at = 0.0
_THRESHOLD_TTL = 30.0


def _redis_client():
    import redis
    from django.conf import settings
    # Fast-fail so a down/unreachable Redis never stalls inference.
    return redis.Redis.from_url(
        settings.REDIS_URL, socket_connect_timeout=0.3, socket_timeout=0.3,
    )


def _refresh_thresholds() -> dict:
    merged = dict(DETECTION_THRESHOLDS)
    try:
        raw = _redis_client().get(_REDIS_KEY)
        if raw:
            merged.update(json.loads(raw))
    except Exception:  # noqa: BLE001 — Redis optional; defaults are fine
        pass
    return merged


def get_thresholds() -> dict:
    global _threshold_cache, _threshold_loaded_at
    import time
    now = time.monotonic()
    if _threshold_cache is None or (now - _threshold_loaded_at) > _THRESHOLD_TTL:
        _threshold_cache = _refresh_thresholds()
        _threshold_loaded_at = now
    return _threshold_cache


def set_thresholds(updates: dict) -> dict:
    global _threshold_cache, _threshold_loaded_at
    import time
    merged = get_thresholds().copy()
    merged.update({k: float(v) for k, v in updates.items() if k in DETECTION_THRESHOLDS})
    try:
        _redis_client().set(_REDIS_KEY, json.dumps(merged))
    except Exception:  # noqa: BLE001
        pass
    _threshold_cache = merged          # reflect immediately, even if Redis is down
    _threshold_loaded_at = time.monotonic()
    return merged


class CerberusDetector:
    _models: dict = {}
    _vectorizers: dict = {}
    _scalers: dict = {}
    _thresholds_dos: dict = {}
    _baselines: dict = {}
    _tflite_interpreter = None
    _tflite_lock = threading.Lock()
    _loaded = False

    _sqli_x = SQLiFeatureExtractor()
    _xss_x = XSSFeatureExtractor()
    _bf_x = BruteForceFeatureExtractor()
    _dos_x = DoSFeatureExtractor()

    # -- loading -----------------------------------------------------------
    @classmethod
    def load_all_models(cls):
        cls._load_text("sqli")
        cls._load_text("xss")
        cls._load_bruteforce()
        cls._load_dos()
        cls._loaded = True
        logger.info("Intelligence models loaded: %s", sorted(cls._models))

    @classmethod
    def _load_text(cls, attack):
        d = A.model_dir(attack)
        mp, vp = d / "model_current.pkl", d / "vectorizer_current.pkl"
        if mp.exists() and vp.exists():
            cls._models[attack] = A.load_pickle(mp)
            cls._vectorizers[attack] = A.load_pickle(vp)

    @classmethod
    def _load_bruteforce(cls):
        d = A.model_dir("bruteforce")
        mp, sp = d / "model_current.pkl", d / "scaler_current.pkl"
        if mp.exists() and sp.exists():
            cls._models["bruteforce"] = A.load_pickle(mp)
            cls._scalers["bruteforce"] = A.load_pickle(sp)
        bj = d / "baseline_current.json"
        if bj.exists():
            try:
                cls._baselines = json.loads(bj.read_text())
            except (OSError, json.JSONDecodeError):
                cls._baselines = {}

    @classmethod
    def _load_dos(cls):
        d = A.model_dir("dos")
        tj = d / "thresholds_current.json"
        if tj.exists():
            try:
                cls._thresholds_dos = json.loads(tj.read_text())
            except (OSError, json.JSONDecodeError):
                cls._thresholds_dos = {}
        tfl = d / "lstm_current.tflite"
        if tfl.exists():
            cls._init_tflite(tfl)

    @classmethod
    def _init_tflite(cls, path):
        try:
            try:
                import tflite_runtime.interpreter as tflite
            except ImportError:
                from tensorflow import lite as tflite  # full TF fallback
            interp = tflite.Interpreter(model_path=str(path))
            interp.allocate_tensors()
            cls._tflite_interpreter = interp
        except Exception as exc:  # noqa: BLE001
            logger.warning("TFLite interpreter unavailable: %s", exc)
            cls._tflite_interpreter = None

    # -- SQLi / XSS --------------------------------------------------------
    def _detect_text(self, attack, payload, explain_fn, extractor):
        model = self._models.get(attack)
        vec = self._vectorizers.get(attack)
        if model is None or vec is None:
            return {"detected": False, "confidence": 0.0,
                    "features_triggered": [], "attack_type": attack, "fallback": True}
        feats = extractor.extract(payload)
        X = combine_text_features([payload], extractor, vec, extractor.NUMERIC_KEYS, fit=False)
        confidence = float(model.predict_proba(X)[0][1])
        thr = get_thresholds()[attack]
        return {
            "detected": confidence >= thr,
            "confidence": round(confidence, 4),
            "features_triggered": explain_fn(feats),
            "attack_type": attack,
            "raw_features": {k: feats[k] for k in extractor.NUMERIC_KEYS},
        }

    def detect_sqli(self, payload: str) -> dict:
        return self._detect_text("sqli", payload or "", self._explain_sqli, self._sqli_x)

    def detect_xss(self, payload: str) -> dict:
        return self._detect_text("xss", payload or "", self._explain_xss, self._xss_x)

    # -- Brute force -------------------------------------------------------
    def detect_bruteforce(self, ip: str, events: list) -> dict:
        model = self._models.get("bruteforce")
        scaler = self._scalers.get("bruteforce")
        baseline = self._baselines.get(ip, {})
        feats = self._bf_x.extract(ip, events or [], baseline)
        if model is None or scaler is None:
            # Baseline-phase fallback: static rule (>10 failed/min).
            failed = sum(1 for e in (events or []) if e.get("success") is False)
            detected = failed > 10
            return {"detected": detected, "confidence": 1.0 if detected else 0.0,
                    "anomaly_score": None, "attack_type": "bruteforce",
                    "features_triggered": self._explain_bruteforce(feats),
                    "raw_features": feats, "fallback": True}
        from .feature_extractor import numeric_vector
        vec = [numeric_vector(feats, self._bf_x.NUMERIC_KEYS)]
        score = float(model.decision_function(scaler.transform(vec))[0])
        thr = get_thresholds()["bruteforce"]
        # Map the (roughly -0.5..0.5) IF score to a 0..1 confidence.
        confidence = 1 / (1 + math.exp(score * 8))
        return {
            "detected": score < thr,
            "confidence": round(confidence, 4),
            "anomaly_score": round(score, 4),
            "attack_type": "bruteforce",
            "features_triggered": self._explain_bruteforce(feats),
            "raw_features": feats,
        }

    # -- DoS ---------------------------------------------------------------
    def detect_dos_statistical(self, window: dict) -> dict:
        thr = get_thresholds()
        t = self._thresholds_dos or {}
        mult = (t.get("multiplier") or 3.0)
        pps = window.get("packets_per_second", 0)
        bps = window.get("bytes_per_second", 0)
        syn = window.get("syn_count", 0)
        ack = window.get("ack_count", 1)
        pps_thr = (t.get("pps", {}) or {}).get("threshold", 100 * mult)
        bps_thr = (t.get("bps", {}) or {}).get("threshold", 50000 * mult)
        syn_ratio = syn / max(ack, 1)

        reasons = []
        if pps > pps_thr:
            reasons.append(f"Packet rate {pps:.0f}/s exceeds threshold {pps_thr:.0f}/s")
        if bps > bps_thr:
            reasons.append(f"Byte rate {bps/1e6:.1f} Mbps exceeds threshold {bps_thr/1e6:.1f} Mbps")
        if syn_ratio > thr["dos_syn_ratio"]:
            reasons.append(f"SYN/ACK ratio {syn_ratio:.1f} indicates SYN flood")
        detected = bool(reasons)
        return {"detected": detected, "confidence": 1.0 if detected else 0.0,
                "attack_type": "dos", "layer": "statistical",
                "features_triggered": reasons[:3]}

    def detect_dos_lstm(self, sequence: list) -> dict:
        if self._tflite_interpreter is None:
            return {"detected": False, "confidence": 0.0, "attack_type": "dos",
                    "layer": "lstm", "features_triggered": [], "fallback": True}
        import numpy as np
        with self._tflite_lock:
            interp = self._tflite_interpreter
            inp = interp.get_input_details()[0]
            out = interp.get_output_details()[0]
            arr = np.asarray([sequence], dtype="float32")
            interp.set_tensor(inp["index"], arr)
            interp.invoke()
            conf = float(interp.get_tensor(out["index"])[0][0])
        thr = get_thresholds()["dos_lstm"]
        return {"detected": conf >= thr, "confidence": round(conf, 4),
                "attack_type": "dos", "layer": "lstm",
                "features_triggered": ["LSTM sequence anomaly"] if conf >= thr else []}

    # -- explanations ------------------------------------------------------
    @staticmethod
    def _explain_sqli(f: dict) -> list:
        reasons = []
        if f.get("has_union"):
            reasons.append("UNION keyword detected in payload")
        if f.get("has_sleep"):
            reasons.append("Time-based blind SQLi keyword (SLEEP/BENCHMARK/WAITFOR)")
        if f.get("special_char_ratio", 0) > 0.15:
            reasons.append(f"High special-character ratio: {f['special_char_ratio']:.0%}")
        if f.get("url_encoded"):
            reasons.append("URL-encoded SQL metacharacters detected")
        if f.get("has_comment"):
            reasons.append("SQL comment sequence detected (--, #, /*)")
        if f.get("keyword_count", 0) >= 2:
            reasons.append(f"{f['keyword_count']} SQL keywords present")
        return reasons[:3] or ["Statistical similarity to known SQLi payloads"]

    @staticmethod
    def _explain_xss(f: dict) -> list:
        reasons = []
        if f.get("has_script_tag"):
            reasons.append("<script> tag detected")
        if f.get("has_event_handler"):
            reasons.append("Inline event handler (onerror/onload/onclick)")
        if f.get("has_javascript_proto"):
            reasons.append("javascript: protocol handler detected")
        if f.get("has_data_uri"):
            reasons.append("data: URI detected")
        if f.get("tag_count", 0) >= 1 and f.get("angle_bracket_count", 0) >= 2:
            reasons.append("HTML tag injection pattern")
        return reasons[:3] or ["Statistical similarity to known XSS payloads"]

    @staticmethod
    def _explain_bruteforce(f: dict) -> list:
        reasons = []
        if f.get("failed_ratio", 0) > 0.5:
            reasons.append(f"High auth-failure ratio: {f['failed_ratio']:.0%}")
        if f.get("has_rapid_fire"):
            reasons.append("Rapid-fire requests (<500ms apart)")
        if f.get("request_regularity", 1) < 0.5 and f.get("request_count", 0) > 5:
            reasons.append("Highly regular timing (automated)")
        if f.get("deviation_from_baseline", 0) > 3:
            reasons.append(f"{f['deviation_from_baseline']:.1f}× normal request volume")
        if f.get("unique_usernames", 0) > 5:
            reasons.append(f"{f['unique_usernames']} distinct usernames tried")
        return reasons[:3] or ["Behavioural anomaly vs. baseline"]
