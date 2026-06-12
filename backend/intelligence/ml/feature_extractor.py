"""
Phase 11.2 — Feature engineering for all four detectors.

Each extractor turns raw input into a feature dict. For the text-based models
(SQLi, XSS) the trainer and detector MUST build identical combined feature
vectors (TF-IDF ⊕ handcrafted numerics); the ordered key lists and the
`numeric_vector` / `combine_text_features` helpers below guarantee that.
"""
from __future__ import annotations

import math
from collections import Counter


# ---------------------------------------------------------------------------
# SQL Injection
# ---------------------------------------------------------------------------
class SQLiFeatureExtractor:
    SQL_KEYWORDS = [
        "select", "union", "insert", "update", "delete", "drop", "create",
        "alter", "exec", "execute", "sleep", "benchmark", "waitfor", "delay",
        "having", "group by", "order by", "where", "from", "into", "load_file",
        "outfile", "information_schema", "sysobjects", "xp_cmdshell",
    ]
    SPECIAL_CHARS = ["'", '"', ";", "--", "/*", "*/", "#", "||", "&&"]

    # Ordered handcrafted numeric features (stable order = stable vectors).
    NUMERIC_KEYS = [
        "length", "special_char_ratio", "keyword_count", "has_comment",
        "has_union", "has_sleep", "url_encoded", "hex_encoded",
        "quote_count", "semicolon_count",
    ]

    def extract(self, payload: str) -> dict:
        payload = payload or ""
        payload_lower = payload.lower()
        return {
            "text": payload,
            "length": len(payload),
            "special_char_ratio": self._special_char_ratio(payload),
            "keyword_count": sum(1 for k in self.SQL_KEYWORDS if k in payload_lower),
            "has_comment": any(c in payload for c in ["--", "/*", "#"]),
            "has_union": "union" in payload_lower,
            "has_sleep": any(k in payload_lower for k in ["sleep", "benchmark", "waitfor"]),
            "url_encoded": "%27" in payload_lower or "%22" in payload_lower or "%3b" in payload_lower,
            "hex_encoded": "0x" in payload_lower,
            "quote_count": payload.count("'") + payload.count('"'),
            "semicolon_count": payload.count(";"),
        }

    @staticmethod
    def _special_char_ratio(payload: str) -> float:
        if not payload:
            return 0.0
        special = sum(1 for c in payload if c in "'\";--/*#")
        return special / len(payload)


# ---------------------------------------------------------------------------
# Cross-Site Scripting
# ---------------------------------------------------------------------------
class XSSFeatureExtractor:
    JS_KEYWORDS = [
        "script", "alert", "confirm", "prompt", "eval", "document",
        "window", "location", "cookie", "onerror", "onload", "onclick",
        "onmouseover", "onfocus", "onblur", "src", "href", "data:",
        "javascript:", "vbscript:", "expression(", "fromcharcode",
    ]
    HTML_TAGS = ["<script", "</script", "<img", "<svg", "<iframe",
                 "<object", "<embed", "<link", "<style", "<input"]

    NUMERIC_KEYS = [
        "length", "tag_count", "js_keyword_count", "has_script_tag",
        "has_event_handler", "has_javascript_proto", "angle_bracket_count",
        "entropy", "url_encoded_ratio", "has_data_uri",
    ]

    def extract(self, payload: str) -> dict:
        payload = payload or ""
        payload_lower = payload.lower()
        return {
            "text": payload,
            "length": len(payload),
            "tag_count": sum(1 for t in self.HTML_TAGS if t in payload_lower),
            "js_keyword_count": sum(1 for k in self.JS_KEYWORDS if k in payload_lower),
            "has_script_tag": "<script" in payload_lower,
            "has_event_handler": any(e in payload_lower for e in ["onerror=", "onload=", "onclick="]),
            "has_javascript_proto": "javascript:" in payload_lower,
            "angle_bracket_count": payload.count("<") + payload.count(">"),
            "entropy": self._entropy(payload),
            "url_encoded_ratio": payload.count("%") / max(len(payload), 1),
            "has_data_uri": "data:" in payload_lower,
        }

    @staticmethod
    def _entropy(s: str) -> float:
        if not s:
            return 0.0
        counts = Counter(s)
        total = len(s)
        return -sum((c / total) * math.log2(c / total) for c in counts.values())


# ---------------------------------------------------------------------------
# Brute Force (behavioural, time-window)
# ---------------------------------------------------------------------------
class BruteForceFeatureExtractor:
    NUMERIC_KEYS = [
        "request_count", "failed_ratio", "unique_usernames", "unique_endpoints",
        "avg_inter_request_delta", "request_regularity",
        "deviation_from_baseline", "has_rapid_fire",
    ]

    def extract(self, ip: str, events: list, baseline: dict) -> dict:
        if not events:
            return self._zero_vector()

        total = len(events)
        failed = sum(1 for e in events if e.get("success") is False)
        unique_users = len({e.get("username", "") for e in events})
        unique_endpoints = len({e.get("endpoint", "") for e in events})

        timestamps = sorted(e.get("timestamp") for e in events if e.get("timestamp"))
        if len(timestamps) > 1:
            deltas = [(timestamps[i + 1] - timestamps[i]).total_seconds()
                      for i in range(len(timestamps) - 1)]
        else:
            deltas = [0]

        avg_delta = sum(deltas) / len(deltas) if deltas else 0
        regularity = (max(deltas) - min(deltas)) if len(deltas) > 1 else 0
        baseline_rpm = baseline.get("avg_requests_per_minute", 1) or 1

        return {
            "request_count": total,
            "failed_ratio": failed / total if total > 0 else 0,
            "unique_usernames": unique_users,
            "unique_endpoints": unique_endpoints,
            "avg_inter_request_delta": avg_delta,
            "request_regularity": regularity,            # low ⇒ automated (too regular)
            "deviation_from_baseline": total / max(baseline_rpm * 1.1, 0.1),
            "has_rapid_fire": avg_delta < 0.5,           # <500ms between requests
        }

    def _zero_vector(self) -> dict:
        return {k: 0 for k in self.NUMERIC_KEYS}


# ---------------------------------------------------------------------------
# DoS / DDoS (traffic volume)
# ---------------------------------------------------------------------------
class DoSFeatureExtractor:
    STAT_KEYS = [
        "pps", "bps", "syn_count", "ack_count", "rst_count", "icmp_count",
        "udp_flood_ports", "pps_deviation", "bps_deviation",
        "syn_ack_ratio", "connection_rate",
    ]

    def extract_statistical(self, window: dict, baseline: dict) -> dict:
        baseline_pps = baseline.get("avg_packets_per_second", 100) or 100
        baseline_bps = baseline.get("avg_bytes_per_second", 50000) or 50000
        return {
            "pps": window.get("packets_per_second", 0),
            "bps": window.get("bytes_per_second", 0),
            "syn_count": window.get("syn_count", 0),
            "ack_count": window.get("ack_count", 0),
            "rst_count": window.get("rst_count", 0),
            "icmp_count": window.get("icmp_count", 0),
            "udp_flood_ports": window.get("unique_udp_ports", 0),
            "pps_deviation": window.get("packets_per_second", 0) / max(baseline_pps, 1),
            "bps_deviation": window.get("bytes_per_second", 0) / max(baseline_bps, 1),
            "syn_ack_ratio": window.get("syn_count", 0) / max(window.get("ack_count", 1), 1),
            "connection_rate": window.get("new_connections_per_second", 0),
        }

    def extract_lstm_sequence(self, windows: list) -> list:
        """Last 30 windows (30s) as an LSTM sequence: [pps, Mbps, syn, ack, rst]."""
        sequence = []
        for w in windows[-30:]:
            sequence.append([
                w.get("packets_per_second", 0),
                w.get("bytes_per_second", 0) / 1e6,
                w.get("syn_count", 0),
                w.get("ack_count", 0),
                w.get("rst_count", 0),
            ])
        while len(sequence) < 30:
            sequence.insert(0, [0, 0, 0, 0, 0])
        return sequence


# ---------------------------------------------------------------------------
# Shared helpers — keep trainer & detector feature vectors identical
# ---------------------------------------------------------------------------
def numeric_vector(features: dict, keys: list) -> list:
    """Project a feature dict onto an ordered key list as floats (bool→0/1)."""
    out = []
    for k in keys:
        v = features.get(k, 0)
        out.append(float(v) if not isinstance(v, bool) else float(bool(v)))
    return out


def combine_text_features(texts, extractor, vectorizer, numeric_keys, *, fit=False):
    """
    Build the combined sparse matrix [TF-IDF | handcrafted numerics] used by the
    SQLi/XSS models. `texts` is a list of raw payload strings. Returns a scipy
    sparse matrix. Identical in training (fit=True) and inference (fit=False).
    """
    import numpy as np
    from scipy import sparse

    if fit:
        tfidf = vectorizer.fit_transform(texts)
    else:
        tfidf = vectorizer.transform(texts)

    rows = []
    for t in texts:
        feats = extractor.extract(t)
        rows.append(numeric_vector(feats, numeric_keys))
    numeric = sparse.csr_matrix(np.asarray(rows, dtype="float64"))
    return sparse.hstack([tfidf, numeric], format="csr")
