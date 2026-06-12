"""
Phase 11.5/11.8 — Admin feedback → training-data pipeline.

When an admin confirms a detection it becomes a labelled positive for the next
retrain; a rejected detection becomes a negative (false_positives.csv) and is
excluded from positives. Model-poisoning safeguards:
  * only admin-verdicted samples ever enter training data,
  * a minimum number of confirmed samples is required before a model updates,
  * payload samples are already truncated to 500 chars upstream.
"""
from __future__ import annotations

import csv
import logging

from . import artifacts as A

logger = logging.getLogger("cerberus.intelligence")

MIN_CONFIRMED_FOR_UPDATE = 10   # poisoning guard (Phase 11.8)

_CONFIRMED_FILE = {
    "sqli": "sqli_confirmed.csv",
    "xss": "xss_confirmed.csv",
    "bruteforce": "bruteforce_confirmed.csv",
    "dos": "dos_confirmed.csv",
}


def record_verdict(detection):
    """Append a verdicted AnomalyDetection to the appropriate training CSV."""
    if detection.verdict == "confirmed":
        _append(A.training_data_dir() / _CONFIRMED_FILE.get(detection.attack_type, "other.csv"),
                detection.payload_sample, detection.attack_type)
    elif detection.verdict == "false_positive":
        _append(A.training_data_dir() / "false_positives.csv",
                detection.payload_sample, detection.attack_type)


def _append(path, payload, attack):
    if not payload:
        return
    newfile = not path.exists()
    with open(path, "a", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        if newfile:
            w.writerow(["payload", "attack_type"])
        w.writerow([payload, attack])
    try:
        import os
        os.chmod(path, 0o600)   # training data is sensitive (Phase 11.8)
    except OSError:
        pass


def export_confirmed_to_csv():
    """Rebuild confirmed/false-positive CSVs from the DB (daily task)."""
    from intelligence.models import AnomalyDetection

    counts = {}
    # Confirmed per attack type.
    for attack, fname in _CONFIRMED_FILE.items():
        rows = (AnomalyDetection.objects
                .filter(attack_type=attack, verdict="confirmed")
                .exclude(payload_sample="")
                .values_list("payload_sample", flat=True))
        _rewrite(A.training_data_dir() / fname, rows, attack)
        counts[attack] = len(rows)
    # False positives across all types.
    fps = (AnomalyDetection.objects
           .filter(verdict="false_positive")
           .exclude(payload_sample="")
           .values_list("payload_sample", "attack_type"))
    _rewrite_pairs(A.training_data_dir() / "false_positives.csv", fps)
    A.training_log(f"Exported confirmed training data: {counts}")
    return counts


def _rewrite(path, rows, attack):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["payload", "attack_type"])
        for r in rows:
            w.writerow([r, attack])
    _chmod600(path)


def _rewrite_pairs(path, pairs):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["payload", "attack_type"])
        for payload, attack in pairs:
            w.writerow([payload, attack])
    _chmod600(path)


def _chmod600(path):
    try:
        import os
        os.chmod(path, 0o600)
    except OSError:
        pass


def enough_confirmed(attack: str) -> bool:
    from intelligence.models import AnomalyDetection
    n = AnomalyDetection.objects.filter(attack_type=attack, verdict="confirmed").count()
    return n >= MIN_CONFIRMED_FOR_UPDATE
