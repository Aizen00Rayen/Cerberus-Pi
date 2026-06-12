"""
Phase 11.6 — Celery tasks for the intelligence module.

ML tasks declare queue="intelligence" so they run in a dedicated worker isolated
from the main worker (Phase 11.8): on the Pi, start it with
    celery -A cerberus worker -Q intelligence --concurrency=1
"""
from __future__ import annotations

import logging
import time

from celery import shared_task
from django.utils import timezone

logger = logging.getLogger("cerberus.intelligence")


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------
@shared_task(queue="intelligence")
def update_baseline():
    """Every 5 min: refresh per-IP/interface baselines; complete the 72h window."""
    from intelligence.ml.baseline import BaselineBuilder

    builder = BaselineBuilder()
    # Observed-stats ingestion from Suricata EVE/auth logs happens on the Pi; this
    # task also handles the phase transition each tick.
    completed = builder.mark_complete_if_due()
    return {"baseline_complete": completed, "remaining_hours": round(builder.get_remaining_hours(), 2)}


# ---------------------------------------------------------------------------
# DoS continuous monitor
# ---------------------------------------------------------------------------
@shared_task(bind=True, queue="intelligence")
def monitor_dos_continuous(self):
    """Every 10s: statistical DoS check; LSTM only if statistical did not trigger."""
    import json
    import redis
    from django.conf import settings
    from intelligence.ml.detector import CerberusDetector

    try:
        r = redis.Redis.from_url(settings.REDIS_URL)
        raw = r.get("cerberus:intelligence:dos_window")
        window = json.loads(raw) if raw else {}
    except Exception:  # noqa: BLE001
        window = {}
    if not window:
        return {"checked": False, "reason": "no traffic window available"}

    detector = CerberusDetector()
    result = detector.detect_dos_statistical(window)
    if not result["detected"]:
        seq = window.get("lstm_sequence")
        if seq:
            result = detector.detect_dos_lstm(seq)
    if result["detected"]:
        _create_dos_detection(window, result)
    return {"checked": True, "detected": result["detected"]}


def _create_dos_detection(window, result):
    from intelligence.models import AnomalyDetection, MLModel
    from intelligence.realtime import broadcast_detection

    model = MLModel.objects.filter(attack_type="dos", status="active").first()
    det = AnomalyDetection.objects.create(
        attack_type="dos",
        confidence_score=result.get("confidence", 1.0),
        src_ip=window.get("top_src_ip"),
        features_triggered=result.get("features_triggered", []),
        model_version=model,
        raw_features=window,
    )
    broadcast_detection(det)


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------
@shared_task(queue="intelligence")
def train_single_model(attack_type: str, triggered_by: str = "manual"):
    """Train one model, tracked by a TrainingJob row."""
    from intelligence.models import TrainingJob
    from intelligence.ml import trainer
    from intelligence.ml.detector import CerberusDetector

    job = TrainingJob.objects.create(attack_type=attack_type, status="running",
                                     triggered_by=triggered_by, started_at=timezone.now())
    t0 = time.perf_counter()
    try:
        fn = trainer.TRAINERS[attack_type]
        mlmodel = fn()
        job.status = "completed"
        job.result_model = mlmodel
    except Exception as exc:  # noqa: BLE001
        logger.exception("Training failed for %s", attack_type)
        job.status = "failed"
        job.error_log = str(exc)
        raise
    finally:
        job.completed_at = timezone.now()
        job.duration_seconds = int(time.perf_counter() - t0)
        job.save()
        # Reload the in-memory model so inference uses the new version immediately.
        try:
            CerberusDetector.load_all_models()
        except Exception:  # noqa: BLE001
            pass
    return {"attack_type": attack_type, "job_id": job.id, "status": job.status}


@shared_task(queue="intelligence")
def retrain_all_models(triggered_by: str = "scheduler"):
    """Weekly (Sun 02:00) or on baseline completion: retrain all four models."""
    results = {}
    for attack in ("sqli", "xss", "bruteforce", "dos"):
        results[attack] = train_single_model.delay(attack, triggered_by).id
    return results


@shared_task(queue="intelligence")
def export_confirmed_threats_to_csv():
    """Daily (01:00): rebuild confirmed/false-positive training CSVs from the DB."""
    from intelligence.ml.feedback import export_confirmed_to_csv
    return export_confirmed_to_csv()
