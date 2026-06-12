"""Celery application for Cerberus Pi (async scans + nightly IPFS archival)."""
import os

from celery import Celery
from celery.schedules import crontab

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cerberus.settings")

app = Celery("cerberus")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()

# Phase 8: daily log archival to IPFS at 23:59.
app.conf.beat_schedule = {
    "daily-ipfs-archive": {
        "task": "logs.tasks.archive_daily_logs",
        "schedule": crontab(hour=23, minute=59),
    },
    "purge-old-scans": {
        "task": "scanner.tasks.purge_old_scans",
        "schedule": crontab(hour=3, minute=0),
    },
    # --- Phase 11: AI anomaly detection (additive — does not replace above) ---
    "ml-baseline-update": {
        "task": "intelligence.tasks.update_baseline",
        "schedule": crontab(minute="*/5"),              # every 5 minutes
    },
    "ml-dos-monitor": {
        "task": "intelligence.tasks.monitor_dos_continuous",
        "schedule": 10.0,                               # every 10 seconds
    },
    "ml-weekly-retrain": {
        "task": "intelligence.tasks.retrain_all_models",
        "schedule": crontab(hour=2, minute=0, day_of_week="sunday"),
    },
    "ml-export-training-data": {
        "task": "intelligence.tasks.export_confirmed_threats_to_csv",
        "schedule": crontab(hour=1, minute=0),          # daily at 01:00
    },
}


@app.task(bind=True)
def debug_task(self):
    print(f"Request: {self.request!r}")
