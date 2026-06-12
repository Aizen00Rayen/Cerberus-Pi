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
}


@app.task(bind=True)
def debug_task(self):
    print(f"Request: {self.request!r}")
