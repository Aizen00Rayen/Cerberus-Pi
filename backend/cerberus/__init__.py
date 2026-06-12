"""Cerberus Pi Django project package."""
# Ensure the Celery app is loaded when Django starts so shared_task can use it.
from .celery import app as celery_app  # noqa: F401

__all__ = ("celery_app",)
