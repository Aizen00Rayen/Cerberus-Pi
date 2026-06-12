import logging
import sys

from django.apps import AppConfig

logger = logging.getLogger("cerberus.intelligence")

# Management commands that must NOT pay the cost of loading ML models / importing
# scikit-learn (and must work before any model artifact exists).
_SKIP_LOAD_FOR = {
    "makemigrations", "migrate", "collectstatic", "test",
    "shell", "createsuperuser", "dumpdata", "loaddata",
}


class IntelligenceConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "intelligence"
    verbose_name = "AI Anomaly Detection (Phase 11)"

    def ready(self):
        # Load all ML models once into the in-process cache (Phase 11.4).
        # Defensive: never raise — a missing/untrained model just leaves that
        # detector in fallback mode (baseline phase behaviour).
        if any(cmd in sys.argv for cmd in _SKIP_LOAD_FOR):
            return
        try:
            from intelligence.ml.detector import CerberusDetector
            CerberusDetector.load_all_models()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Intelligence model preload skipped: %s", exc)
