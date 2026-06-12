"""
Train version-1 models from the bundled datasets if they don't exist yet.

Run once at deploy (cerberus_start.sh calls this). Idempotent: skips any attack
type that already has an active model unless --force is given.

    python manage.py ml_bootstrap [--force]
"""
from django.core.management.base import BaseCommand

from intelligence.models import MLModel
from intelligence.ml import trainer
from intelligence.ml.detector import CerberusDetector


class Command(BaseCommand):
    help = "Train v1 ML models from bundled datasets (Phase 11)."

    def add_arguments(self, parser):
        parser.add_argument("--force", action="store_true",
                            help="Retrain even if an active model already exists.")

    def handle(self, *args, **opts):
        force = opts["force"]
        for attack in ("sqli", "xss", "bruteforce", "dos"):
            exists = MLModel.objects.filter(attack_type=attack, status="active").exists()
            if exists and not force:
                self.stdout.write(f"  {attack}: active model present — skipping")
                continue
            self.stdout.write(f"  {attack}: training v1 from bundled datasets...")
            try:
                m = trainer.TRAINERS[attack]()
                self.stdout.write(self.style.SUCCESS(
                    f"  {attack}: v{m.version} status={m.status} accuracy={m.accuracy}"))
            except Exception as exc:  # noqa: BLE001
                self.stderr.write(self.style.ERROR(f"  {attack}: training failed — {exc}"))
        CerberusDetector.load_all_models()
        self.stdout.write(self.style.SUCCESS("ml_bootstrap complete."))
