"""
Management command: tail an engine log and ingest alerts into the Threat table.

    python manage.py run_parser --engine suricata
    python manage.py run_parser --engine snort

The cerberus-backend systemd setup runs one instance per engine.
"""
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand

from threats import threat_parser as tp


class Command(BaseCommand):
    help = "Tail Suricata/Snort logs and ingest alerts as Threats (Phase 5.4)."

    def add_arguments(self, parser):
        parser.add_argument("--engine", choices=["suricata", "snort"], default="suricata")

    def handle(self, *args, **opts):
        engine = opts["engine"]
        if engine == "suricata":
            path = Path(settings.SURICATA_EVE)
            normaliser = tp.normalise_suricata
        else:
            # Snort 3 alert_json output file.
            path = Path(settings.SNORT_LOGDIR) / "alert_json.txt"
            normaliser = tp.normalise_snort

        self.stdout.write(self.style.SUCCESS(f"run_parser: tailing {engine} at {path}"))
        import time
        while True:
            try:
                for fields in tp.tail(path, normaliser):
                    tp.persist_and_broadcast(fields)
            except Exception as exc:  # noqa: BLE001
                self.stderr.write(f"parser error ({engine}), retry in 3s: {exc}")
                time.sleep(3)
