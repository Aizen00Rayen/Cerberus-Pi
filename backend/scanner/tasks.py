"""Phase 4.2 — async scan tasks (Celery)."""
import logging

from celery import shared_task
from django.conf import settings
from django.utils import timezone

from .models import NetworkHost, ScanResult
from . import cerberus_scanner as cs

logger = logging.getLogger("cerberus.scanner.tasks")


@shared_task(bind=True)
def run_scan_task(self, scan_result_id: int):
    """Execute a queued ScanResult, persist hosts, compute risk + CVE enrichment."""
    try:
        scan = ScanResult.objects.get(pk=scan_result_id)
    except ScanResult.DoesNotExist:
        logger.error("ScanResult %s not found", scan_result_id)
        return

    scan.status = ScanResult.Status.RUNNING
    scan.started_at = timezone.now()
    scan.save(update_fields=["status", "started_at"])

    try:
        hosts = cs.run_scan(scan.scan_type, scan.target)
        vuln_total = 0
        for ip, host in hosts.items():
            # Enrich CVEs (bounded — only for vuln scans to limit NVD calls).
            if scan.scan_type == "vuln":
                host["vulnerabilities"] = [
                    cs.enrich_cve(v, settings.NVD_API_KEY) for v in host.get("vulnerabilities", [])
                ]
            host["risk_score"] = cs.risk_score(host)
            vuln_total += len(host.get("vulnerabilities", []))
            _upsert_host(host)

        scan.findings = hosts
        scan.host_count = len(hosts)
        scan.vulnerability_count = vuln_total
        scan.status = ScanResult.Status.DONE
        scan.completed_at = timezone.now()
        scan.save()
        logger.info("Scan %s done: %s hosts, %s vulns", scan.pk, len(hosts), vuln_total)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Scan %s failed", scan.pk)
        scan.status = ScanResult.Status.FAILED
        scan.error = str(exc)
        scan.completed_at = timezone.now()
        scan.save(update_fields=["status", "error", "completed_at"])
        raise


def _upsert_host(host: dict):
    NetworkHost.objects.update_or_create(
        ip_address=host["ip_address"],
        defaults={
            "mac_address": host.get("mac_address", ""),
            "hostname": host.get("hostname", ""),
            "os_detected": host.get("os_detected", ""),
            "open_ports": host.get("open_ports", []),
            "vulnerabilities": host.get("vulnerabilities", []),
            "risk_score": host.get("risk_score", 0),
        },
    )


@shared_task
def purge_old_scans():
    """Retention: drop scan results older than SCAN_RETENTION_DAYS (Phase 4.2)."""
    import os
    days = int(os.environ.get("SCAN_RETENTION_DAYS", "90"))
    cutoff = timezone.now() - timezone.timedelta(days=days)
    deleted, _ = ScanResult.objects.filter(created_at__lt=cutoff).delete()
    logger.info("Purged %s scan results older than %s days", deleted, days)
    return deleted
