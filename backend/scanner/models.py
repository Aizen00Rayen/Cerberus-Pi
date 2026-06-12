"""Scanner models (Phase 5.2): discovered hosts and scan runs."""
from django.db import models


class NetworkHost(models.Model):
    ip_address = models.GenericIPAddressField(unique=True, db_index=True)
    mac_address = models.CharField(max_length=17, blank=True)
    hostname = models.CharField(max_length=255, blank=True)
    os_detected = models.CharField(max_length=255, blank=True)
    open_ports = models.JSONField(default=list, blank=True)   # [{"port":22,"proto":"tcp","service":"ssh","version":"OpenSSH 9.2"}]
    vulnerabilities = models.JSONField(default=list, blank=True)  # [{"id":"CVE-...","cvss":7.5,"summary":...}]
    risk_score = models.PositiveSmallIntegerField(default=0)   # 0..100
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-risk_score", "ip_address"]

    def __str__(self):
        return f"{self.ip_address} (risk {self.risk_score})"


class ScanType(models.TextChoices):
    DISCOVERY = "discovery", "Host Discovery"
    PORT = "port", "Port Scan"
    OS = "os", "OS Fingerprint"
    VULN = "vuln", "Vulnerability Scan"
    SERVICE = "service", "Service Version"
    STEALTH = "stealth", "Stealth Scan"
    UDP = "udp", "UDP Scan"
    ARP = "arp", "ARP Scan"


class ScanResult(models.Model):
    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        DONE = "done", "Completed"
        FAILED = "failed", "Failed"

    scan_type = models.CharField(max_length=16, choices=ScanType.choices)
    target = models.CharField(max_length=255, help_text="CIDR, IP, or 'localnet'")
    status = models.CharField(max_length=12, choices=Status.choices, default=Status.QUEUED)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    findings = models.JSONField(default=dict, blank=True)
    host_count = models.PositiveIntegerField(default=0)
    vulnerability_count = models.PositiveIntegerField(default=0)
    error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.scan_type} {self.target} [{self.status}]"
