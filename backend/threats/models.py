"""Threat model (Phase 5.2): normalised alert from Suricata or Snort."""
from django.db import models


class Severity(models.TextChoices):
    CRITICAL = "CRITICAL", "Critical"
    HIGH = "HIGH", "High"
    MEDIUM = "MEDIUM", "Medium"
    LOW = "LOW", "Low"
    INFO = "INFO", "Info"


class Engine(models.TextChoices):
    SURICATA = "suricata", "Suricata"
    SNORT = "snort", "Snort 3"


class Threat(models.Model):
    timestamp = models.DateTimeField(db_index=True, help_text="When the alert fired")
    engine = models.CharField(max_length=16, choices=Engine.choices, db_index=True)
    severity = models.CharField(max_length=8, choices=Severity.choices, db_index=True)
    category = models.CharField(max_length=128, blank=True, db_index=True)
    src_ip = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    dst_ip = models.GenericIPAddressField(null=True, blank=True)
    src_port = models.PositiveIntegerField(null=True, blank=True)
    dst_port = models.PositiveIntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=16, blank=True)
    signature = models.TextField(blank=True)
    description = models.TextField(blank=True)
    raw_alert = models.JSONField(default=dict, blank=True)
    advice = models.TextField(blank=True, help_text="AI/rule-based remediation advice")
    is_blocked = models.BooleanField(default=False)
    # Deduplication key: hash of signature+src+dst within the 60s window.
    dedup_key = models.CharField(max_length=64, blank=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["severity", "-timestamp"]),
            models.Index(fields=["src_ip", "-timestamp"]),
        ]

    def __str__(self):
        return f"[{self.severity}] {self.category or self.signature[:40]} {self.src_ip}→{self.dst_ip}"
