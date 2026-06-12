"""
Phase 11.1 — AI Anomaly Detection models.

NEW models only. The existing `threats.Threat` model is referenced via a nullable
ForeignKey (AnomalyDetection.linked_threat) — no existing model is modified.
"""
from django.db import models

ATTACK_CHOICES = [
    ("sqli", "SQL Injection"),
    ("xss", "Cross-Site Scripting"),
    ("bruteforce", "Brute Force"),
    ("dos", "DoS/DDoS"),
]


class MLModel(models.Model):
    """Tracks all trained model versions (one row per attack_type+version)."""
    STATUS_CHOICES = [
        ("training", "Training"),
        ("active", "Active"),
        ("archived", "Archived"),
        ("failed", "Failed"),
    ]
    attack_type = models.CharField(max_length=20, choices=ATTACK_CHOICES)
    version = models.IntegerField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="training")
    accuracy = models.FloatField(null=True)
    f1_score = models.FloatField(null=True)
    precision = models.FloatField(null=True)
    recall = models.FloatField(null=True)
    trained_at = models.DateTimeField(null=True)
    training_samples = models.IntegerField(default=0)
    model_path = models.CharField(max_length=255)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("attack_type", "version")
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.attack_type} v{self.version} [{self.status}]"


class AnomalyDetection(models.Model):
    """Each ML-generated detection event."""
    VERDICT_CHOICES = [
        ("pending", "Pending Review"),
        ("confirmed", "Confirmed Threat"),
        ("false_positive", "False Positive"),
    ]
    attack_type = models.CharField(max_length=20, choices=ATTACK_CHOICES)
    confidence_score = models.FloatField()            # 0.0 .. 1.0
    anomaly_score = models.FloatField(null=True)      # Isolation Forest raw score
    src_ip = models.GenericIPAddressField(null=True)
    dst_ip = models.GenericIPAddressField(null=True)
    src_port = models.IntegerField(null=True)
    dst_port = models.IntegerField(null=True)
    payload_sample = models.TextField(blank=True)     # truncated to 500 chars (Phase 11.8)
    features_triggered = models.JSONField(default=list)   # top-3 human-readable reasons
    model_version = models.ForeignKey(MLModel, on_delete=models.SET_NULL, null=True)
    # Link to the existing Threat model (threats app) — additive integration point.
    linked_threat = models.ForeignKey(
        "threats.Threat", on_delete=models.SET_NULL, null=True, blank=True,
        related_name="anomaly_detections",
    )
    verdict = models.CharField(max_length=20, choices=VERDICT_CHOICES, default="pending")
    verdict_at = models.DateTimeField(null=True)
    raw_features = models.JSONField(default=dict)     # full feature vector (for retraining)
    detected_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-detected_at"]
        indexes = [
            models.Index(fields=["attack_type", "-detected_at"]),
            models.Index(fields=["verdict", "-detected_at"]),
        ]

    def __str__(self):
        return f"{self.attack_type} {self.confidence_score:.2f} {self.src_ip} [{self.verdict}]"


class BaselineProfile(models.Model):
    """Per-IP behavioural baseline built during the 72h observation window."""
    ip_address = models.GenericIPAddressField(unique=True)
    avg_requests_per_minute = models.FloatField(default=0)
    avg_failed_auth_per_hour = models.FloatField(default=0)
    avg_payload_length = models.FloatField(default=0)
    common_ports = models.JSONField(default=list)
    common_user_agents = models.JSONField(default=list)
    common_endpoints = models.JSONField(default=list)
    avg_packets_per_second = models.FloatField(default=0)
    avg_bytes_per_second = models.FloatField(default=0)
    observation_start = models.DateTimeField()
    observation_end = models.DateTimeField(null=True)
    is_complete = models.BooleanField(default=False)   # True after 72h
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["ip_address"]

    def __str__(self):
        return f"baseline {self.ip_address} (complete={self.is_complete})"


class TrainingJob(models.Model):
    """Tracks weekly retraining jobs (and manual triggers)."""
    STATUS_CHOICES = [
        ("queued", "Queued"),
        ("running", "Running"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]
    attack_type = models.CharField(max_length=20)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="queued")
    triggered_by = models.CharField(max_length=50, default="scheduler")  # scheduler|manual
    started_at = models.DateTimeField(null=True)
    completed_at = models.DateTimeField(null=True)
    duration_seconds = models.IntegerField(null=True)
    result_model = models.ForeignKey(MLModel, on_delete=models.SET_NULL, null=True)
    error_log = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"train {self.attack_type} [{self.status}]"
