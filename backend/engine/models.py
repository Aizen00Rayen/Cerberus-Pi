"""EngineStatus model (Phase 5.2 / 3.3): health of each IDS/IPS engine."""
from django.db import models


class EngineStatus(models.Model):
    class State(models.TextChoices):
        RUNNING = "running", "Running"
        STOPPED = "stopped", "Stopped"
        CRASHED = "crashed", "Crashed"
        RESTARTING = "restarting", "Restarting"
        UNKNOWN = "unknown", "Unknown"

    engine_name = models.CharField(max_length=32, unique=True)  # suricata | snort
    status = models.CharField(max_length=12, choices=State.choices, default=State.UNKNOWN)
    pid = models.PositiveIntegerField(null=True, blank=True)
    uptime = models.PositiveBigIntegerField(default=0, help_text="seconds")
    alerts_count = models.PositiveBigIntegerField(default=0)
    last_heartbeat = models.DateTimeField(null=True, blank=True)
    last_restart = models.DateTimeField(null=True, blank=True)
    restart_count = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["engine_name"]
        verbose_name_plural = "Engine statuses"

    def __str__(self):
        return f"{self.engine_name}: {self.status}"
