"""Login audit log (Phase 10): every login attempt with IP + timestamp."""
from django.db import models


class LoginAudit(models.Model):
    username = models.CharField(max_length=150)
    success = models.BooleanField(default=False)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self):
        flag = "OK" if self.success else "FAIL"
        return f"{self.timestamp:%Y-%m-%d %H:%M} {flag} {self.username}@{self.ip_address}"
