"""
Phase 11.5 — 72h behavioural baseline builder.

Runs every 5 minutes (Celery Beat). Observes traffic passively and maintains a
per-IP BaselineProfile plus per-interface traffic stats. After 72h it flips
is_complete and triggers the first round of training. Profiles keep updating on a
rolling window forever.

During the baseline phase, detectors run in fallback mode (see CerberusDetector);
the dashboard shows "🟡 BASELINE MODE — AI learning your network (Xh remaining)".
"""
from __future__ import annotations

import logging

from django.conf import settings
from django.utils import timezone

logger = logging.getLogger("cerberus.intelligence")


class BaselineBuilder:
    @property
    def duration_hours(self) -> int:
        return int(settings.ML_BASELINE_HOURS)

    # -- per-IP profile ----------------------------------------------------
    def update_ip_profile(self, ip: str, stats: dict):
        """Create/update a rolling BaselineProfile for an IP from observed stats."""
        from intelligence.models import BaselineProfile

        prof, created = BaselineProfile.objects.get_or_create(
            ip_address=ip,
            defaults={"observation_start": timezone.now()},
        )
        # Exponential moving average so the profile tracks a rolling window.
        a = 0.2
        prof.avg_requests_per_minute = _ema(prof.avg_requests_per_minute, stats.get("rpm", 0), a)
        prof.avg_failed_auth_per_hour = _ema(prof.avg_failed_auth_per_hour, stats.get("failed_per_hour", 0), a)
        prof.avg_payload_length = _ema(prof.avg_payload_length, stats.get("avg_payload_length", 0), a)
        prof.avg_packets_per_second = _ema(prof.avg_packets_per_second, stats.get("pps", 0), a)
        prof.avg_bytes_per_second = _ema(prof.avg_bytes_per_second, stats.get("bps", 0), a)
        if stats.get("ports"):
            prof.common_ports = _merge_top(prof.common_ports, stats["ports"])
        if stats.get("endpoints"):
            prof.common_endpoints = _merge_top(prof.common_endpoints, stats["endpoints"])
        if stats.get("user_agents"):
            prof.common_user_agents = _merge_top(prof.common_user_agents, stats["user_agents"])
        prof.save()
        return prof

    def update_traffic_stats(self, interface_stats: dict):
        """Hook for per-interface traffic baselines (consumed by the DoS trainer)."""
        # Persisted via Redis for the DoS monitor; thresholds are derived at train
        # time from aggregated BaselineProfile stats. Kept as an explicit seam.
        try:
            import redis
            import json
            r = redis.Redis.from_url(settings.REDIS_URL)
            r.set("cerberus:intelligence:iface_stats", json.dumps(interface_stats))
        except Exception:  # noqa: BLE001
            pass

    # -- phase tracking ----------------------------------------------------
    def _start_time(self):
        from intelligence.models import BaselineProfile
        first = BaselineProfile.objects.order_by("observation_start").first()
        return first.observation_start if first else None

    def is_baseline_complete(self) -> bool:
        start = self._start_time()
        if start is None:
            return False
        elapsed = (timezone.now() - start).total_seconds() / 3600.0
        return elapsed >= self.duration_hours

    def get_remaining_hours(self) -> float:
        start = self._start_time()
        if start is None:
            return float(self.duration_hours)
        elapsed = (timezone.now() - start).total_seconds() / 3600.0
        return max(0.0, self.duration_hours - elapsed)

    def mark_complete_if_due(self) -> bool:
        """Flip profiles to complete and trigger initial training once 72h pass."""
        from intelligence.models import BaselineProfile
        if not self.is_baseline_complete():
            return False
        updated = BaselineProfile.objects.filter(is_complete=False).update(
            is_complete=True, observation_end=timezone.now())
        if updated:
            logger.info("Baseline window complete (%s profiles) — triggering training", updated)
            self.trigger_initial_training()
        return True

    def trigger_initial_training(self):
        from intelligence.tasks import retrain_all_models
        retrain_all_models.delay(triggered_by="baseline_complete")


def _ema(old, new, alpha):
    old = old or 0.0
    return (1 - alpha) * old + alpha * float(new or 0)


def _merge_top(existing: list, new_items, limit: int = 10) -> list:
    seen = list(existing or [])
    for item in new_items:
        if item not in seen:
            seen.append(item)
    return seen[:limit]
