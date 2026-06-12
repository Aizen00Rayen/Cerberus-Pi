"""Threat API (Phase 5.3): list/detail, filtering, and the Block-IP action."""
import logging

from django.utils import timezone
from django.db.models import Count
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets, filters, status
from rest_framework.decorators import action
from rest_framework.response import Response

from .models import Threat
from .serializers import ThreatSerializer, ThreatDetailSerializer
from .blocking import block_source_ip

logger = logging.getLogger("cerberus.threats")


class ThreatViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Threat.objects.all()
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter, filters.SearchFilter]
    filterset_fields = ["severity", "category", "engine", "src_ip", "dst_ip", "is_blocked"]
    search_fields = ["signature", "description", "category"]
    ordering_fields = ["timestamp", "severity", "created_at"]
    ordering = ["-timestamp"]

    def get_serializer_class(self):
        return ThreatDetailSerializer if self.action == "retrieve" else ThreatSerializer

    @action(detail=True, methods=["post"])
    def block(self, request, pk=None):
        """POST /api/threats/{id}/block/ — drop the source IP via iptables."""
        threat = self.get_object()
        if not threat.src_ip:
            return Response({"detail": "Threat has no source IP."},
                            status=status.HTTP_400_BAD_REQUEST)
        ok, msg = block_source_ip(threat.src_ip)
        if ok:
            threat.is_blocked = True
            threat.save(update_fields=["is_blocked"])
            logger.info("Blocked %s (threat %s) by %s", threat.src_ip, threat.pk, request.user)
            return Response({"detail": msg, "blocked_ip": threat.src_ip})
        return Response({"detail": msg}, status=status.HTTP_502_BAD_GATEWAY)

    @action(detail=False, methods=["get"])
    def summary(self, request):
        """GET /api/threats/summary/ — counts by severity + top attackers (dashboard)."""
        since = timezone.now() - timezone.timedelta(hours=24)
        by_sev = dict(
            Threat.objects.values_list("severity")
            .annotate(n=Count("id")).values_list("severity", "n")
        )
        top_attackers = list(
            Threat.objects.filter(timestamp__gte=since, src_ip__isnull=False)
            .values("src_ip").annotate(count=Count("id")).order_by("-count")[:5]
        )
        return Response({
            "by_severity": by_sev,
            "top_attackers_24h": top_attackers,
            "total": Threat.objects.count(),
        })
