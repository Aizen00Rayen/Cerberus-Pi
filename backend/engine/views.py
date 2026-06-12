"""Engine API (Phase 5.3): status + restart, plus Pi system health."""
from rest_framework import viewsets, mixins, status as http
from rest_framework.decorators import action
from rest_framework.response import Response

from .models import EngineStatus
from .serializers import EngineStatusSerializer
from .control import control_engine
from .health import system_health


class EngineStatusViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    queryset = EngineStatus.objects.all()
    serializer_class = EngineStatusSerializer

    @action(detail=False, methods=["post"])
    def restart(self, request):
        """POST /api/engine/restart/ {engine: suricata|snort, action?: restart}."""
        engine = request.data.get("engine", "")
        act = request.data.get("action", "restart")
        ok, msg = control_engine(engine, act)
        code = http.HTTP_200_OK if ok else http.HTTP_502_BAD_GATEWAY
        return Response({"ok": ok, "detail": msg}, status=code)

    @action(detail=False, methods=["get"])
    def health(self, request):
        """GET /api/engine/health/ — CPU, RAM, disk, temperature (Pi-specific)."""
        return Response(system_health())
