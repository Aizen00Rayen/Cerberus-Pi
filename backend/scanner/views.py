"""Scanner API (Phase 5.3): hosts, trigger scan, scan results."""
from rest_framework import viewsets, mixins, status
from rest_framework.decorators import action
from rest_framework.response import Response

from .models import NetworkHost, ScanResult
from .serializers import (
    NetworkHostSerializer, ScanResultSerializer, ScanResultDetailSerializer,
    ScanRequestSerializer,
)
from .tasks import run_scan_task


class NetworkHostViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = NetworkHost.objects.all()
    serializer_class = NetworkHostSerializer
    filterset_fields = ["risk_score", "os_detected"]
    ordering_fields = ["risk_score", "last_seen", "ip_address"]


class ScanResultViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin,
                        viewsets.GenericViewSet):
    queryset = ScanResult.objects.all()

    def get_serializer_class(self):
        return ScanResultDetailSerializer if self.action == "retrieve" else ScanResultSerializer

    @action(detail=False, methods=["post"])
    def scan(self, request):
        """POST /api/scanner/scan/ — enqueue an async scan."""
        ser = ScanRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        scan = ScanResult.objects.create(
            scan_type=ser.validated_data["scan_type"],
            target=ser.validated_data["target"],
            status=ScanResult.Status.QUEUED,
        )
        run_scan_task.delay(scan.pk)
        return Response(ScanResultSerializer(scan).data, status=status.HTTP_202_ACCEPTED)
