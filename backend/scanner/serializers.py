from rest_framework import serializers

from .models import NetworkHost, ScanResult, ScanType
from .validators import validate_target


class NetworkHostSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkHost
        fields = [
            "id", "ip_address", "mac_address", "hostname", "os_detected",
            "open_ports", "vulnerabilities", "risk_score", "first_seen", "last_seen",
        ]


class ScanResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanResult
        fields = [
            "id", "scan_type", "target", "status", "started_at", "completed_at",
            "host_count", "vulnerability_count", "error", "created_at",
        ]


class ScanResultDetailSerializer(ScanResultSerializer):
    class Meta(ScanResultSerializer.Meta):
        fields = ScanResultSerializer.Meta.fields + ["findings"]


class ScanRequestSerializer(serializers.Serializer):
    scan_type = serializers.ChoiceField(choices=ScanType.choices)
    target = serializers.CharField(max_length=255, default="localnet")

    def validate_target(self, value):
        # Reject argument injection / non-local targets before a scan is queued.
        return validate_target(value)
