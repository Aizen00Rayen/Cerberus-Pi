from rest_framework import serializers

from .models import Threat


class ThreatSerializer(serializers.ModelSerializer):
    class Meta:
        model = Threat
        fields = [
            "id", "timestamp", "engine", "severity", "category",
            "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
            "signature", "description", "advice", "is_blocked", "created_at",
        ]
        read_only_fields = fields


class ThreatDetailSerializer(ThreatSerializer):
    class Meta(ThreatSerializer.Meta):
        fields = ThreatSerializer.Meta.fields + ["raw_alert"]
        read_only_fields = fields
