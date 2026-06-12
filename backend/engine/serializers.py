from rest_framework import serializers

from .models import EngineStatus


class EngineStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = EngineStatus
        fields = ["id", "engine_name", "status", "pid", "uptime", "alerts_count",
                  "last_heartbeat", "last_restart", "restart_count"]
