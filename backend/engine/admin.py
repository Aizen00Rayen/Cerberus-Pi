from django.contrib import admin

from .models import EngineStatus


@admin.register(EngineStatus)
class EngineStatusAdmin(admin.ModelAdmin):
    list_display = ("engine_name", "status", "pid", "uptime", "alerts_count",
                    "last_heartbeat", "restart_count")
