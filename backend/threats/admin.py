from django.contrib import admin

from .models import Threat


@admin.register(Threat)
class ThreatAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "severity", "engine", "category", "src_ip", "dst_ip", "is_blocked")
    list_filter = ("severity", "engine", "is_blocked")
    search_fields = ("signature", "src_ip", "dst_ip", "category")
    readonly_fields = ("raw_alert", "dedup_key", "created_at")
