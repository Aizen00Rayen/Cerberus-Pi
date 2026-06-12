from django.contrib import admin

from .models import NetworkHost, ScanResult


@admin.register(NetworkHost)
class NetworkHostAdmin(admin.ModelAdmin):
    list_display = ("ip_address", "mac_address", "os_detected", "risk_score", "last_seen")
    search_fields = ("ip_address", "mac_address", "hostname")
    ordering = ("-risk_score",)


@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ("scan_type", "target", "status", "host_count", "vulnerability_count", "created_at")
    list_filter = ("scan_type", "status")
