from django.contrib import admin

from .models import LoginAudit


@admin.register(LoginAudit)
class LoginAuditAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "success", "username", "ip_address")
    list_filter = ("success",)
    search_fields = ("username", "ip_address")
    readonly_fields = ("timestamp",)
