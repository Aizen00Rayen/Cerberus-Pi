"""Shared helpers for auth auditing."""


def client_ip(request) -> str | None:
    """Resolve the real client IP behind the Nginx reverse proxy."""
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def record_login(username: str, success: bool, request):
    from .models import LoginAudit
    LoginAudit.objects.create(
        username=username or "",
        success=success,
        ip_address=client_ip(request),
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:512],
    )
