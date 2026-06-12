"""
Login-audit middleware (Phase 10).

Connects to Django's auth signals once, to record every login success/failure
with IP + timestamp. Implemented as middleware purely so it loads on startup;
the actual recording is signal-driven so it captures admin + API logins alike.
"""
from django.contrib.auth.signals import user_logged_in, user_login_failed
from django.dispatch import receiver

from .utils import record_login

_CONNECTED = False


class LoginAuditMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        global _CONNECTED
        if not _CONNECTED:
            _connect_signals()
            _CONNECTED = True

    def __call__(self, request):
        return self.get_response(request)


def _connect_signals():
    @receiver(user_logged_in)
    def _on_success(sender, request, user, **kwargs):
        record_login(getattr(user, "username", ""), True, request)

    @receiver(user_login_failed)
    def _on_fail(sender, credentials, request=None, **kwargs):
        if request is not None:
            record_login(credentials.get("username", ""), False, request)
