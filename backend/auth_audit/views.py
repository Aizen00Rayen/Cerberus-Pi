"""
Auth API (Phase 10): rate-limited login, logout, session/CSRF bootstrap.

Single admin appliance — no registration. Login is throttled to 5 attempts /
10 min per IP via DRF's ScopedRateThrottle ('login' scope, set in settings).
"""
from django.contrib.auth import authenticate, login, logout
from django.middleware.csrf import get_token
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle


class LoginThrottle(ScopedRateThrottle):
    scope = "login"


@api_view(["GET"])
@permission_classes([AllowAny])
def csrf(request):
    """GET /api/auth/csrf/ — set CSRF cookie + return token for the SPA."""
    return Response({"csrfToken": get_token(request)})


@api_view(["POST"])
@permission_classes([AllowAny])
@throttle_classes([LoginThrottle])
def login_view(request):
    """POST /api/auth/login/ {username, password}."""
    username = request.data.get("username", "")
    password = request.data.get("password", "")
    user = authenticate(request, username=username, password=password)
    if user is None or not user.is_active:
        # signal-driven audit records the failure; respond generically.
        return Response({"detail": "Invalid credentials."},
                        status=status.HTTP_401_UNAUTHORIZED)
    login(request, user)
    return Response({"detail": "ok", "username": user.username, "is_staff": user.is_staff})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout_view(request):
    logout(request)
    return Response({"detail": "ok"})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def me(request):
    return Response({"username": request.user.username, "is_staff": request.user.is_staff})
