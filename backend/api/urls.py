"""
DRF API router (Phase 5.3). Maps to the endpoint table in the spec:

  /api/threats/                 ThreatViewSet (+ /{id}/block/, /summary/)
  /api/scanner/hosts/           NetworkHostViewSet
  /api/scanner/results/         ScanResultViewSet (+ /scan/)
  /api/logs/daily/              DailyLogArchiveViewSet (+ /{id}/verify/, /archive_now/)
  /api/logs/entries/            LogEntryViewSet (+ /by-date/<date>/, ?search=)
  /api/reports/                 ReportViewSet (+ /generate/, /{id}/download/)
  /api/engine/status/           EngineStatusViewSet (+ /restart/, /health/)
  /api/auth/{csrf,login,logout,me}/
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from threats.views import ThreatViewSet
from scanner.views import NetworkHostViewSet, ScanResultViewSet
from logs.views import DailyLogArchiveViewSet, LogEntryViewSet
from reports.views import ReportViewSet
from engine.views import EngineStatusViewSet
from auth_audit import views as auth_views

router = DefaultRouter()
router.register(r"threats", ThreatViewSet, basename="threat")
router.register(r"scanner/hosts", NetworkHostViewSet, basename="host")
router.register(r"scanner/results", ScanResultViewSet, basename="scanresult")
router.register(r"logs/daily", DailyLogArchiveViewSet, basename="dailyarchive")
router.register(r"logs/entries", LogEntryViewSet, basename="logentry")
router.register(r"reports", ReportViewSet, basename="report")
router.register(r"engine/status", EngineStatusViewSet, basename="engine")

urlpatterns = [
    path("", include(router.urls)),
    path("auth/csrf/", auth_views.csrf),
    path("auth/login/", auth_views.login_view),
    path("auth/logout/", auth_views.logout_view),
    path("auth/me/", auth_views.me),
]
