"""
Phase 11.6 — Intelligence API routes (included at /api/intelligence/ by api/urls.py).

  GET  models/                      list ML models + metrics
  GET  models/{id}/                 model detail
  POST models/retrain/              trigger retraining (all or one)
  GET  detections/                  list detections (paginated, filterable)
  GET  detections/{id}/             detection detail + features
  POST detections/{id}/verdict/     admin feedback (confirm/reject)
  GET  baseline/status/             baseline phase status + progress
  GET  baseline/profiles/           per-IP behavioural profiles
  GET  training/                    training-job history
  GET  stats/                       detection stats
  GET/POST thresholds/              read/update detection thresholds
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    MLModelViewSet, AnomalyDetectionViewSet, BaselineViewSet,
    TrainingJobViewSet, StatsView, ThresholdView,
)

router = DefaultRouter()
router.register(r"models", MLModelViewSet, basename="mlmodel")
router.register(r"detections", AnomalyDetectionViewSet, basename="detection")
router.register(r"baseline", BaselineViewSet, basename="baseline")
router.register(r"training", TrainingJobViewSet, basename="trainingjob")

urlpatterns = [
    path("", include(router.urls)),
    path("stats/", StatsView.as_view()),
    path("thresholds/", ThresholdView.as_view()),
]
