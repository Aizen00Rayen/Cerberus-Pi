"""Phase 11.6 — Intelligence API."""
from django.db.models import Count
from django.utils import timezone
from rest_framework import viewsets, mixins, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import MLModel, AnomalyDetection, BaselineProfile, TrainingJob
from .serializers import (
    MLModelSerializer, AnomalyDetectionSerializer, AnomalyDetectionDetailSerializer,
    VerdictSerializer, BaselineProfileSerializer, TrainingJobSerializer,
)


class MLModelViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = MLModel.objects.all()
    serializer_class = MLModelSerializer
    filterset_fields = ["attack_type", "status"]

    @action(detail=False, methods=["post"])
    def retrain(self, request):
        """POST /api/intelligence/models/retrain/ {attack_type?: all|sqli|...}."""
        from .tasks import retrain_all_models, train_single_model
        attack = request.data.get("attack_type", "all")
        if attack in ("all", None, ""):
            retrain_all_models.delay(triggered_by="manual")
            return Response({"detail": "Retraining queued for all models."},
                            status=status.HTTP_202_ACCEPTED)
        if attack not in dict(MLModel._meta.get_field("attack_type").choices):
            return Response({"detail": f"Unknown attack_type {attack!r}."},
                            status=status.HTTP_400_BAD_REQUEST)
        train_single_model.delay(attack, "manual")
        return Response({"detail": f"Retraining queued for {attack}."},
                        status=status.HTTP_202_ACCEPTED)


class AnomalyDetectionViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = AnomalyDetection.objects.all()
    filterset_fields = ["attack_type", "verdict", "src_ip"]
    ordering_fields = ["detected_at", "confidence_score"]

    def get_serializer_class(self):
        return AnomalyDetectionDetailSerializer if self.action == "retrieve" else AnomalyDetectionSerializer

    @action(detail=True, methods=["post"])
    def verdict(self, request, pk=None):
        """POST /api/intelligence/detections/{id}/verdict/ — admin feedback."""
        from .ml.feedback import record_verdict

        detection = self.get_object()
        ser = VerdictSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        detection.verdict = ser.validated_data["verdict"]
        detection.verdict_at = timezone.now()
        detection.save(update_fields=["verdict", "verdict_at"])
        record_verdict(detection)   # append to training CSV (poisoning-guarded)
        return Response({"detail": "verdict recorded", "verdict": detection.verdict})


class BaselineViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    queryset = BaselineProfile.objects.all()
    serializer_class = BaselineProfileSerializer

    @action(detail=False, methods=["get"])
    def status(self, request):
        """GET /api/intelligence/baseline/status/ — phase + progress."""
        from .ml.baseline import BaselineBuilder
        b = BaselineBuilder()
        remaining = b.get_remaining_hours()
        total = b.duration_hours
        return Response({
            "complete": b.is_baseline_complete(),
            "remaining_hours": round(remaining, 2),
            "total_hours": total,
            "progress_percent": round((total - remaining) / total * 100, 1) if total else 100.0,
            "profiles": BaselineProfile.objects.count(),
        })

    @action(detail=False, methods=["get"])
    def profiles(self, request):
        """GET /api/intelligence/baseline/profiles/ — per-IP behavioural profiles."""
        qs = self.get_queryset()
        page = self.paginate_queryset(qs)
        ser = self.get_serializer(page or qs, many=True)
        return self.get_paginated_response(ser.data) if page is not None else Response(ser.data)


class TrainingJobViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = TrainingJob.objects.all()
    serializer_class = TrainingJobSerializer
    filterset_fields = ["attack_type", "status"]


class StatsView(APIView):
    """GET /api/intelligence/stats/ — detection counts + verdict breakdown."""
    def get(self, request):
        since = timezone.now() - timezone.timedelta(days=7)
        per_type = dict(
            AnomalyDetection.objects.filter(detected_at__gte=since)
            .values_list("attack_type").annotate(n=Count("id")).values_list("attack_type", "n")
        )
        verdicts = dict(
            AnomalyDetection.objects.values_list("verdict")
            .annotate(n=Count("id")).values_list("verdict", "n")
        )
        models = {
            m.attack_type: {"version": m.version, "accuracy": m.accuracy, "f1": m.f1_score}
            for m in MLModel.objects.filter(status="active")
        }
        return Response({
            "detections_7d_by_type": per_type,
            "verdict_breakdown": verdicts,
            "active_models": models,
            "total_detections": AnomalyDetection.objects.count(),
        })


class ThresholdView(APIView):
    """GET/POST /api/intelligence/thresholds/ — read or update detection thresholds."""
    def get(self, request):
        from .ml.detector import get_thresholds
        return Response(get_thresholds())

    def post(self, request):
        from .ml.detector import set_thresholds
        updated = set_thresholds(request.data or {})
        return Response({"detail": "thresholds updated", "thresholds": updated})
