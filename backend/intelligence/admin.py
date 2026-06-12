from django.contrib import admin

from .models import MLModel, AnomalyDetection, BaselineProfile, TrainingJob


@admin.register(MLModel)
class MLModelAdmin(admin.ModelAdmin):
    list_display = ("attack_type", "version", "status", "accuracy", "f1_score", "trained_at")
    list_filter = ("attack_type", "status")


@admin.register(AnomalyDetection)
class AnomalyDetectionAdmin(admin.ModelAdmin):
    list_display = ("detected_at", "attack_type", "confidence_score", "src_ip", "verdict")
    list_filter = ("attack_type", "verdict")
    search_fields = ("src_ip", "payload_sample")
    readonly_fields = ("raw_features", "detected_at")


@admin.register(BaselineProfile)
class BaselineProfileAdmin(admin.ModelAdmin):
    list_display = ("ip_address", "avg_requests_per_minute", "is_complete", "updated_at")
    list_filter = ("is_complete",)


@admin.register(TrainingJob)
class TrainingJobAdmin(admin.ModelAdmin):
    list_display = ("attack_type", "status", "triggered_by", "duration_seconds", "created_at")
    list_filter = ("attack_type", "status", "triggered_by")
