from rest_framework import serializers

from .models import MLModel, AnomalyDetection, BaselineProfile, TrainingJob


class MLModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = MLModel
        fields = ["id", "attack_type", "version", "status", "accuracy", "f1_score",
                  "precision", "recall", "trained_at", "training_samples", "notes",
                  "created_at"]


class AnomalyDetectionSerializer(serializers.ModelSerializer):
    class Meta:
        model = AnomalyDetection
        fields = ["id", "attack_type", "confidence_score", "anomaly_score",
                  "src_ip", "dst_ip", "src_port", "dst_port", "payload_sample",
                  "features_triggered", "model_version", "linked_threat",
                  "verdict", "verdict_at", "detected_at"]
        read_only_fields = fields


class AnomalyDetectionDetailSerializer(AnomalyDetectionSerializer):
    class Meta(AnomalyDetectionSerializer.Meta):
        fields = AnomalyDetectionSerializer.Meta.fields + ["raw_features"]
        read_only_fields = fields


class VerdictSerializer(serializers.Serializer):
    verdict = serializers.ChoiceField(choices=["confirmed", "false_positive"])


class BaselineProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = BaselineProfile
        fields = ["id", "ip_address", "avg_requests_per_minute",
                  "avg_failed_auth_per_hour", "avg_payload_length",
                  "avg_packets_per_second", "avg_bytes_per_second",
                  "common_ports", "common_endpoints", "is_complete",
                  "observation_start", "observation_end", "updated_at"]


class TrainingJobSerializer(serializers.ModelSerializer):
    class Meta:
        model = TrainingJob
        fields = ["id", "attack_type", "status", "triggered_by", "started_at",
                  "completed_at", "duration_seconds", "result_model", "error_log",
                  "created_at"]
