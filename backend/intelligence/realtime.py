"""Push new AnomalyDetection events to the /ws/intelligence/ group (Phase 11.6)."""
import logging

logger = logging.getLogger("cerberus.intelligence")


def broadcast_detection(detection):
    try:
        from asgiref.sync import async_to_sync
        from channels.layers import get_channel_layer
        from intelligence.serializers import AnomalyDetectionSerializer

        layer = get_channel_layer()
        if layer is None:
            return
        async_to_sync(layer.group_send)(
            "intelligence",
            {"type": "anomaly.new", "data": AnomalyDetectionSerializer(detection).data},
        )
    except Exception as exc:  # noqa: BLE001 — never lose a detection over a WS error
        logger.warning("intelligence WS broadcast failed: %s", exc)
