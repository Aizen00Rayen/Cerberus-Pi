"""WebSocket URL routing (Phase 5.3): real-time threat + engine streams."""
from django.urls import path

from threats.consumers import ThreatConsumer
from engine.consumers import EngineConsumer

websocket_urlpatterns = [
    path("ws/threats/", ThreatConsumer.as_asgi()),
    path("ws/engine/", EngineConsumer.as_asgi()),
]
