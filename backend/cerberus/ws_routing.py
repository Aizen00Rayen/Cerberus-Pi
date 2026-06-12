"""WebSocket URL routing (Phase 5.3): real-time threat + engine streams."""
from django.urls import path

from threats.consumers import ThreatConsumer
from engine.consumers import EngineConsumer
from intelligence.consumers import IntelligenceConsumer  # Phase 11

websocket_urlpatterns = [
    path("ws/threats/", ThreatConsumer.as_asgi()),
    path("ws/engine/", EngineConsumer.as_asgi()),
    path("ws/intelligence/", IntelligenceConsumer.as_asgi()),  # Phase 11
]
