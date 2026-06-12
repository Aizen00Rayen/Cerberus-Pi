"""Phase 11.6 — real-time anomaly WebSocket consumer (/ws/intelligence/)."""
from channels.generic.websocket import AsyncJsonWebsocketConsumer


class IntelligenceConsumer(AsyncJsonWebsocketConsumer):
    GROUP = "intelligence"

    async def connect(self):
        user = self.scope.get("user")
        if user is None or not user.is_authenticated:
            await self.close(code=4401)
            return
        await self.channel_layer.group_add(self.GROUP, self.channel_name)
        await self.accept()

    async def disconnect(self, code):
        await self.channel_layer.group_discard(self.GROUP, self.channel_name)

    # group_send(type="anomaly.new") from intelligence.realtime.broadcast_detection.
    async def anomaly_new(self, event):
        await self.send_json({"event": "anomaly", "data": event["data"]})
