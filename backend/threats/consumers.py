"""Phase 5.3/6.3 — real-time threat WebSocket consumer (/ws/threats/)."""
from channels.generic.websocket import AsyncJsonWebsocketConsumer


class ThreatConsumer(AsyncJsonWebsocketConsumer):
    GROUP = "threats"

    async def connect(self):
        # Only authenticated sessions may subscribe to the live threat feed.
        user = self.scope.get("user")
        if user is None or not user.is_authenticated:
            await self.close(code=4401)
            return
        await self.channel_layer.group_add(self.GROUP, self.channel_name)
        await self.accept()

    async def disconnect(self, code):
        await self.channel_layer.group_discard(self.GROUP, self.channel_name)

    # Triggered by threat_parser._broadcast via group_send(type="threat.new").
    async def threat_new(self, event):
        await self.send_json({"event": "threat", "data": event["data"]})
