"""Phase 5.3/6.3 — engine-status WebSocket consumer (/ws/engine/)."""
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from asgiref.sync import sync_to_async


class EngineConsumer(AsyncJsonWebsocketConsumer):
    GROUP = "engine"

    async def connect(self):
        user = self.scope.get("user")
        if user is None or not user.is_authenticated:
            await self.close(code=4401)
            return
        await self.channel_layer.group_add(self.GROUP, self.channel_name)
        await self.accept()
        # Send the current snapshot on connect.
        await self.send_json({"event": "snapshot", "data": await self._snapshot()})

    async def disconnect(self, code):
        await self.channel_layer.group_discard(self.GROUP, self.channel_name)

    # group_send(type="engine.update") from the watchdog.
    async def engine_update(self, event):
        await self.send_json({"event": "engine", "data": event["data"]})

    @sync_to_async
    def _snapshot(self):
        from .models import EngineStatus
        from .serializers import EngineStatusSerializer
        return EngineStatusSerializer(EngineStatus.objects.all(), many=True).data
