import asyncio
import json
import logging
from typing import List
from fastapi import WebSocket
from app.core.redis import get_redis

logger = logging.getLogger("aura.websockets")

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._pubsub_task = None

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        """
        Publishes the message to Redis.
        The background task will pick it up and send it to active connections.
        Fallback to in-memory broadcast if Redis is unavailable.
        """
        try:
            rc = get_redis()
            rc.publish("aura_approvals", json.dumps(message))
        except Exception as e:
            logger.warning(f"Redis publish failed, falling back to in-memory broadcast: {e}")
            await self._in_memory_broadcast(message)

    async def _in_memory_broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

    async def listen_to_redis(self):
        try:
            rc = get_redis()
            pubsub = rc.pubsub()
            pubsub.subscribe("aura_approvals", "aura_model_events", "aura_security_events")
            logger.info("Subscribed to Redis channels 'aura_approvals', 'aura_model_events', 'aura_security_events'")
            while True:
                message = pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message:
                    try:
                        channel = message['channel']
                        if isinstance(channel, bytes):
                            channel = channel.decode('utf-8')
                        
                        data = json.loads(message['data'])
                        
                        if channel == "aura_approvals":
                            await self._in_memory_broadcast(data)
                        elif channel == "aura_model_events":
                            logger.info(f"Model event received: {data}")
                            if data.get("event") == "model_activated":
                                # Perform reload in a background thread to prevent blocking event loop
                                from app.api.v1.endpoints import get_risk_engine
                                re = get_risk_engine()
                                loop = asyncio.get_event_loop()
                                await loop.run_in_executor(None, re.reload_active_model)
                        elif channel == "aura_security_events":
                            logger.info(f"Security event received: {data}")
                            if data.get("event") == "lockdown_state_changed":
                                enabled = data.get("enabled", False)
                                from app.api.v1.sec_ops import _lockdown_state
                                _lockdown_state["enabled"] = enabled
                                logger.info(f"Synchronized local lockdown state to: {enabled}")
                    except Exception as e:
                        logger.error(f"Error decoding/processing pubsub message: {e}")
                await asyncio.sleep(0.01)
        except Exception as e:
            logger.error(f"Redis pubsub listener failed: {e}")

manager = ConnectionManager()

def start_pubsub_listener():
    loop = asyncio.get_event_loop()
    manager._pubsub_task = loop.create_task(manager.listen_to_redis())
