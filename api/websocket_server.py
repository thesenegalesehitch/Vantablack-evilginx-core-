"""
VANTABLACK WebSocket Server - Real-time Communication
==================================================

WebSocket server for real-time updates:
- Live campaign monitoring
- Real-time analytics
- Instant notifications
- Live collaboration
- Event streaming
"""

import asyncio
import json
import logging
from typing import Dict, List, Any, Set, Optional
from datetime import datetime
import uuid
from fastapi import WebSocket, WebSocketDisconnect
from dataclasses import dataclass, asdict
from enum import Enum


class EventType(Enum):
    """WebSocket event types"""
    CAMPAIGN_UPDATE = "campaign_update"
    ANALYTICS_UPDATE = "analytics_update"
    SYSTEM_ALERT = "system_alert"
    USER_NOTIFICATION = "user_notification"
    TEMPLATE_UPDATE = "template_update"
    MARKETPLACE_UPDATE = "marketplace_update"
    OPTIMIZATION_UPDATE = "optimization_update"
    BEHAVIORAL_UPDATE = "behavioral_update"


@dataclass
class WebSocketMessage:
    """WebSocket message structure"""
    event_type: EventType
    data: Dict[str, Any]
    timestamp: datetime
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    message_id: str = None
    
    def __post_init__(self):
        if self.message_id is None:
            self.message_id = str(uuid.uuid4())


class WebSocketManager:
    """WebSocket connection manager"""
    
    def __init__(self):
        # Active connections by user
        self.active_connections: Dict[str, List[WebSocket]] = {}
        
        # Connection metadata
        self.connection_metadata: Dict[str, Dict[str, Any]] = {}
        
        # Room subscriptions
        self.room_subscriptions: Dict[str, Set[str]] = {}
        
        # Event handlers
        self.event_handlers: Dict[EventType, List[callable]] = {}
        
        # Message queue for broadcasting
        self.message_queue: asyncio.Queue = asyncio.Queue()
        
        # Broadcast task
        self.broadcast_task: Optional[asyncio.Task] = None
        
        # Statistics
        self.stats = {
            "total_connections": 0,
            "active_connections": 0,
            "messages_sent": 0,
            "messages_received": 0,
            "rooms_active": 0
        }
    
    async def connect(self, websocket: WebSocket, user_id: str, session_id: str = None):
        """Accept and register WebSocket connection"""
        await websocket.accept()
        
        # Generate session ID if not provided
        if session_id is None:
            session_id = str(uuid.uuid4())
        
        # Add to active connections
        if user_id not in self.active_connections:
            self.active_connections[user_id] = []
        
        self.active_connections[user_id].append(websocket)
        
        # Store connection metadata
        self.connection_metadata[session_id] = {
            "user_id": user_id,
            "session_id": session_id,
            "connected_at": datetime.now(),
            "last_activity": datetime.now(),
            "subscriptions": set(),
            "websocket": websocket
        }
        
        # Update statistics
        self.stats["total_connections"] += 1
        self.stats["active_connections"] += 1
        
        # Start broadcast task if not running
        if self.broadcast_task is None or self.broadcast_task.done():
            self.broadcast_task = asyncio.create_task(self._broadcast_messages())
        
        logging.info(f"WebSocket connected: user={user_id}, session={session_id}")
        
        # Send welcome message
        await self.send_to_user(user_id, WebSocketMessage(
            event_type=EventType.USER_NOTIFICATION,
            data={
                "type": "connection_established",
                "message": "Connected to VANTABLACK WebSocket",
                "session_id": session_id
            },
            timestamp=datetime.now()
        ))
        
        return session_id
    
    async def disconnect(self, websocket: WebSocket, user_id: str, session_id: str):
        """Disconnect WebSocket connection"""
        # Remove from active connections
        if user_id in self.active_connections:
            self.active_connections[user_id].remove(websocket)
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
        
        # Remove from room subscriptions
        if session_id in self.connection_metadata:
            subscriptions = self.connection_metadata[session_id]["subscriptions"]
            for room in subscriptions:
                if room in self.room_subscriptions:
                    self.room_subscriptions[room].discard(session_id)
                    if not self.room_subscriptions[room]:
                        del self.room_subscriptions[room]
            
            del self.connection_metadata[session_id]
        
        # Update statistics
        self.stats["active_connections"] -= 1
        
        logging.info(f"WebSocket disconnected: user={user_id}, session={session_id}")
    
    async def send_to_user(self, user_id: str, message: WebSocketMessage):
        """Send message to specific user"""
        if user_id in self.active_connections:
            message.user_id = user_id
            message_data = asdict(message)
            message_data["timestamp"] = message.timestamp.isoformat()
            message_data["event_type"] = message.event_type.value
            
            # Send to all connections for this user
            disconnected = []
            for websocket in self.active_connections[user_id]:
                try:
                    await websocket.send_text(json.dumps(message_data))
                    self.stats["messages_sent"] += 1
                except Exception as e:
                    logging.error(f"Error sending to user {user_id}: {e}")
                    disconnected.append(websocket)
            
            # Remove disconnected connections
            for ws in disconnected:
                self.active_connections[user_id].remove(ws)
    
    async def send_to_room(self, room: str, message: WebSocketMessage):
        """Send message to all subscribers in a room"""
        if room in self.room_subscriptions:
            message_data = asdict(message)
            message_data["timestamp"] = message.timestamp.isoformat()
            message_data["event_type"] = message.event_type.value
            
            # Send to all room subscribers
            disconnected_sessions = []
            for session_id in self.room_subscriptions[room]:
                if session_id in self.connection_metadata:
                    websocket = self.connection_metadata[session_id]["websocket"]
                    try:
                        await websocket.send_text(json.dumps(message_data))
                        self.stats["messages_sent"] += 1
                    except Exception as e:
                        logging.error(f"Error sending to room {room}, session {session_id}: {e}")
                        disconnected_sessions.append(session_id)
            
            # Remove disconnected sessions
            for session_id in disconnected_sessions:
                self.room_subscriptions[room].discard(session_id)
    
    async def broadcast(self, message: WebSocketMessage):
        """Broadcast message to all connected users"""
        message_data = asdict(message)
        message_data["timestamp"] = message.timestamp.isoformat()
        message_data["event_type"] = message.event_type.value
        
        # Send to all active connections
        disconnected_users = []
        for user_id, websockets in self.active_connections.items():
            user_disconnected = []
            for websocket in websockets:
                try:
                    await websocket.send_text(json.dumps(message_data))
                    self.stats["messages_sent"] += 1
                except Exception as e:
                    logging.error(f"Error broadcasting to user {user_id}: {e}")
                    user_disconnected.append(websocket)
            
            # Remove disconnected connections
            for ws in user_disconnected:
                websockets.remove(ws)
            
            if not websockets:
                disconnected_users.append(user_id)
        
        # Remove users with no connections
        for user_id in disconnected_users:
            del self.active_connections[user_id]
    
    async def subscribe_to_room(self, user_id: str, session_id: str, room: str):
        """Subscribe user to a room"""
        if session_id in self.connection_metadata:
            self.connection_metadata[session_id]["subscriptions"].add(room)
            
            if room not in self.room_subscriptions:
                self.room_subscriptions[room] = set()
            
            self.room_subscriptions[room].add(session_id)
            
            logging.info(f"User {user_id} subscribed to room {room}")
            
            # Send confirmation
            await self.send_to_user(user_id, WebSocketMessage(
                event_type=EventType.USER_NOTIFICATION,
                data={
                    "type": "subscription_confirmed",
                    "room": room,
                    "message": f"Subscribed to {room}"
                },
                timestamp=datetime.now()
            ))
    
    async def unsubscribe_from_room(self, user_id: str, session_id: str, room: str):
        """Unsubscribe user from a room"""
        if session_id in self.connection_metadata:
            self.connection_metadata[session_id]["subscriptions"].discard(room)
            
            if room in self.room_subscriptions:
                self.room_subscriptions[room].discard(session_id)
                if not self.room_subscriptions[room]:
                    del self.room_subscriptions[room]
            
            logging.info(f"User {user_id} unsubscribed from room {room}")
            
            # Send confirmation
            await self.send_to_user(user_id, WebSocketMessage(
                event_type=EventType.USER_NOTIFICATION,
                data={
                    "type": "unsubscription_confirmed",
                    "room": room,
                    "message": f"Unsubscribed from {room}"
                },
                timestamp=datetime.now()
            ))
    
    async def handle_message(self, websocket: WebSocket, user_id: str, session_id: str, message_data: Dict[str, Any]):
        """Handle incoming WebSocket message"""
        self.stats["messages_received"] += 1
        
        # Update last activity
        if session_id in self.connection_metadata:
            self.connection_metadata[session_id]["last_activity"] = datetime.now()
        
        message_type = message_data.get("type")
        
        if message_type == "subscribe":
            room = message_data.get("room")
            if room:
                await self.subscribe_to_room(user_id, session_id, room)
        
        elif message_type == "unsubscribe":
            room = message_data.get("room")
            if room:
                await self.unsubscribe_from_room(user_id, session_id, room)
        
        elif message_type == "ping":
            # Handle ping/pong
            await self.send_to_user(user_id, WebSocketMessage(
                event_type=EventType.USER_NOTIFICATION,
                data={"type": "pong", "timestamp": datetime.now().isoformat()},
                timestamp=datetime.now()
            ))
        
        else:
            # Handle custom message types
            await self._handle_custom_message(user_id, session_id, message_data)
    
    async def _handle_custom_message(self, user_id: str, session_id: str, message_data: Dict[str, Any]):
        """Handle custom message types"""
        # This can be extended to handle custom message types
        logging.info(f"Custom message from user {user_id}: {message_data}")
    
    async def _broadcast_messages(self):
        """Background task to broadcast queued messages"""
        while True:
            try:
                # Get message from queue
                message = await self.message_queue.get()
                
                # Broadcast based on message type
                if message.user_id:
                    await self.send_to_user(message.user_id, message)
                else:
                    await self.broadcast(message)
                
            except Exception as e:
                logging.error(f"Error in broadcast task: {e}")
                await asyncio.sleep(1)
    
    def register_event_handler(self, event_type: EventType, handler: callable):
        """Register event handler"""
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        
        self.event_handlers[event_type].append(handler)
    
    async def emit_event(self, event_type: EventType, data: Dict[str, Any], 
                        user_id: str = None, room: str = None):
        """Emit event to subscribers"""
        message = WebSocketMessage(
            event_type=event_type,
            data=data,
            timestamp=datetime.now(),
            user_id=user_id
        )
        
        # Call event handlers
        if event_type in self.event_handlers:
            for handler in self.event_handlers[event_type]:
                try:
                    await handler(message)
                except Exception as e:
                    logging.error(f"Error in event handler: {e}")
        
        # Send message
        if room:
            await self.send_to_room(room, message)
        elif user_id:
            await self.send_to_user(user_id, message)
        else:
            await self.broadcast(message)
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """Get connection statistics"""
        self.stats["active_connections"] = sum(len(connections) for connections in self.active_connections.values())
        self.stats["rooms_active"] = len(self.room_subscriptions)
        
        return {
            **self.stats,
            "users_connected": len(self.active_connections),
            "rooms": {room: len(subscribers) for room, subscribers in self.room_subscriptions.items()}
        }
    
    def get_user_connections(self, user_id: str) -> List[Dict[str, Any]]:
        """Get user connection details"""
        connections = []
        
        if user_id in self.active_connections:
            for session_id, metadata in self.connection_metadata.items():
                if metadata["user_id"] == user_id:
                    connections.append({
                        "session_id": session_id,
                        "connected_at": metadata["connected_at"].isoformat(),
                        "last_activity": metadata["last_activity"].isoformat(),
                        "subscriptions": list(metadata["subscriptions"])
                    })
        
        return connections


class WebSocketEventHandler:
    """WebSocket event handlers for different event types"""
    
    def __init__(self, manager: WebSocketManager):
        self.manager = manager
        
        # Register event handlers
        self.manager.register_event_handler(EventType.CAMPAIGN_UPDATE, self.handle_campaign_update)
        self.manager.register_event_handler(EventType.ANALYTICS_UPDATE, self.handle_analytics_update)
        self.manager.register_event_handler(EventType.SYSTEM_ALERT, self.handle_system_alert)
        self.manager.register_event_handler(EventType.TEMPLATE_UPDATE, self.handle_template_update)
        self.manager.register_event_handler(EventType.OPTIMIZATION_UPDATE, self.handle_optimization_update)
    
    async def handle_campaign_update(self, message: WebSocketMessage):
        """Handle campaign update events"""
        data = message.data
        campaign_id = data.get("campaign_id")
        
        # Send to campaign room
        await self.manager.send_to_room(f"campaign_{campaign_id}", message)
        
        # Log event
        logging.info(f"Campaign update: {campaign_id}")
    
    async def handle_analytics_update(self, message: WebSocketMessage):
        """Handle analytics update events"""
        data = message.data
        
        # Send to analytics room
        await self.manager.send_to_room("analytics", message)
        
        # Send to specific user if specified
        if message.user_id:
            await self.manager.send_to_user(message.user_id, message)
    
    async def handle_system_alert(self, message: WebSocketMessage):
        """Handle system alert events"""
        data = message.data
        alert_level = data.get("level", "info")
        
        # Send to admin users
        admin_users = ["admin1", "admin2"]  # This would come from user management
        
        for admin_id in admin_users:
            await self.manager.send_to_user(admin_id, message)
        
        # Send to system room
        await self.manager.send_to_room("system_alerts", message)
        
        # Log alert
        logging.warning(f"System alert: {alert_level} - {data.get('message', 'No message')}")
    
    async def handle_template_update(self, message: WebSocketMessage):
        """Handle template update events"""
        data = message.data
        template_id = data.get("template_id")
        
        # Send to template room
        await self.manager.send_to_room(f"template_{template_id}", message)
        
        # Send to marketplace room
        await self.manager.send_to_room("marketplace", message)
    
    async def handle_optimization_update(self, message: WebSocketMessage):
        """Handle optimization update events"""
        data = message.data
        optimization_id = data.get("optimization_id")
        
        # Send to optimization room
        await self.manager.send_to_room(f"optimization_{optimization_id}", message)
        
        # Send to specific user if specified
        if message.user_id:
            await self.manager.send_to_user(message.user_id, message)


# Global WebSocket manager
websocket_manager = WebSocketManager()
websocket_event_handler = WebSocketEventHandler(websocket_manager)


# Helper functions for common WebSocket operations
async def notify_campaign_update(campaign_id: str, update_data: Dict[str, Any]):
    """Notify campaign subscribers of updates"""
    await websocket_manager.emit_event(
        EventType.CAMPAIGN_UPDATE,
        update_data,
        room=f"campaign_{campaign_id}"
    )


async def notify_analytics_update(user_id: str, analytics_data: Dict[str, Any]):
    """Notify user of analytics updates"""
    await websocket_manager.emit_event(
        EventType.ANALYTICS_UPDATE,
        analytics_data,
        user_id=user_id
    )


async def notify_system_alert(alert_data: Dict[str, Any]):
    """Notify system alert to admins"""
    await websocket_manager.emit_event(
        EventType.SYSTEM_ALERT,
        alert_data
    )


async def notify_template_update(template_id: str, update_data: Dict[str, Any]):
    """Notify template subscribers of updates"""
    await websocket_manager.emit_event(
        EventType.TEMPLATE_UPDATE,
        update_data,
        room=f"template_{template_id}"
    )


async def notify_optimization_update(optimization_id: str, update_data: Dict[str, Any], user_id: str = None):
    """Notify optimization subscribers of updates"""
    await websocket_manager.emit_event(
        EventType.OPTIMIZATION_UPDATE,
        update_data,
        user_id=user_id,
        room=f"optimization_{optimization_id}"
    )


# WebSocket endpoint handler
async def websocket_endpoint(websocket: WebSocket, user_id: str, session_id: str = None):
    """Main WebSocket endpoint handler"""
    try:
        # Connect
        session_id = await websocket_manager.connect(websocket, user_id, session_id)
        
        # Handle messages
        while True:
            try:
                # Receive message
                data = await websocket.receive_text()
                message_data = json.loads(data)
                
                # Handle message
                await websocket_manager.handle_message(websocket, user_id, session_id, message_data)
                
            except WebSocketDisconnect:
                break
            except Exception as e:
                logging.error(f"Error handling WebSocket message: {e}")
                break
    
    except WebSocketDisconnect:
        pass
    finally:
        # Disconnect
        await websocket_manager.disconnect(websocket, user_id, session_id)


# Example usage in FastAPI
"""
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends
from fastapi.security import HTTPBearer

app = FastAPI()
security = HTTPBearer()

@app.websocket("/ws/{user_id}")
async def websocket_route(websocket: WebSocket, user_id: str):
    await websocket_endpoint(websocket, user_id)

@app.websocket("/ws/{user_id}/{session_id}")
async def websocket_route_with_session(websocket: WebSocket, user_id: str, session_id: str):
    await websocket_endpoint(websocket, user_id, session_id)
"""
