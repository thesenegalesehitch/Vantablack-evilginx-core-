"""
VANTABLACK API - Red Team Integration
=====================================

Comprehensive API for Red Team operations:
- RESTful API endpoints
- WebSocket real-time communication
- Authentication and authorization
- Rate limiting and security
- Integration with external tools
"""

from .rest_api import VantablackAPI
from .websocket_server import WebSocketServer
from .auth_manager import AuthManager
from .rate_limiter import RateLimiter
from .integration_manager import IntegrationManager

__all__ = ["VantablackAPI", "WebSocketServer", "AuthManager", "RateLimiter", "IntegrationManager"]
