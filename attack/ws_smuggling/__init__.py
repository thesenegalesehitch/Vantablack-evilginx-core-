"""WebSocket Smuggling package."""

from .smuggler import (
    TunnelConfig,
    WSSmugglingTunnel,
    register_ws_routes,
)

__all__ = [
    "TunnelConfig",
    "WSSmugglingTunnel",
    "register_ws_routes",
]
