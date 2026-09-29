"""Anti-forensics package - extended wiper & log sanitization."""

from .wiper import (
    AntiForensicsWiper,
    WipeTarget,
    register_wipe_routes,
)

__all__ = [
    "AntiForensicsWiper",
    "WipeTarget",
    "register_wipe_routes",
]
