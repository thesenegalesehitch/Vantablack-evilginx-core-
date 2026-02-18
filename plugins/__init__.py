"""
VANTABLACK Plugin System - Extensible Architecture
==================================================

Comprehensive plugin system for extensibility:
- Plugin loading and management
- Hook system for event handling
- Plugin configuration
- Plugin marketplace
- Security sandboxing
- API extensions
"""

from .plugin_manager import PluginManager
from .plugin_loader import PluginLoader
from .hook_system import HookSystem
from .plugin_api import PluginAPI
from .plugin_sandbox import PluginSandbox

__all__ = ["PluginManager", "PluginLoader", "HookSystem", "PluginAPI", "PluginSandbox"]
