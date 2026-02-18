"""
VANTABLACK Plugin API - Plugin Development Interface
==================================================

Plugin API for plugin developers:
- Safe API access
- Resource management
- Configuration access
- Logging utilities
- Event emission
- Data storage
"""

import logging
import json
import os
from typing import Dict, List, Any, Optional, Union
from datetime import datetime
from dataclasses import dataclass
import asyncio
from pathlib import Path


@dataclass
class APIEndpoint:
    """API endpoint definition"""
    path: str
    method: str
    handler: callable
    plugin_id: str
    description: str
    permissions: List[str]
    rate_limit: Optional[int] = None


class PluginAPI:
    """Plugin API interface"""
    
    def __init__(self, plugin_manager):
        self.plugin_manager = plugin_manager
        self.logger = logging.getLogger("plugin_api")
        
        # API endpoints registry
        self.endpoints: Dict[str, APIEndpoint] = {}
        
        # Plugin data storage
        self.data_storage: Dict[str, Dict[str, Any]] = {}
        
        # Plugin configuration
        self.config_cache: Dict[str, Dict[str, Any]] = {}
        
        # Resource limits
        self.resource_limits: Dict[str, Dict[str, Any]] = {}
        
        # API statistics
        self.stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "data_operations": 0,
            "config_operations": 0
        }
    
    def get_plugin_info(self, plugin_id: str) -> Optional[Dict[str, Any]]:
        """Get plugin information"""
        return self.plugin_manager.get_plugin_info(plugin_id)
    
    def get_plugin_config(self, plugin_id: str) -> Dict[str, Any]:
        """Get plugin configuration"""
        if plugin_id not in self.config_cache:
            config = self.plugin_manager.get_plugin_config(plugin_id)
            self.config_cache[plugin_id] = config or {}
        
        return self.config_cache[plugin_id].copy()
    
    async def update_plugin_config(self, plugin_id: str, config_data: Dict[str, Any]) -> bool:
        """Update plugin configuration"""
        success = await self.plugin_manager.update_plugin_config(plugin_id, config_data)
        
        if success:
            # Update cache
            if plugin_id not in self.config_cache:
                self.config_cache[plugin_id] = {}
            self.config_cache[plugin_id].update(config_data)
            self.stats["config_operations"] += 1
        
        return success
    
    def get_data(self, plugin_id: str, key: str, default: Any = None) -> Any:
        """Get plugin data"""
        if plugin_id not in self.data_storage:
            self.data_storage[plugin_id] = {}
        
        return self.data_storage[plugin_id].get(key, default)
    
    def set_data(self, plugin_id: str, key: str, value: Any) -> bool:
        """Set plugin data"""
        try:
            if plugin_id not in self.data_storage:
                self.data_storage[plugin_id] = {}
            
            self.data_storage[plugin_id][key] = value
            self.stats["data_operations"] += 1
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to set data for plugin {plugin_id}: {e}")
            return False
    
    def delete_data(self, plugin_id: str, key: str) -> bool:
        """Delete plugin data"""
        try:
            if plugin_id in self.data_storage and key in self.data_storage[plugin_id]:
                del self.data_storage[plugin_id][key]
                self.stats["data_operations"] += 1
                return True
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to delete data for plugin {plugin_id}: {e}")
            return False
    
    def get_all_data(self, plugin_id: str) -> Dict[str, Any]:
        """Get all plugin data"""
        return self.data_storage.get(plugin_id, {}).copy()
    
    def clear_data(self, plugin_id: str) -> bool:
        """Clear all plugin data"""
        try:
            if plugin_id in self.data_storage:
                del self.data_storage[plugin_id]
                self.stats["data_operations"] += 1
                return True
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to clear data for plugin {plugin_id}: {e}")
            return False
    
    def persist_data(self, plugin_id: str, file_path: str = None) -> bool:
        """Persist plugin data to file"""
        try:
            if plugin_id not in self.data_storage:
                return True  # No data to persist
            
            if file_path is None:
                file_path = os.path.join(self.plugin_manager.config_dir, f"{plugin_id}_data.json")
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            # Save data
            with open(file_path, 'w') as f:
                json.dump(self.data_storage[plugin_id], f, indent=2, default=str)
            
            self.logger.info(f"Plugin data persisted: {plugin_id} -> {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to persist data for plugin {plugin_id}: {e}")
            return False
    
    def load_data(self, plugin_id: str, file_path: str = None) -> bool:
        """Load plugin data from file"""
        try:
            if file_path is None:
                file_path = os.path.join(self.plugin_manager.config_dir, f"{plugin_id}_data.json")
            
            if not os.path.exists(file_path):
                return True  # No data to load
            
            # Load data
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            if plugin_id not in self.data_storage:
                self.data_storage[plugin_id] = {}
            
            self.data_storage[plugin_id].update(data)
            self.logger.info(f"Plugin data loaded: {plugin_id} <- {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load data for plugin {plugin_id}: {e}")
            return False
    
    def register_endpoint(self, plugin_id: str, endpoint_config: Dict[str, Any], plugin_instance):
        """Register API endpoint"""
        try:
            endpoint = APIEndpoint(
                path=endpoint_config["path"],
                method=endpoint_config["method"],
                handler=getattr(plugin_instance, endpoint_config["handler"]),
                plugin_id=plugin_id,
                description=endpoint_config.get("description", ""),
                permissions=endpoint_config.get("permissions", []),
                rate_limit=endpoint_config.get("rate_limit")
            )
            
            endpoint_key = f"{endpoint.method}:{endpoint.path}"
            self.endpoints[endpoint_key] = endpoint
            
            self.logger.info(f"API endpoint registered: {endpoint_key} by plugin {plugin_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to register endpoint for plugin {plugin_id}: {e}")
            return False
    
    def unregister_endpoint(self, plugin_id: str, path: str, method: str) -> bool:
        """Unregister API endpoint"""
        try:
            endpoint_key = f"{method}:{path}"
            if endpoint_key in self.endpoints:
                endpoint = self.endpoints[endpoint_key]
                if endpoint.plugin_id == plugin_id:
                    del self.endpoints[endpoint_key]
                    self.logger.info(f"API endpoint unregistered: {endpoint_key} by plugin {plugin_id}")
                    return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to unregister endpoint for plugin {plugin_id}: {e}")
            return False
    
    async def execute_hook(self, hook_name: str, *args, **kwargs) -> List[Any]:
        """Execute plugin hook"""
        if self.plugin_manager.hook_system:
            return await self.plugin_manager.hook_system.execute_hook(hook_name, *args, **kwargs)
        return []
    
    def emit_event(self, event_type: str, data: Dict[str, Any], target_plugin_id: str = None):
        """Emit event to plugins"""
        # This would integrate with the event system
        self.logger.info(f"Event emitted: {event_type} -> {target_plugin_id or 'all'}")
    
    def get_logger(self, plugin_id: str) -> logging.Logger:
        """Get logger for plugin"""
        logger_name = f"plugin.{plugin_id}"
        logger = logging.getLogger(logger_name)
        
        # Create plugin-specific handler if needed
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                f'[{asctime}] [{levelname}] [plugin:{plugin_id}] {message}',
                style='{'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        
        return logger
    
    def check_permission(self, plugin_id: str, permission: str) -> bool:
        """Check if plugin has permission"""
        plugin_info = self.get_plugin_info(plugin_id)
        if not plugin_info:
            return False
        
        permissions = plugin_info.get("metadata", {}).get("permissions", [])
        return permission in permissions
    
    def get_resource_limits(self, plugin_id: str) -> Dict[str, Any]:
        """Get resource limits for plugin"""
        if plugin_id not in self.resource_limits:
            plugin_info = self.get_plugin_info(plugin_id)
            if plugin_info:
                self.resource_limits[plugin_id] = plugin_info.get("config", {}).get("resource_limits", {})
            else:
                self.resource_limits[plugin_id] = {}
        
        return self.resource_limits[plugin_id].copy()
    
    def set_resource_limit(self, plugin_id: str, resource: str, limit: Any) -> bool:
        """Set resource limit for plugin"""
        try:
            if plugin_id not in self.resource_limits:
                self.resource_limits[plugin_id] = {}
            
            self.resource_limits[plugin_id][resource] = limit
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to set resource limit for plugin {plugin_id}: {e}")
            return False
    
    def check_resource_limit(self, plugin_id: str, resource: str, current_value: Any) -> bool:
        """Check if resource usage is within limits"""
        limits = self.get_resource_limits(plugin_id)
        
        if resource not in limits:
            return True  # No limit set
        
        limit = limits[resource]
        
        # Different limit types
        if isinstance(limit, int) and isinstance(current_value, int):
            return current_value <= limit
        elif isinstance(limit, float) and isinstance(current_value, float):
            return current_value <= limit
        elif isinstance(limit, str) and isinstance(current_value, str):
            return len(current_value) <= int(limit)
        
        return True
    
    def get_plugin_directory(self, plugin_id: str) -> str:
        """Get plugin directory path"""
        return os.path.join(self.plugin_manager.plugin_dir, plugin_id)
    
    def get_plugin_config_directory(self, plugin_id: str) -> str:
        """Get plugin config directory path"""
        config_dir = os.path.join(self.plugin_manager.config_dir, plugin_id)
        os.makedirs(config_dir, exist_ok=True)
        return config_dir
    
    def get_plugin_data_directory(self, plugin_id: str) -> str:
        """Get plugin data directory path"""
        data_dir = os.path.join(self.plugin_manager.config_dir, f"{plugin_id}_data")
        os.makedirs(data_dir, exist_ok=True)
        return data_dir
    
    def get_plugin_logs_directory(self, plugin_id: str) -> str:
        """Get plugin logs directory path"""
        logs_dir = os.path.join("logs", "plugins", plugin_id)
        os.makedirs(logs_dir, exist_ok=True)
        return logs_dir
    
    def create_plugin_file(self, plugin_id: str, file_path: str, content: str) -> bool:
        """Create file in plugin directory"""
        try:
            full_path = os.path.join(self.get_plugin_directory(plugin_id), file_path)
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            
            # Write file
            with open(full_path, 'w') as f:
                f.write(content)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create file for plugin {plugin_id}: {e}")
            return False
    
    def read_plugin_file(self, plugin_id: str, file_path: str) -> Optional[str]:
        """Read file from plugin directory"""
        try:
            full_path = os.path.join(self.get_plugin_directory(plugin_id), file_path)
            
            if os.path.exists(full_path):
                with open(full_path, 'r') as f:
                    return f.read()
            
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to read file for plugin {plugin_id}: {e}")
            return None
    
    def delete_plugin_file(self, plugin_id: str, file_path: str) -> bool:
        """Delete file from plugin directory"""
        try:
            full_path = os.path.join(self.get_plugin_directory(plugin_id), file_path)
            
            if os.path.exists(full_path):
                os.remove(full_path)
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to delete file for plugin {plugin_id}: {e}")
            return False
    
    def list_plugin_files(self, plugin_id: str, directory: str = "") -> List[str]:
        """List files in plugin directory"""
        try:
            full_path = os.path.join(self.get_plugin_directory(plugin_id), directory)
            
            if os.path.exists(full_path):
                files = []
                for root, dirs, filenames in os.walk(full_path):
                    for filename in filenames:
                        rel_path = os.path.relpath(os.path.join(root, filename), full_path)
                        files.append(rel_path)
                return files
            
            return []
            
        except Exception as e:
            self.logger.error(f"Failed to list files for plugin {plugin_id}: {e}")
            return []
    
    def get_stats(self) -> Dict[str, Any]:
        """Get API statistics"""
        self.stats["registered_endpoints"] = len(self.endpoints)
        self.stats["active_plugins"] = len(self.data_storage)
        return self.stats.copy()
    
    def cleanup(self, plugin_id: str = None):
        """Cleanup API resources"""
        if plugin_id:
            # Cleanup specific plugin
            if plugin_id in self.data_storage:
                del self.data_storage[plugin_id]
            
            if plugin_id in self.config_cache:
                del self.config_cache[plugin_id]
            
            if plugin_id in self.resource_limits:
                del self.resource_limits[plugin_id]
            
            # Remove endpoints
            endpoints_to_remove = []
            for key, endpoint in self.endpoints.items():
                if endpoint.plugin_id == plugin_id:
                    endpoints_to_remove.append(key)
            
            for key in endpoints_to_remove:
                del self.endpoints[key]
            
            self.logger.info(f"API cleanup completed for plugin: {plugin_id}")
        else:
            # Cleanup all
            self.data_storage.clear()
            self.config_cache.clear()
            self.resource_limits.clear()
            self.endpoints.clear()
            
            self.logger.info("API cleanup completed for all plugins")


class PluginBase:
    """Base class for plugins"""
    
    def __init__(self, api: PluginAPI, config: Dict[str, Any]):
        self.api = api
        self.config = config
        self.plugin_id = config.get("plugin_id", "unknown")
        self.logger = api.get_logger(self.plugin_id)
        
        # Plugin metadata
        self.__plugin__ = True
        self.__plugin_id__ = self.plugin_id
        self.__plugin_type__ = "base"
        
        # Plugin state
        self.is_running = False
        self.start_time = None
    
    async def start(self):
        """Start plugin"""
        self.logger.info(f"Starting plugin: {self.plugin_id}")
        self.is_running = True
        self.start_time = datetime.now()
        
        # Emit start event
        await self.api.execute_hook("plugin.after_start", self.plugin_id)
    
    async def stop(self):
        """Stop plugin"""
        self.logger.info(f"Stopping plugin: {self.plugin_id}")
        self.is_running = False
        
        # Emit stop event
        await self.api.execute_hook("plugin.after_stop", self.plugin_id)
    
    async def on_config_change(self, new_config: Dict[str, Any]):
        """Handle configuration change"""
        self.logger.info(f"Configuration changed for plugin: {self.plugin_id}")
        self.config.update(new_config)
        
        # Emit config change event
        await self.api.execute_hook("plugin.config_changed", self.plugin_id, new_config)
    
    def get_status(self) -> Dict[str, Any]:
        """Get plugin status"""
        return {
            "plugin_id": self.plugin_id,
            "is_running": self.is_running,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "uptime": (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        }
    
    def health_check(self) -> Dict[str, Any]:
        """Plugin health check"""
        return {
            "healthy": self.is_running,
            "status": "running" if self.is_running else "stopped",
            "last_check": datetime.now().isoformat()
        }


# Plugin decorators
def plugin_endpoint(path: str, method: str = "GET", permissions: List[str] = None, 
                   rate_limit: int = None, description: str = ""):
    """Decorator for plugin API endpoints"""
    def decorator(func):
        func.__endpoint_config__ = {
            "path": path,
            "method": method,
            "permissions": permissions or [],
            "rate_limit": rate_limit,
            "description": description,
            "handler": func.__name__
        }
        return func
    return decorator


def plugin_hook(hook_name: str, priority: int = 50):
    """Decorator for plugin hooks"""
    def decorator(func):
        func.__hook_name__ = hook_name
        func.__hook_priority__ = priority
        return func
    return decorator


def plugin_permission(permission: str):
    """Decorator for permission checking"""
    def decorator(func):
        func.__required_permission__ = permission
        return func
    return decorator
