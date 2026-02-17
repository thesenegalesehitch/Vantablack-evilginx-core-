"""
VANTABLACK Plugin Manager - Core Plugin Management
==================================================

Plugin management system:
- Plugin discovery and loading
- Plugin lifecycle management
- Plugin configuration
- Plugin dependencies
- Plugin marketplace integration
"""

import os
import json
import yaml
import importlib
import inspect
import logging
from typing import Dict, List, Any, Optional, Type, Callable
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import zipfile
import tempfile
import shutil


class PluginStatus(Enum):
    """Plugin status"""
    INSTALLED = "installed"
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    UPDATING = "updating"
    DISABLED = "disabled"


class PluginType(Enum):
    """Plugin types"""
    ANALYSIS = "analysis"
    MUTATION = "mutation"
    TEMPLATE = "template"
    INTEGRATION = "integration"
    AUTHENTICATION = "authentication"
    NOTIFICATION = "notification"
    MONITORING = "monitoring"
    UTILITY = "utility"


@dataclass
class PluginMetadata:
    """Plugin metadata"""
    plugin_id: str
    name: str
    version: str
    description: str
    author: str
    email: str
    website: str
    license: str
    plugin_type: PluginType
    category: str
    tags: List[str]
    dependencies: List[str]
    python_version: str
    vantablack_version: str
    install_date: datetime
    last_updated: datetime
    file_hash: str
    config_schema: Dict[str, Any]
    hooks: List[str]
    api_endpoints: List[str]
    permissions: List[str]


@dataclass
class PluginConfig:
    """Plugin configuration"""
    plugin_id: str
    config_data: Dict[str, Any]
    is_enabled: bool
    auto_start: bool
    priority: int
    resource_limits: Dict[str, Any]


@dataclass
class PluginInstance:
    """Plugin instance"""
    metadata: PluginMetadata
    config: PluginConfig
    module: Any
    instance: Any
    status: PluginStatus
    error_message: Optional[str]
    load_time: datetime
    last_activity: datetime


class PluginManager:
    """Main plugin manager"""
    
    def __init__(self, plugin_dir: str = "plugins", config_dir: str = "config/plugins"):
        self.plugin_dir = plugin_dir
        self.config_dir = config_dir
        self.plugins: Dict[str, PluginInstance] = {}
        self.plugin_dependencies: Dict[str, List[str]] = {}
        self.hook_system = None
        self.plugin_api = None
        self.sandbox = None
        
        # Statistics
        self.stats = {
            "total_plugins": 0,
            "active_plugins": 0,
            "failed_plugins": 0,
            "total_hooks": 0,
            "total_api_endpoints": 0
        }
        
        # Ensure directories exist
        os.makedirs(plugin_dir, exist_ok=True)
        os.makedirs(config_dir, exist_ok=True)
        
        # Initialize components
        self._initialize_components()
        
        # Load installed plugins
        self._load_installed_plugins()
    
    def _initialize_components(self):
        """Initialize plugin system components"""
        from .hook_system import HookSystem
        from .plugin_api import PluginAPI
        from .plugin_sandbox import PluginSandbox
        
        self.hook_system = HookSystem()
        self.plugin_api = PluginAPI(self)
        self.sandbox = PluginSandbox()
    
    def _load_installed_plugins(self):
        """Load all installed plugins"""
        logging.info("Loading installed plugins...")
        
        for plugin_name in os.listdir(self.plugin_dir):
            plugin_path = os.path.join(self.plugin_dir, plugin_name)
            
            if os.path.isdir(plugin_path):
                try:
                    self._load_plugin_from_directory(plugin_path)
                except Exception as e:
                    logging.error(f"Failed to load plugin {plugin_name}: {e}")
        
        logging.info(f"Loaded {len(self.plugins)} plugins")
    
    def _load_plugin_from_directory(self, plugin_path: str):
        """Load plugin from directory"""
        # Check for plugin manifest
        manifest_path = os.path.join(plugin_path, "plugin.yaml")
        if not os.path.exists(manifest_path):
            manifest_path = os.path.join(plugin_path, "plugin.json")
        
        if not os.path.exists(manifest_path):
            raise ValueError("Plugin manifest not found")
        
        # Load manifest
        with open(manifest_path, 'r') as f:
            if manifest_path.endswith('.yaml'):
                manifest = yaml.safe_load(f)
            else:
                manifest = json.load(f)
        
        # Validate manifest
        self._validate_manifest(manifest)
        
        # Create metadata
        metadata = PluginMetadata(
            plugin_id=manifest["plugin_id"],
            name=manifest["name"],
            version=manifest["version"],
            description=manifest["description"],
            author=manifest["author"],
            email=manifest.get("email", ""),
            website=manifest.get("website", ""),
            license=manifest.get("license", "MIT"),
            plugin_type=PluginType(manifest["type"]),
            category=manifest.get("category", "general"),
            tags=manifest.get("tags", []),
            dependencies=manifest.get("dependencies", []),
            python_version=manifest.get("python_version", "3.9+"),
            vantablack_version=manifest.get("vantablack_version", "4.0.0"),
            install_date=datetime.now(),
            last_updated=datetime.now(),
            file_hash=self._calculate_directory_hash(plugin_path),
            config_schema=manifest.get("config_schema", {}),
            hooks=manifest.get("hooks", []),
            api_endpoints=manifest.get("api_endpoints", []),
            permissions=manifest.get("permissions", [])
        )
        
        # Load plugin configuration
        config = self._load_plugin_config(metadata.plugin_id)
        
        # Check if plugin should be loaded
        if not config.is_enabled:
            logging.info(f"Plugin {metadata.plugin_id} is disabled")
            return
        
        # Load plugin module
        module_path = os.path.join(plugin_path, manifest.get("main_file", "main.py"))
        if not os.path.exists(module_path):
            raise ValueError(f"Main file not found: {module_path}")
        
        # Import plugin module
        spec = importlib.util.spec_from_file_location(metadata.plugin_id, module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        # Find plugin class
        plugin_class = None
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if hasattr(obj, '__plugin__') and obj.__plugin__:
                plugin_class = obj
                break
        
        if not plugin_class:
            raise ValueError("Plugin class not found")
        
        # Create plugin instance
        try:
            instance = plugin_class(self.plugin_api, config.config_data)
        except Exception as e:
            raise ValueError(f"Failed to create plugin instance: {e}")
        
        # Create plugin instance object
        plugin_instance = PluginInstance(
            metadata=metadata,
            config=config,
            module=module,
            instance=instance,
            status=PluginStatus.ACTIVE,
            error_message=None,
            load_time=datetime.now(),
            last_activity=datetime.now()
        )
        
        # Register plugin
        self.plugins[metadata.plugin_id] = plugin_instance
        
        # Register hooks
        for hook_name in metadata.hooks:
            self.hook_system.register_hook(hook_name, instance)
        
        # Register API endpoints
        for endpoint in metadata.api_endpoints:
            self.plugin_api.register_endpoint(metadata.plugin_id, endpoint, instance)
        
        # Update statistics
        self.stats["total_plugins"] += 1
        self.stats["active_plugins"] += 1
        self.stats["total_hooks"] += len(metadata.hooks)
        self.stats["total_api_endpoints"] += len(metadata.api_endpoints)
        
        logging.info(f"Plugin loaded: {metadata.name} v{metadata.version}")
    
    def _validate_manifest(self, manifest: Dict[str, Any]):
        """Validate plugin manifest"""
        required_fields = ["plugin_id", "name", "version", "description", "author", "type"]
        
        for field in required_fields:
            if field not in manifest:
                raise ValueError(f"Required field missing: {field}")
        
        # Validate plugin ID format
        plugin_id = manifest["plugin_id"]
        if not plugin_id.replace("-", "").replace("_", "").isalnum():
            raise ValueError("Invalid plugin ID format")
        
        # Validate version format
        version = manifest["version"]
        if not isinstance(version, str) or not version.count(".") >= 1:
            raise ValueError("Invalid version format")
    
    def _calculate_directory_hash(self, directory: str) -> str:
        """Calculate hash of directory contents"""
        hash_md5 = hashlib.md5()
        
        for root, dirs, files in os.walk(directory):
            for file in sorted(files):
                if file.endswith(('.py', '.yaml', '.json', '.md')):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'rb') as f:
                        hash_md5.update(f.read())
        
        return hash_md5.hexdigest()
    
    def _load_plugin_config(self, plugin_id: str) -> PluginConfig:
        """Load plugin configuration"""
        config_file = os.path.join(self.config_dir, f"{plugin_id}.json")
        
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config_data = json.load(f)
        else:
            config_data = {}
        
        return PluginConfig(
            plugin_id=plugin_id,
            config_data=config_data.get("config", {}),
            is_enabled=config_data.get("enabled", True),
            auto_start=config_data.get("auto_start", True),
            priority=config_data.get("priority", 100),
            resource_limits=config_data.get("resource_limits", {})
        )
    
    def _save_plugin_config(self, config: PluginConfig):
        """Save plugin configuration"""
        config_file = os.path.join(self.config_dir, f"{config.plugin_id}.json")
        
        config_data = {
            "config": config.config_data,
            "enabled": config.is_enabled,
            "auto_start": config.auto_start,
            "priority": config.priority,
            "resource_limits": config.resource_limits
        }
        
        with open(config_file, 'w') as f:
            json.dump(config_data, f, indent=2)
    
    async def install_plugin(self, plugin_package: str) -> str:
        """Install plugin from package file"""
        # Extract plugin package
        with tempfile.TemporaryDirectory() as temp_dir:
            # Extract ZIP file
            with zipfile.ZipFile(plugin_package, 'r') as zip_file:
                zip_file.extractall(temp_dir)
            
            # Find plugin directory
            plugin_dir = None
            for item in os.listdir(temp_dir):
                item_path = os.path.join(temp_dir, item)
                if os.path.isdir(item_path):
                    plugin_dir = item_path
                    break
            
            if not plugin_dir:
                raise ValueError("No plugin directory found in package")
            
            # Load and validate manifest
            manifest_path = os.path.join(plugin_dir, "plugin.yaml")
            if not os.path.exists(manifest_path):
                manifest_path = os.path.join(plugin_dir, "plugin.json")
            
            if not os.path.exists(manifest_path):
                raise ValueError("Plugin manifest not found")
            
            with open(manifest_path, 'r') as f:
                if manifest_path.endswith('.yaml'):
                    manifest = yaml.safe_load(f)
                else:
                    manifest = json.load(f)
            
            self._validate_manifest(manifest)
            plugin_id = manifest["plugin_id"]
            
            # Check if plugin already exists
            if plugin_id in self.plugins:
                raise ValueError(f"Plugin {plugin_id} already installed")
            
            # Check dependencies
            for dependency in manifest.get("dependencies", []):
                if dependency not in self.plugins:
                    raise ValueError(f"Dependency not found: {dependency}")
            
            # Copy plugin to plugins directory
            target_dir = os.path.join(self.plugin_dir, plugin_id)
            if os.path.exists(target_dir):
                shutil.rmtree(target_dir)
            
            shutil.copytree(plugin_dir, target_dir)
            
            # Load plugin
            try:
                self._load_plugin_from_directory(target_dir)
                logging.info(f"Plugin installed: {plugin_id}")
                return plugin_id
            except Exception as e:
                # Remove plugin directory if loading failed
                shutil.rmtree(target_dir)
                raise e
    
    async def uninstall_plugin(self, plugin_id: str) -> bool:
        """Uninstall plugin"""
        if plugin_id not in self.plugins:
            return False
        
        plugin_instance = self.plugins[plugin_id]
        
        # Unregister hooks
        for hook_name in plugin_instance.metadata.hooks:
            self.hook_system.unregister_hook(hook_name, plugin_instance.instance)
        
        # Unregister API endpoints
        for endpoint in plugin_instance.metadata.api_endpoints:
            self.plugin_api.unregister_endpoint(plugin_id, endpoint)
        
        # Stop plugin
        if hasattr(plugin_instance.instance, 'stop'):
            try:
                await plugin_instance.instance.stop()
            except Exception as e:
                logging.error(f"Error stopping plugin {plugin_id}: {e}")
        
        # Remove from plugins
        del self.plugins[plugin_id]
        
        # Remove plugin directory
        plugin_dir = os.path.join(self.plugin_dir, plugin_id)
        if os.path.exists(plugin_dir):
            shutil.rmtree(plugin_dir)
        
        # Remove config file
        config_file = os.path.join(self.config_dir, f"{plugin_id}.json")
        if os.path.exists(config_file):
            os.remove(config_file)
        
        # Update statistics
        self.stats["total_plugins"] -= 1
        if plugin_instance.status == PluginStatus.ACTIVE:
            self.stats["active_plugins"] -= 1
        self.stats["total_hooks"] -= len(plugin_instance.metadata.hooks)
        self.stats["total_api_endpoints"] -= len(plugin_instance.metadata.api_endpoints)
        
        logging.info(f"Plugin uninstalled: {plugin_id}")
        return True
    
    async def enable_plugin(self, plugin_id: str) -> bool:
        """Enable plugin"""
        if plugin_id not in self.plugins:
            return False
        
        plugin_instance = self.plugins[plugin_id]
        
        if plugin_instance.status == PluginStatus.ACTIVE:
            return True
        
        try:
            # Start plugin
            if hasattr(plugin_instance.instance, 'start'):
                await plugin_instance.instance.start()
            
            plugin_instance.status = PluginStatus.ACTIVE
            plugin_instance.config.is_enabled = True
            self._save_plugin_config(plugin_instance.config)
            
            # Re-register hooks and endpoints
            for hook_name in plugin_instance.metadata.hooks:
                self.hook_system.register_hook(hook_name, plugin_instance.instance)
            
            for endpoint in plugin_instance.metadata.api_endpoints:
                self.plugin_api.register_endpoint(plugin_id, endpoint, plugin_instance.instance)
            
            # Update statistics
            self.stats["active_plugins"] += 1
            
            logging.info(f"Plugin enabled: {plugin_id}")
            return True
            
        except Exception as e:
            plugin_instance.status = PluginStatus.ERROR
            plugin_instance.error_message = str(e)
            logging.error(f"Failed to enable plugin {plugin_id}: {e}")
            return False
    
    async def disable_plugin(self, plugin_id: str) -> bool:
        """Disable plugin"""
        if plugin_id not in self.plugins:
            return False
        
        plugin_instance = self.plugins[plugin_id]
        
        if plugin_instance.status != PluginStatus.ACTIVE:
            return True
        
        try:
            # Stop plugin
            if hasattr(plugin_instance.instance, 'stop'):
                await plugin_instance.instance.stop()
            
            plugin_instance.status = PluginStatus.INACTIVE
            plugin_instance.config.is_enabled = False
            self._save_plugin_config(plugin_instance.config)
            
            # Unregister hooks and endpoints
            for hook_name in plugin_instance.metadata.hooks:
                self.hook_system.unregister_hook(hook_name, plugin_instance.instance)
            
            for endpoint in plugin_instance.metadata.api_endpoints:
                self.plugin_api.unregister_endpoint(plugin_id, endpoint)
            
            # Update statistics
            self.stats["active_plugins"] -= 1
            
            logging.info(f"Plugin disabled: {plugin_id}")
            return True
            
        except Exception as e:
            plugin_instance.status = PluginStatus.ERROR
            plugin_instance.error_message = str(e)
            logging.error(f"Failed to disable plugin {plugin_id}: {e}")
            return False
    
    async def update_plugin(self, plugin_id: str, plugin_package: str) -> bool:
        """Update plugin"""
        if plugin_id not in self.plugins:
            return False
        
        # Disable plugin
        await self.disable_plugin(plugin_id)
        
        # Install new version
        try:
            new_plugin_id = await self.install_plugin(plugin_package)
            
            if new_plugin_id != plugin_id:
                # Plugin ID changed, remove old plugin
                await self.uninstall_plugin(plugin_id)
            
            return True
            
        except Exception as e:
            # Try to re-enable old plugin
            await self.enable_plugin(plugin_id)
            logging.error(f"Failed to update plugin {plugin_id}: {e}")
            return False
    
    def get_plugin_info(self, plugin_id: str) -> Optional[Dict[str, Any]]:
        """Get plugin information"""
        if plugin_id not in self.plugins:
            return None
        
        plugin_instance = self.plugins[plugin_id]
        
        return {
            "metadata": asdict(plugin_instance.metadata),
            "config": asdict(plugin_instance.config),
            "status": plugin_instance.status.value,
            "error_message": plugin_instance.error_message,
            "load_time": plugin_instance.load_time.isoformat(),
            "last_activity": plugin_instance.last_activity.isoformat()
        }
    
    def list_plugins(self, status: PluginStatus = None, 
                    plugin_type: PluginType = None) -> List[Dict[str, Any]]:
        """List plugins with optional filters"""
        plugins = []
        
        for plugin_id, plugin_instance in self.plugins.items():
            if status and plugin_instance.status != status:
                continue
            
            if plugin_type and plugin_instance.metadata.plugin_type != plugin_type:
                continue
            
            plugins.append({
                "plugin_id": plugin_id,
                "name": plugin_instance.metadata.name,
                "version": plugin_instance.metadata.version,
                "description": plugin_instance.metadata.description,
                "author": plugin_instance.metadata.author,
                "type": plugin_instance.metadata.plugin_type.value,
                "status": plugin_instance.status.value,
                "load_time": plugin_instance.load_time.isoformat(),
                "last_activity": plugin_instance.last_activity.isoformat()
            })
        
        return plugins
    
    def get_plugin_config(self, plugin_id: str) -> Optional[Dict[str, Any]]:
        """Get plugin configuration"""
        if plugin_id not in self.plugins:
            return None
        
        plugin_instance = self.plugins[plugin_id]
        return plugin_instance.config.config_data
    
    async def update_plugin_config(self, plugin_id: str, config_data: Dict[str, Any]) -> bool:
        """Update plugin configuration"""
        if plugin_id not in self.plugins:
            return False
        
        plugin_instance = self.plugins[plugin_id]
        
        try:
            # Validate config against schema
            if plugin_instance.metadata.config_schema:
                self._validate_config(config_data, plugin_instance.metadata.config_schema)
            
            # Update config
            plugin_instance.config.config_data.update(config_data)
            self._save_plugin_config(plugin_instance.config)
            
            # Notify plugin of config change
            if hasattr(plugin_instance.instance, 'on_config_change'):
                await plugin_instance.instance.on_config_change(config_data)
            
            logging.info(f"Plugin configuration updated: {plugin_id}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to update plugin config {plugin_id}: {e}")
            return False
    
    def _validate_config(self, config: Dict[str, Any], schema: Dict[str, Any]):
        """Validate configuration against schema"""
        # Simple validation (can be enhanced with jsonschema)
        for field, field_schema in schema.items():
            if field_schema.get("required", False) and field not in config:
                raise ValueError(f"Required field missing: {field}")
            
            if field in config:
                field_type = field_schema.get("type")
                if field_type and not isinstance(config[field], eval(field_type)):
                    raise ValueError(f"Invalid type for field {field}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get plugin system statistics"""
        self.stats["total_plugins"] = len(self.plugins)
        self.stats["active_plugins"] = sum(1 for p in self.plugins.values() if p.status == PluginStatus.ACTIVE)
        self.stats["failed_plugins"] = sum(1 for p in self.plugins.values() if p.status == PluginStatus.ERROR)
        
        return self.stats.copy()
    
    async def execute_hook(self, hook_name: str, *args, **kwargs) -> List[Any]:
        """Execute plugin hook"""
        if not self.hook_system:
            return []
        
        return await self.hook_system.execute_hook(hook_name, *args, **kwargs)
    
    def get_plugin_api(self):
        """Get plugin API instance"""
        return self.plugin_api
    
    async def shutdown(self):
        """Shutdown plugin system"""
        logging.info("Shutting down plugin system...")
        
        # Stop all plugins
        for plugin_id, plugin_instance in self.plugins.items():
            if plugin_instance.status == PluginStatus.ACTIVE:
                try:
                    if hasattr(plugin_instance.instance, 'stop'):
                        await plugin_instance.instance.stop()
                except Exception as e:
                    logging.error(f"Error stopping plugin {plugin_id}: {e}")
        
        # Cleanup
        if self.sandbox:
            await self.sandbox.cleanup()
        
        logging.info("Plugin system shutdown complete")
