"""
VANTABLACK Plugin Loader - Dynamic Plugin Loading
==============================================

Dynamic plugin loading system:
- Runtime plugin discovery
- Hot reloading
- Dependency resolution
- Plugin validation
- Security checks
"""

import os
import sys
import importlib
import importlib.util
import inspect
import logging
import threading
import asyncio
from typing import Dict, List, Any, Optional, Type, Callable
from datetime import datetime
from pathlib import Path
import json
import yaml
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class PluginLoadError(Exception):
    """Plugin loading error"""
    pass


class PluginValidationError(Exception):
    """Plugin validation error"""
    pass


class PluginWatcher(FileSystemEventHandler):
    """File system watcher for plugin hot reloading"""
    
    def __init__(self, plugin_manager):
        self.plugin_manager = plugin_manager
        self.logger = logging.getLogger(__name__)
    
    def on_modified(self, event):
        """Handle file modification"""
        if event.is_directory:
            return
        
        file_path = Path(event.src_path)
        
        # Check if it's a plugin file
        if file_path.suffix in ['.py', '.yaml', '.json']:
            # Find plugin directory
            plugin_dir = file_path.parent
            while plugin_dir.name != 'plugins' and plugin_dir.parent != plugin_dir.parent:
                plugin_dir = plugin_dir.parent
            
            if plugin_dir.name == 'plugins':
                plugin_name = file_path.parent.name
                self.logger.info(f"Plugin file modified: {plugin_name}/{file_path.name}")
                
                # Schedule reload
                asyncio.create_task(self._reload_plugin(plugin_name))
    
    async def _reload_plugin(self, plugin_name: str):
        """Reload plugin"""
        try:
            await self.plugin_manager.reload_plugin(plugin_name)
        except Exception as e:
            self.logger.error(f"Failed to reload plugin {plugin_name}: {e}")


class PluginLoader:
    """Dynamic plugin loader"""
    
    def __init__(self, plugin_manager):
        self.plugin_manager = plugin_manager
        self.logger = logging.getLogger(__name__)
        self.loaded_modules: Dict[str, Any] = {}
        self.module_cache: Dict[str, Any] = {}
        self.dependency_graph: Dict[str, List[str]] = {}
        self.observer = None
        self.watcher = None
        
        # Loading statistics
        self.stats = {
            "modules_loaded": 0,
            "modules_reloaded": 0,
            "load_errors": 0,
            "validation_errors": 0
        }
    
    def start_watching(self):
        """Start file system watching for hot reloading"""
        if self.observer is None:
            self.observer = Observer()
            self.watcher = PluginWatcher(self.plugin_manager)
            
            plugin_dir = Path(self.plugin_manager.plugin_dir)
            self.observer.schedule(self.watcher, str(plugin_dir), recursive=True)
            self.observer.start()
            
            self.logger.info("Plugin hot reloading enabled")
    
    def stop_watching(self):
        """Stop file system watching"""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
            self.watcher = None
            
            self.logger.info("Plugin hot reloading disabled")
    
    async def load_plugin_module(self, plugin_path: str, plugin_id: str) -> Any:
        """Load plugin module dynamically"""
        try:
            # Find main module file
            main_file = self._find_main_file(plugin_path)
            if not main_file:
                raise PluginLoadError("Main plugin file not found")
            
            # Load module
            module = self._load_module_from_file(main_file, plugin_id)
            
            # Validate module
            self._validate_plugin_module(module, plugin_id)
            
            # Cache module
            self.loaded_modules[plugin_id] = module
            self.stats["modules_loaded"] += 1
            
            self.logger.info(f"Plugin module loaded: {plugin_id}")
            return module
            
        except Exception as e:
            self.stats["load_errors"] += 1
            self.logger.error(f"Failed to load plugin module {plugin_id}: {e}")
            raise PluginLoadError(f"Failed to load plugin module: {e}")
    
    def _find_main_file(self, plugin_path: str) -> Optional[str]:
        """Find main plugin file"""
        main_files = ["main.py", "__init__.py", "plugin.py"]
        
        for main_file in main_files:
            file_path = os.path.join(plugin_path, main_file)
            if os.path.exists(file_path):
                return file_path
        
        return None
    
    def _load_module_from_file(self, file_path: str, plugin_id: str) -> Any:
        """Load Python module from file"""
        # Create module spec
        spec = importlib.util.spec_from_file_location(plugin_id, file_path)
        if spec is None:
            raise PluginLoadError(f"Could not create module spec for {file_path}")
        
        # Create module
        module = importlib.util.module_from_spec(spec)
        
        # Add to sys.modules for imports
        sys.modules[plugin_id] = module
        
        # Execute module
        try:
            spec.loader.exec_module(module)
        except Exception as e:
            # Remove from sys.modules if loading failed
            if plugin_id in sys.modules:
                del sys.modules[plugin_id]
            raise PluginLoadError(f"Failed to execute module {plugin_id}: {e}")
        
        return module
    
    def _validate_plugin_module(self, module: Any, plugin_id: str):
        """Validate plugin module"""
        # Check for plugin class
        plugin_class = None
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if hasattr(obj, '__plugin__') and obj.__plugin__:
                plugin_class = obj
                break
        
        if not plugin_class:
            raise PluginValidationError("No plugin class found")
        
        # Check plugin class interface
        required_methods = ['__init__', 'start', 'stop']
        for method in required_methods:
            if not hasattr(plugin_class, method):
                raise PluginValidationError(f"Missing required method: {method}")
        
        # Check plugin metadata
        if not hasattr(plugin_class, '__metadata__'):
            raise PluginValidationError("Plugin metadata not found")
        
        metadata = plugin_class.__metadata__
        required_metadata = ['name', 'version', 'description', 'author']
        for field in required_metadata:
            if field not in metadata:
                raise PluginValidationError(f"Missing required metadata: {field}")
        
        # Validate plugin ID
        if 'plugin_id' not in metadata:
            raise PluginValidationError("Plugin ID not found in metadata")
        
        if metadata['plugin_id'] != plugin_id:
            raise PluginValidationError("Plugin ID mismatch")
    
    async def reload_plugin(self, plugin_id: str) -> bool:
        """Reload plugin module"""
        if plugin_id not in self.loaded_modules:
            self.logger.warning(f"Plugin {plugin_id} not loaded, cannot reload")
            return False
        
        try:
            # Get plugin instance
            plugin_instance = self.plugin_manager.plugins.get(plugin_id)
            if not plugin_instance:
                self.logger.warning(f"Plugin instance {plugin_id} not found")
                return False
            
            # Stop current plugin
            if hasattr(plugin_instance.instance, 'stop'):
                await plugin_instance.instance.stop()
            
            # Remove from sys.modules
            if plugin_id in sys.modules:
                del sys.modules[plugin_id]
            
            # Remove submodules
            modules_to_remove = [name for name in sys.modules.keys() if name.startswith(plugin_id + '.')]
            for module_name in modules_to_remove:
                del sys.modules[module_name]
            
            # Reload module
            plugin_path = os.path.join(self.plugin_manager.plugin_dir, plugin_id)
            module = await self.load_plugin_module(plugin_path, plugin_id)
            
            # Find plugin class
            plugin_class = None
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if hasattr(obj, '__plugin__') and obj.__plugin__:
                    plugin_class = obj
                    break
            
            if not plugin_class:
                raise PluginLoadError("Plugin class not found after reload")
            
            # Create new instance
            new_instance = plugin_class(self.plugin_manager.plugin_api, plugin_instance.config.config_data)
            
            # Update plugin instance
            plugin_instance.module = module
            plugin_instance.instance = new_instance
            plugin_instance.status = plugin_instance.status  # Keep current status
            plugin_instance.load_time = datetime.now()
            
            # Start new instance if it was active
            if plugin_instance.status.value == 'active':
                if hasattr(new_instance, 'start'):
                    await new_instance.start()
            
            self.stats["modules_reloaded"] += 1
            self.logger.info(f"Plugin reloaded: {plugin_id}")
            return True
            
        except Exception as e:
            self.stats["load_errors"] += 1
            self.logger.error(f"Failed to reload plugin {plugin_id}: {e}")
            return False
    
    def unload_plugin_module(self, plugin_id: str) -> bool:
        """Unload plugin module"""
        if plugin_id not in self.loaded_modules:
            return False
        
        try:
            # Remove from sys.modules
            if plugin_id in sys.modules:
                del sys.modules[plugin_id]
            
            # Remove submodules
            modules_to_remove = [name for name in sys.modules.keys() if name.startswith(plugin_id + '.')]
            for module_name in modules_to_remove:
                del sys.modules[module_name]
            
            # Remove from loaded modules
            del self.loaded_modules[plugin_id]
            
            self.logger.info(f"Plugin module unloaded: {plugin_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to unload plugin module {plugin_id}: {e}")
            return False
    
    def resolve_dependencies(self, plugin_id: str, dependencies: List[str]) -> List[str]:
        """Resolve plugin dependencies"""
        resolved = []
        unresolved = dependencies.copy()
        
        while unresolved:
            dependency = unresolved.pop(0)
            
            # Check if dependency is already loaded
            if dependency in self.loaded_modules:
                resolved.append(dependency)
                continue
            
            # Check if dependency exists
            dependency_path = os.path.join(self.plugin_manager.plugin_dir, dependency)
            if not os.path.exists(dependency_path):
                raise PluginLoadError(f"Dependency not found: {dependency}")
            
            # Load dependency manifest
            manifest_path = os.path.join(dependency_path, "plugin.yaml")
            if not os.path.exists(manifest_path):
                manifest_path = os.path.join(dependency_path, "plugin.json")
            
            if os.path.exists(manifest_path):
                with open(manifest_path, 'r') as f:
                    if manifest_path.endswith('.yaml'):
                        manifest = yaml.safe_load(f)
                    else:
                        manifest = json.load(f)
                
                # Resolve dependency's dependencies
                sub_dependencies = manifest.get("dependencies", [])
                for sub_dep in sub_dependencies:
                    if sub_dep not in resolved and sub_dep not in unresolved:
                        unresolved.insert(0, sub_dep)
            
            resolved.append(dependency)
        
        return resolved
    
    def validate_plugin_security(self, plugin_path: str) -> bool:
        """Validate plugin security"""
        try:
            # Check for dangerous imports
            dangerous_imports = [
                'os.system', 'subprocess', 'eval', 'exec', 'compile',
                '__import__', 'open', 'file', 'input', 'raw_input'
            ]
            
            # Scan Python files
            for root, dirs, files in os.walk(plugin_path):
                for file in files:
                    if file.endswith('.py'):
                        file_path = os.path.join(root, file)
                        with open(file_path, 'r') as f:
                            content = f.read()
                            
                            # Check for dangerous imports
                            for dangerous in dangerous_imports:
                                if dangerous in content:
                                    self.logger.warning(f"Dangerous import found in {file_path}: {dangerous}")
                                    return False
            
            # Check file permissions
            for root, dirs, files in os.walk(plugin_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.access(file_path, os.X_OK):
                        self.logger.warning(f"Executable file found: {file_path}")
                        return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Security validation failed: {e}")
            return False
    
    def get_module_info(self, plugin_id: str) -> Optional[Dict[str, Any]]:
        """Get module information"""
        if plugin_id not in self.loaded_modules:
            return None
        
        module = self.loaded_modules[plugin_id]
        
        return {
            "plugin_id": plugin_id,
            "module_name": module.__name__,
            "module_file": getattr(module, '__file__', None),
            "module_version": getattr(module, '__version__', 'unknown'),
            "classes": [name for name, obj in inspect.getmembers(module, inspect.isclass)],
            "functions": [name for name, obj in inspect.getmembers(module, inspect.isfunction)],
            "variables": [name for name, obj in inspect.getmembers(module) if not name.startswith('_')],
            "docstring": module.__doc__,
            "load_time": datetime.now().isoformat()
        }
    
    def get_dependency_graph(self) -> Dict[str, List[str]]:
        """Get plugin dependency graph"""
        return self.dependency_graph.copy()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get loader statistics"""
        return self.stats.copy()
    
    def cleanup(self):
        """Cleanup loader resources"""
        # Stop watching
        self.stop_watching()
        
        # Unload all modules
        for plugin_id in list(self.loaded_modules.keys()):
            self.unload_plugin_module(plugin_id)
        
        # Clear caches
        self.module_cache.clear()
        self.dependency_graph.clear()
        
        self.logger.info("Plugin loader cleanup complete")


class PluginValidator:
    """Plugin validation system"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def validate_plugin_structure(self, plugin_path: str) -> bool:
        """Validate plugin directory structure"""
        required_files = ["plugin.yaml", "main.py"]
        optional_files = ["README.md", "LICENSE", "requirements.txt", "config.yaml"]
        
        # Check required files
        for file in required_files:
            file_path = os.path.join(plugin_path, file)
            if not os.path.exists(file_path):
                self.logger.error(f"Required file missing: {file}")
                return False
        
        # Check for Python files
        python_files = []
        for root, dirs, files in os.walk(plugin_path):
            for file in files:
                if file.endswith('.py'):
                    python_files.append(os.path.join(root, file))
        
        if not python_files:
            self.logger.error("No Python files found")
            return False
        
        return True
    
    def validate_plugin_manifest(self, manifest_path: str) -> bool:
        """Validate plugin manifest"""
        try:
            with open(manifest_path, 'r') as f:
                if manifest_path.endswith('.yaml'):
                    manifest = yaml.safe_load(f)
                else:
                    manifest = json.load(f)
            
            # Required fields
            required_fields = [
                "plugin_id", "name", "version", "description", 
                "author", "type", "main_file"
            ]
            
            for field in required_fields:
                if field not in manifest:
                    self.logger.error(f"Required manifest field missing: {field}")
                    return False
            
            # Validate plugin ID
            plugin_id = manifest["plugin_id"]
            if not plugin_id.replace("-", "").replace("_", "").isalnum():
                self.logger.error("Invalid plugin ID format")
                return False
            
            # Validate version
            version = manifest["version"]
            if not isinstance(version, str) or not version.count(".") >= 1:
                self.logger.error("Invalid version format")
                return False
            
            # Validate type
            valid_types = ["analysis", "mutation", "template", "integration", 
                          "authentication", "notification", "monitoring", "utility"]
            if manifest["type"] not in valid_types:
                self.logger.error(f"Invalid plugin type: {manifest['type']}")
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to validate manifest: {e}")
            return False
    
    def validate_plugin_code(self, plugin_path: str) -> bool:
        """Validate plugin code quality"""
        try:
            # Check syntax
            for root, dirs, files in os.walk(plugin_path):
                for file in files:
                    if file.endswith('.py'):
                        file_path = os.path.join(root, file)
                        
                        try:
                            with open(file_path, 'r') as f:
                                code = f.read()
                            
                            # Compile to check syntax
                            compile(code, file_path, 'exec')
                            
                        except SyntaxError as e:
                            self.logger.error(f"Syntax error in {file_path}: {e}")
                            return False
                        except Exception as e:
                            self.logger.error(f"Error checking {file_path}: {e}")
                            return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Code validation failed: {e}")
            return False
    
    def validate_plugin_dependencies(self, plugin_path: str) -> bool:
        """Validate plugin dependencies"""
        try:
            # Check requirements.txt
            requirements_path = os.path.join(plugin_path, "requirements.txt")
            if os.path.exists(requirements_path):
                with open(requirements_path, 'r') as f:
                    requirements = f.read().strip().split('\n')
                
                for requirement in requirements:
                    requirement = requirement.strip()
                    if requirement and not requirement.startswith('#'):
                        try:
                            importlib.import_module(requirement.split('==')[0].split('>=')[0].split('<=')[0])
                        except ImportError:
                            self.logger.warning(f"Dependency not available: {requirement}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Dependency validation failed: {e}")
            return False
