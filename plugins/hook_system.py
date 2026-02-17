"""
VANTABLACK Hook System - Event-Driven Architecture
================================================

Event hook system for plugin integration:
- Hook registration and execution
- Event filtering and routing
- Async hook execution
- Hook priority system
- Error handling and recovery
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional, Callable, Union
from datetime import datetime
from dataclasses import dataclass
from enum import Enum
import inspect
import traceback


class HookPriority(Enum):
    """Hook execution priority"""
    LOWEST = 0
    LOW = 25
    NORMAL = 50
    HIGH = 75
    HIGHEST = 100


@dataclass
class HookRegistration:
    """Hook registration information"""
    hook_name: str
    callback: Callable
    plugin_instance: Any
    priority: HookPriority
    enabled: bool
    registration_time: datetime
    execution_count: int = 0
    last_execution: Optional[datetime] = None
    average_execution_time: float = 0.0
    error_count: int = 0
    last_error: Optional[str] = None


@dataclass
class HookResult:
    """Hook execution result"""
    hook_name: str
    plugin_id: str
    success: bool
    result: Any
    execution_time: float
    error_message: Optional[str] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


class HookSystem:
    """Event hook system for plugins"""
    
    def __init__(self):
        self.hooks: Dict[str, List[HookRegistration]] = {}
        self.global_hooks: List[HookRegistration] = []
        self.logger = logging.getLogger(__name__)
        
        # Execution statistics
        self.stats = {
            "total_hooks": 0,
            "active_hooks": 0,
            "total_executions": 0,
            "successful_executions": 0,
            "failed_executions": 0,
            "average_execution_time": 0.0
        }
        
        # Hook execution history
        self.execution_history: List[HookResult] = []
        self.max_history_size = 1000
        
        # Built-in hooks
        self._register_builtin_hooks()
    
    def _register_builtin_hooks(self):
        """Register built-in hook definitions"""
        self.builtin_hooks = {
            # Plugin lifecycle hooks
            "plugin.before_load": "Called before a plugin is loaded",
            "plugin.after_load": "Called after a plugin is loaded",
            "plugin.before_unload": "Called before a plugin is unloaded",
            "plugin.after_unload": "Called after a plugin is unloaded",
            "plugin.before_enable": "Called before a plugin is enabled",
            "plugin.after_enable": "Called after a plugin is enabled",
            "plugin.before_disable": "Called before a plugin is disabled",
            "plugin.after_disable": "Called after a plugin is disabled",
            
            # Template hooks
            "template.before_generate": "Called before template generation",
            "template.after_generate": "Called after template generation",
            "template.before_optimize": "Called before template optimization",
            "template.after_optimize": "Called after template optimization",
            
            # Campaign hooks
            "campaign.before_create": "Called before campaign creation",
            "campaign.after_create": "Called after campaign creation",
            "campaign.before_start": "Called before campaign start",
            "campaign.after_start": "Called after campaign start",
            "campaign.before_stop": "Called before campaign stop",
            "campaign.after_stop": "Called after campaign stop",
            
            # Analysis hooks
            "analysis.before_run": "Called before analysis execution",
            "analysis.after_run": "Called after analysis execution",
            "analysis.on_result": "Called when analysis result is available",
            
            # Mutation hooks
            "mutation.before_generate": "Called before mutation generation",
            "mutation.after_generate": "Called after mutation generation",
            "mutation.before_apply": "Called before mutation application",
            "mutation.after_apply": "Called after mutation application",
            
            # API hooks
            "api.before_request": "Called before API request processing",
            "api.after_request": "Called after API request processing",
            "api.on_error": "Called when API error occurs",
            
            # Authentication hooks
            "auth.before_login": "Called before user login",
            "auth.after_login": "Called after user login",
            "auth.before_logout": "Called before user logout",
            "auth.after_logout": "Called after user logout",
            
            # System hooks
            "system.startup": "Called during system startup",
            "system.shutdown": "Called during system shutdown",
            "system.error": "Called when system error occurs",
            
            # Data hooks
            "data.before_save": "Called before data is saved",
            "data.after_save": "Called after data is saved",
            "data.before_load": "Called before data is loaded",
            "data.after_load": "Called after data is loaded",
            
            # Notification hooks
            "notification.send": "Called to send notification",
            "notification.received": "Called when notification is received",
            
            # Monitoring hooks
            "monitor.metric": "Called when metric is collected",
            "monitor.alert": "Called when alert is triggered",
            "monitor.health_check": "Called during health check"
        }
    
    def register_hook(self, hook_name: str, plugin_instance: Any, 
                     callback: Callable = None, priority: HookPriority = HookPriority.NORMAL) -> bool:
        """Register a hook callback"""
        try:
            # If callback not provided, look for method with hook name
            if callback is None:
                if hasattr(plugin_instance, hook_name):
                    callback = getattr(plugin_instance, hook_name)
                else:
                    self.logger.error(f"Hook method not found: {hook_name}")
                    return False
            
            # Validate callback
            if not callable(callback):
                self.logger.error(f"Hook callback is not callable: {hook_name}")
                return False
            
            # Create registration
            registration = HookRegistration(
                hook_name=hook_name,
                callback=callback,
                plugin_instance=plugin_instance,
                priority=priority,
                enabled=True,
                registration_time=datetime.now()
            )
            
            # Add to hooks registry
            if hook_name not in self.hooks:
                self.hooks[hook_name] = []
            
            self.hooks[hook_name].append(registration)
            
            # Sort by priority (highest first)
            self.hooks[hook_name].sort(key=lambda x: x.priority.value, reverse=True)
            
            # Update statistics
            self.stats["total_hooks"] += 1
            self.stats["active_hooks"] += 1
            
            self.logger.info(f"Hook registered: {hook_name} for plugin {getattr(plugin_instance, '__class__', {}).get('__name__', 'Unknown')}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to register hook {hook_name}: {e}")
            return False
    
    def unregister_hook(self, hook_name: str, plugin_instance: Any, callback: Callable = None) -> bool:
        """Unregister a hook callback"""
        try:
            if hook_name not in self.hooks:
                return False
            
            # Find registration to remove
            to_remove = None
            for registration in self.hooks[hook_name]:
                if registration.plugin_instance == plugin_instance:
                    if callback is None or registration.callback == callback:
                        to_remove = registration
                        break
            
            if to_remove:
                self.hooks[hook_name].remove(to_remove)
                
                # Update statistics
                self.stats["total_hooks"] -= 1
                if to_remove.enabled:
                    self.stats["active_hooks"] -= 1
                
                self.logger.info(f"Hook unregistered: {hook_name}")
                return True
            else:
                self.logger.warning(f"Hook registration not found: {hook_name}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to unregister hook {hook_name}: {e}")
            return False
    
    def enable_hook(self, hook_name: str, plugin_instance: Any) -> bool:
        """Enable a hook"""
        if hook_name not in self.hooks:
            return False
        
        for registration in self.hooks[hook_name]:
            if registration.plugin_instance == plugin_instance:
                if not registration.enabled:
                    registration.enabled = True
                    self.stats["active_hooks"] += 1
                    self.logger.info(f"Hook enabled: {hook_name}")
                return True
        
        return False
    
    def disable_hook(self, hook_name: str, plugin_instance: Any) -> bool:
        """Disable a hook"""
        if hook_name not in self.hooks:
            return False
        
        for registration in self.hooks[hook_name]:
            if registration.plugin_instance == plugin_instance:
                if registration.enabled:
                    registration.enabled = False
                    self.stats["active_hooks"] -= 1
                    self.logger.info(f"Hook disabled: {hook_name}")
                return True
        
        return False
    
    async def execute_hook(self, hook_name: str, *args, **kwargs) -> List[Any]:
        """Execute all registered callbacks for a hook"""
        results = []
        
        if hook_name not in self.hooks:
            self.logger.debug(f"No hooks registered for: {hook_name}")
            return results
        
        # Execute hooks in priority order
        for registration in self.hooks[hook_name]:
            if not registration.enabled:
                continue
            
            try:
                start_time = datetime.now()
                
                # Execute callback
                if inspect.iscoroutinefunction(registration.callback):
                    result = await registration.callback(*args, **kwargs)
                else:
                    result = registration.callback(*args, **kwargs)
                
                # Calculate execution time
                execution_time = (datetime.now() - start_time).total_seconds()
                
                # Update registration statistics
                registration.execution_count += 1
                registration.last_execution = datetime.now()
                registration.average_execution_time = (
                    (registration.average_execution_time * (registration.execution_count - 1) + execution_time) /
                    registration.execution_count
                )
                
                # Create result
                hook_result = HookResult(
                    hook_name=hook_name,
                    plugin_id=getattr(registration.plugin_instance, '__class__', {}).get('__name__', 'Unknown'),
                    success=True,
                    result=result,
                    execution_time=execution_time
                )
                
                results.append(hook_result)
                
                # Add to history
                self._add_to_history(hook_result)
                
                # Update statistics
                self.stats["total_executions"] += 1
                self.stats["successful_executions"] += 1
                
            except Exception as e:
                execution_time = (datetime.now() - start_time).total_seconds()
                
                # Update registration error statistics
                registration.error_count += 1
                registration.last_error = str(e)
                
                # Create error result
                hook_result = HookResult(
                    hook_name=hook_name,
                    plugin_id=getattr(registration.plugin_instance, '__class__', {}).get('__name__', 'Unknown'),
                    success=False,
                    result=None,
                    execution_time=execution_time,
                    error_message=str(e)
                )
                
                results.append(hook_result)
                
                # Add to history
                self._add_to_history(hook_result)
                
                # Update statistics
                self.stats["total_executions"] += 1
                self.stats["failed_executions"] += 1
                
                self.logger.error(f"Hook execution failed: {hook_name} - {e}")
                self.logger.debug(f"Traceback: {traceback.format_exc()}")
        
        # Update average execution time
        if self.stats["total_executions"] > 0:
            total_time = sum(r.execution_time for r in self.execution_history[-100:])
            self.stats["average_execution_time"] = total_time / min(len(self.execution_history[-100:]), 100)
        
        return results
    
    async def execute_hook_filtered(self, hook_name: str, filter_func: Callable, *args, **kwargs) -> List[Any]:
        """Execute hooks with filtering"""
        results = []
        
        if hook_name not in self.hooks:
            return results
        
        for registration in self.hooks[hook_name]:
            if not registration.enabled:
                continue
            
            # Apply filter
            if not filter_func(registration.plugin_instance):
                continue
            
            try:
                start_time = datetime.now()
                
                # Execute callback
                if inspect.iscoroutinefunction(registration.callback):
                    result = await registration.callback(*args, **kwargs)
                else:
                    result = registration.callback(*args, **kwargs)
                
                execution_time = (datetime.now() - start_time).total_seconds()
                
                hook_result = HookResult(
                    hook_name=hook_name,
                    plugin_id=getattr(registration.plugin_instance, '__class__', {}).get('__name__', 'Unknown'),
                    success=True,
                    result=result,
                    execution_time=execution_time
                )
                
                results.append(hook_result)
                self._add_to_history(hook_result)
                
            except Exception as e:
                execution_time = (datetime.now() - start_time).total_seconds()
                
                hook_result = HookResult(
                    hook_name=hook_name,
                    plugin_id=getattr(registration.plugin_instance, '__class__', {}).get('__name__', 'Unknown'),
                    success=False,
                    result=None,
                    execution_time=execution_time,
                    error_message=str(e)
                )
                
                results.append(hook_result)
                self._add_to_history(hook_result)
                
                self.logger.error(f"Filtered hook execution failed: {hook_name} - {e}")
        
        return results
    
    def _add_to_history(self, result: HookResult):
        """Add result to execution history"""
        self.execution_history.append(result)
        
        # Limit history size
        if len(self.execution_history) > self.max_history_size:
            self.execution_history = self.execution_history[-self.max_history_size:]
    
    def get_hook_registrations(self, hook_name: str = None) -> List[Dict[str, Any]]:
        """Get hook registration information"""
        registrations = []
        
        if hook_name:
            if hook_name in self.hooks:
                hooks_list = [self.hooks[hook_name]]
            else:
                return registrations
        else:
            hooks_list = self.hooks.values()
        
        for hooks in hooks_list:
            for registration in hooks:
                registrations.append({
                    "hook_name": registration.hook_name,
                    "plugin_id": getattr(registration.plugin_instance, '__class__', {}).get('__name__', 'Unknown'),
                    "priority": registration.priority.value,
                    "enabled": registration.enabled,
                    "registration_time": registration.registration_time.isoformat(),
                    "execution_count": registration.execution_count,
                    "last_execution": registration.last_execution.isoformat() if registration.last_execution else None,
                    "average_execution_time": registration.average_execution_time,
                    "error_count": registration.error_count,
                    "last_error": registration.last_error
                })
        
        return registrations
    
    def get_execution_history(self, hook_name: str = None, plugin_id: str = None, 
                            limit: int = 100) -> List[Dict[str, Any]]:
        """Get hook execution history"""
        history = self.execution_history
        
        # Apply filters
        if hook_name:
            history = [h for h in history if h.hook_name == hook_name]
        
        if plugin_id:
            history = [h for h in history if h.plugin_id == plugin_id]
        
        # Sort by timestamp (newest first)
        history.sort(key=lambda x: x.timestamp, reverse=True)
        
        # Limit results
        history = history[:limit]
        
        return [
            {
                "hook_name": h.hook_name,
                "plugin_id": h.plugin_id,
                "success": h.success,
                "result": str(h.result) if h.result is not None else None,
                "execution_time": h.execution_time,
                "error_message": h.error_message,
                "timestamp": h.timestamp.isoformat()
            }
            for h in history
        ]
    
    def get_hook_stats(self) -> Dict[str, Any]:
        """Get hook system statistics"""
        # Update statistics
        self.stats["total_hooks"] = sum(len(hooks) for hooks in self.hooks.values())
        self.stats["active_hooks"] = sum(len([h for h in hooks if h.enabled]) for hooks in self.hooks.values())
        
        return self.stats.copy()
    
    def get_available_hooks(self) -> Dict[str, str]:
        """Get list of available built-in hooks"""
        return self.builtin_hooks.copy()
    
    def clear_history(self):
        """Clear execution history"""
        self.execution_history.clear()
        self.logger.info("Hook execution history cleared")
    
    def reset_stats(self):
        """Reset hook statistics"""
        self.stats = {
            "total_hooks": 0,
            "active_hooks": 0,
            "total_executions": 0,
            "successful_executions": 0,
            "failed_executions": 0,
            "average_execution_time": 0.0
        }
        
        # Reset registration stats
        for hooks in self.hooks.values():
            for registration in hooks:
                registration.execution_count = 0
                registration.last_execution = None
                registration.average_execution_time = 0.0
                registration.error_count = 0
                registration.last_error = None
        
        self.logger.info("Hook statistics reset")
    
    def cleanup(self):
        """Cleanup hook system"""
        # Clear all hooks
        self.hooks.clear()
        self.global_hooks.clear()
        
        # Clear history
        self.clear_history()
        
        # Reset stats
        self.reset_stats()
        
        self.logger.info("Hook system cleanup complete")


# Decorator for easy hook registration
def hook(hook_name: str, priority: HookPriority = HookPriority.NORMAL):
    """Decorator for hook registration"""
    def decorator(func):
        func.__hook_name__ = hook_name
        func.__hook_priority__ = priority
        return func
    return decorator


# Hook context manager for batch operations
class HookContext:
    """Context manager for hook execution"""
    
    def __init__(self, hook_system: HookSystem, hook_name: str):
        self.hook_system = hook_system
        self.hook_name = hook_name
        self.results = []
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            # Handle exception
            await self.hook_system.execute_hook("system.error", exc_type, exc_val, exc_tb)
        return False
    
    async def execute(self, *args, **kwargs):
        """Execute hook within context"""
        self.results = await self.hook_system.execute_hook(self.hook_name, *args, **kwargs)
        return self.results


# Hook filter utilities
class HookFilters:
    """Common hook filters"""
    
    @staticmethod
    def by_plugin_type(plugin_type: str) -> Callable:
        """Filter by plugin type"""
        def filter_func(plugin_instance):
            return getattr(plugin_instance, '__plugin_type__', None) == plugin_type
        return filter_func
    
    @staticmethod
    def by_plugin_id(plugin_id: str) -> Callable:
        """Filter by plugin ID"""
        def filter_func(plugin_instance):
            return getattr(plugin_instance, '__plugin_id__', None) == plugin_id
        return filter_func
    
    @staticmethod
    def by_priority(min_priority: HookPriority) -> Callable:
        """Filter by minimum priority"""
        def filter_func(plugin_instance):
            # This would need access to registration, simplified here
            return True
        return filter_func
    
    @staticmethod
    def by_attribute(attribute_name: str, attribute_value: Any) -> Callable:
        """Filter by plugin attribute"""
        def filter_func(plugin_instance):
            return getattr(plugin_instance, attribute_name, None) == attribute_value
        return filter_func
