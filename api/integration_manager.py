"""
VANTABLACK Integration Manager - External Tool Integration
======================================================

Integration system for external Red Team tools:
- Evilginx integration
- Gophish integration
- Third-party tool APIs
- Webhook management
- Data synchronization
- Plugin system
"""

import asyncio
import json
import logging
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum
import aiohttp
import hashlib
import hmac
import base64


class IntegrationType(Enum):
    """Integration types"""
    EVILGINX = "evilginx"
    GOPHISH = "gophish"
    METASPLOIT = "metasploit"
    BURP_SUITE = "burp_suite"
    CUSTOM = "custom"
    WEBHOOK = "webhook"


class IntegrationStatus(Enum):
    """Integration status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    PENDING = "pending"


@dataclass
class IntegrationConfig:
    """Integration configuration"""
    integration_id: str
    name: str
    type: IntegrationType
    endpoint_url: str
    api_key: Optional[str]
    secret_key: Optional[str]
    config_params: Dict[str, Any]
    is_active: bool
    created_at: datetime
    last_sync: Optional[datetime]
    status: IntegrationStatus
    error_message: Optional[str]
    webhook_url: Optional[str]
    sync_interval: int = 300  # seconds


@dataclass
class IntegrationResult:
    """Integration operation result"""
    integration_id: str
    operation: str
    success: bool
    data: Optional[Dict[str, Any]]
    error_message: Optional[str]
    timestamp: datetime
    execution_time: float


class EvilginxIntegration:
    """Evilginx integration handler"""
    
    def __init__(self, config: IntegrationConfig):
        self.config = config
        self.base_url = config.endpoint_url
        self.api_key = config.api_key
        self.session = None
    
    async def initialize(self):
        """Initialize Evilginx session"""
        self.session = aiohttp.ClientSession(
            base_url=self.base_url,
            headers={"X-API-Key": self.api_key} if self.api_key else {}
        )
    
    async def close(self):
        """Close Evilginx session"""
        if self.session:
            await self.session.close()
    
    async def get_phishlets(self) -> IntegrationResult:
        """Get available phishlets"""
        try:
            async with self.session.get("/api/phishlets") as response:
                if response.status == 200:
                    data = await response.json()
                    return IntegrationResult(
                        integration_id=self.config.integration_id,
                        operation="get_phishlets",
                        success=True,
                        data=data,
                        error_message=None,
                        timestamp=datetime.now(),
                        execution_time=0.0
                    )
                else:
                    return IntegrationResult(
                        integration_id=self.config.integration_id,
                        operation="get_phishlets",
                        success=False,
                        data=None,
                        error_message=f"HTTP {response.status}",
                        timestamp=datetime.now(),
                        execution_time=0.0
                    )
        except Exception as e:
            return IntegrationResult(
                integration_id=self.config.integration_id,
                operation="get_phishlets",
                success=False,
                data=None,
                error_message=str(e),
                timestamp=datetime.now(),
                execution_time=0.0
            )
    
    async def create_phishlet(self, phishlet_data: Dict[str, Any]) -> IntegrationResult:
        """Create a new phishlet"""
        try:
            async with self.session.post("/api/phishlets", json=phishlet_data) as response:
                if response.status == 201:
                    data = await response.json()
                    return IntegrationResult(
                        integration_id=self.config.integration_id,
                        operation="create_phishlet",
                        success=True,
                        data=data,
                        error_message=None,
                        timestamp=datetime.now(),
                        execution_time=0.0
                    )
                else:
                    return IntegrationResult(
                        integration_id=self.config.integration_id,
                        operation="create_phishlet",
                        success=False,
                        data=None,
                        error_message=f"HTTP {response.status}",
                        timestamp=datetime.now(),
                        execution_time=0.0
                    )
        except Exception as e:
            return IntegrationResult(
                integration_id=self.config.integration_id,
                operation="create_phishlet",
                success=False,
                data=None,
                error_message=str(e),
                timestamp=datetime.now(),
                execution_time=0.0
            )
    
    async def start_campaign(self, campaign_data: Dict[str, Any]) -> IntegrationResult:
        """Start a phishing campaign"""
        try:
            async with self.session.post("/api/campaigns", json=campaign_data) as response:
                if response.status == 201:
                    data = await response.json()
                    return IntegrationResult(
                        integration_id=self.config.integration_id,
                        operation="start_campaign",
                        success=True,
                        data=data,
                        error_message=None,
                        timestamp=datetime.now(),
                        execution_time=0.0
                    )
                else:
                    return IntegrationResult(
                        integration_id=self.config.integration_id,
                        operation="start_campaign",
                        success=False,
                        data=None,
                        error_message=f"HTTP {response.status}",
                        timestamp=datetime.now(),
                        execution_time=0.0
                    )
        except Exception as e:
            return IntegrationResult(
                integration_id=self.config.integration_id,
                operation="start_campaign",
                success=False,
                data=None,
                error_message=str(e),
                timestamp=datetime.now(),
                execution_time=0.0
            )
    
    async def get_campaign_stats(self, campaign_id: str) -> IntegrationResult:
        """Get campaign statistics"""
        try:
            async with self.session.get(f"/api/campaigns/{campaign_id}/stats") as response:
                if response.status == 200:
                    data = await response.json()
                    return IntegrationResult(
                        integration_id=self.config.integration_id,
                        operation="get_campaign_stats",
                        success=True,
                        data=data,
                        error_message=None,
                        timestamp=datetime.now(),
                        execution_time=0.0
                    )
                else:
                    return IntegrationResult(
                        integration_id=self.config.integration_id,
                        operation="get_campaign_stats",
                        success=False,
                        data=None,
                        error_message=f"HTTP {response.status}",
                        timestamp=datetime.now(),
                        execution_time=0.0
                    )
        except Exception as e:
            return IntegrationResult(
                integration_id=self.config.integration_id,
                operation="get_campaign_stats",
                success=False,
                data=None,
                error_message=str(e),
                timestamp=datetime.now(),
                execution_time=0.0
            )


class GophishIntegration:
    """Gophish integration handler"""
    
    def __init__(self, config: IntegrationConfig):
        self.config = config
        self.base_url = config.endpoint_url
        self.api_key = config.api_key
        self.session = None
    
    async def initialize(self):
        """Initialize Gophish session"""
        self.session = aiohttp.ClientSession(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        )
    
    async def close(self):
        """Close Gophish session"""
        if self.session:
            await self.session.close()
    
    async def get_campaigns(self) -> IntegrationResult:
        """Get Gophish campaigns"""
        try:
            async with self.session.get("/api/campaigns") as response:
                if response.status == 200:
                    data = await response.json()
                    return IntegrationResult(
                        integration_id=self.config.integration_id,
                        operation="get_campaigns",
                        success=True,
                        data=data,
                        error_message=None,
                        timestamp=datetime.now(),
                        execution_time=0.0
                    )
                else:
                    return IntegrationResult(
                        integration_id=self.config.integration_id,
                        operation="get_campaigns",
                        success=False,
                        data=None,
                        error_message=f"HTTP {response.status}",
                        timestamp=datetime.now(),
                        execution_time=0.0
                    )
        except Exception as e:
            return IntegrationResult(
                integration_id=self.config.integration_id,
                operation="get_campaigns",
                success=False,
                data=None,
                error_message=str(e),
                timestamp=datetime.now(),
                execution_time=0.0
            )
    
    async import_templates(self, templates: List[Dict[str, Any]]) -> IntegrationResult:
        """Import templates to Gophish"""
        results = []
        
        for template in templates:
            try:
                async with self.session.post("/api/templates", json=template) as response:
                    if response.status == 201:
                        template_data = await response.json()
                        results.append({"success": True, "data": template_data})
                    else:
                        results.append({"success": False, "error": f"HTTP {response.status}"})
            except Exception as e:
                results.append({"success": False, "error": str(e)})
        
        return IntegrationResult(
            integration_id=self.config.integration_id,
            operation="import_templates",
            success=True,
            data={"results": results},
            error_message=None,
            timestamp=datetime.now(),
            execution_time=0.0
        )


class WebhookIntegration:
    """Webhook integration handler"""
    
    def __init__(self, config: IntegrationConfig):
        self.config = config
        self.webhook_url = config.webhook_url
        self.secret_key = config.secret_key
    
    def _generate_signature(self, payload: str) -> str:
        """Generate webhook signature"""
        if self.secret_key:
            signature = hmac.new(
                self.secret_key.encode(),
                payload.encode(),
                hashlib.sha256
            ).digest()
            return base64.b64encode(signature).decode()
        return ""
    
    async def send_webhook(self, event_type: str, data: Dict[str, Any]) -> IntegrationResult:
        """Send webhook notification"""
        try:
            payload = {
                "event_type": event_type,
                "timestamp": datetime.now().isoformat(),
                "data": data,
                "integration_id": self.config.integration_id
            }
            
            payload_str = json.dumps(payload)
            signature = self._generate_signature(payload_str)
            
            headers = {
                "Content-Type": "application/json",
                "X-Vantablack-Signature": signature
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, data=payload_str, headers=headers) as response:
                    if response.status == 200:
                        return IntegrationResult(
                            integration_id=self.config.integration_id,
                            operation="send_webhook",
                            success=True,
                            data={"status": "delivered"},
                            error_message=None,
                            timestamp=datetime.now(),
                            execution_time=0.0
                        )
                    else:
                        return IntegrationResult(
                            integration_id=self.config.integration_id,
                            operation="send_webhook",
                            success=False,
                            data=None,
                            error_message=f"HTTP {response.status}",
                            timestamp=datetime.now(),
                            execution_time=0.0
                        )
        except Exception as e:
            return IntegrationResult(
                integration_id=self.config.integration_id,
                operation="send_webhook",
                success=False,
                data=None,
                error_message=str(e),
                timestamp=datetime.now(),
                execution_time=0.0
            )


class IntegrationManager:
    """Main integration manager"""
    
    def __init__(self):
        self.integrations: Dict[str, IntegrationConfig] = {}
        self.integration_handlers: Dict[str, Any] = {}
        self.webhook_handlers: Dict[str, List[Callable]] = {}
        self.sync_tasks: Dict[str, asyncio.Task] = {}
        self.results_history: List[IntegrationResult] = []
        
        # Statistics
        self.stats = {
            "total_integrations": 0,
            "active_integrations": 0,
            "total_operations": 0,
            "successful_operations": 0,
            "failed_operations": 0
        }
    
    async def add_integration(self, name: str, integration_type: IntegrationType,
                            endpoint_url: str, api_key: str = None,
                            secret_key: str = None, config_params: Dict[str, Any] = None,
                            webhook_url: str = None, sync_interval: int = 300) -> str:
        """Add a new integration"""
        integration_id = f"int_{int(datetime.now().timestamp())}"
        
        config = IntegrationConfig(
            integration_id=integration_id,
            name=name,
            type=integration_type,
            endpoint_url=endpoint_url,
            api_key=api_key,
            secret_key=secret_key,
            config_params=config_params or {},
            is_active=True,
            created_at=datetime.now(),
            last_sync=None,
            status=IntegrationStatus.PENDING,
            error_message=None,
            webhook_url=webhook_url,
            sync_interval=sync_interval
        )
        
        self.integrations[integration_id] = config
        
        # Initialize integration handler
        await self._initialize_integration(integration_id)
        
        # Start sync task if configured
        if sync_interval > 0:
            await self._start_sync_task(integration_id)
        
        logging.info(f"Integration added: {name} ({integration_id})")
        return integration_id
    
    async def _initialize_integration(self, integration_id: str):
        """Initialize integration handler"""
        config = self.integrations[integration_id]
        
        try:
            if config.type == IntegrationType.EVILGINX:
                handler = EvilginxIntegration(config)
                await handler.initialize()
                self.integration_handlers[integration_id] = handler
                config.status = IntegrationStatus.ACTIVE
            
            elif config.type == IntegrationType.GOPHISH:
                handler = GophishIntegration(config)
                await handler.initialize()
                self.integration_handlers[integration_id] = handler
                config.status = IntegrationStatus.ACTIVE
            
            elif config.type == IntegrationType.WEBHOOK:
                handler = WebhookIntegration(config)
                self.integration_handlers[integration_id] = handler
                config.status = IntegrationStatus.ACTIVE
            
            else:
                # Custom integration
                handler = CustomIntegration(config)
                await handler.initialize()
                self.integration_handlers[integration_id] = handler
                config.status = IntegrationStatus.ACTIVE
            
            self.stats["active_integrations"] += 1
            
        except Exception as e:
            config.status = IntegrationStatus.ERROR
            config.error_message = str(e)
            logging.error(f"Failed to initialize integration {integration_id}: {e}")
    
    async def _start_sync_task(self, integration_id: str):
        """Start sync task for integration"""
        config = self.integrations[integration_id]
        
        if config.sync_interval > 0:
            task = asyncio.create_task(self._sync_loop(integration_id))
            self.sync_tasks[integration_id] = task
    
    async def _sync_loop(self, integration_id: str):
        """Background sync loop"""
        config = self.integrations[integration_id]
        
        while config.is_active and integration_id in self.integrations:
            try:
                await self.sync_integration(integration_id)
                await asyncio.sleep(config.sync_interval)
            except Exception as e:
                logging.error(f"Error in sync loop for {integration_id}: {e}")
                await asyncio.sleep(config.sync_interval)
    
    async def sync_integration(self, integration_id: str) -> IntegrationResult:
        """Sync integration data"""
        if integration_id not in self.integrations:
            return IntegrationResult(
                integration_id=integration_id,
                operation="sync",
                success=False,
                data=None,
                error_message="Integration not found",
                timestamp=datetime.now(),
                execution_time=0.0
            )
        
        config = self.integrations[integration_id]
        handler = self.integration_handlers.get(integration_id)
        
        if not handler:
            return IntegrationResult(
                integration_id=integration_id,
                operation="sync",
                success=False,
                data=None,
                error_message="Handler not initialized",
                timestamp=datetime.now(),
                execution_time=0.0
            )
        
        try:
            # Perform sync based on integration type
            if config.type == IntegrationType.EVILGINX:
                result = await handler.get_phishlets()
            elif config.type == IntegrationType.GOPHISH:
                result = await handler.get_campaigns()
            else:
                result = IntegrationResult(
                    integration_id=integration_id,
                    operation="sync",
                    success=True,
                    data={"message": "Sync completed"},
                    error_message=None,
                    timestamp=datetime.now(),
                    execution_time=0.0
                )
            
            # Update last sync
            config.last_sync = datetime.now()
            
            # Store result
            self.results_history.append(result)
            self._update_stats(result)
            
            return result
            
        except Exception as e:
            result = IntegrationResult(
                integration_id=integration_id,
                operation="sync",
                success=False,
                data=None,
                error_message=str(e),
                timestamp=datetime.now(),
                execution_time=0.0
            )
            
            self.results_history.append(result)
            self._update_stats(result)
            
            return result
    
    async def execute_operation(self, integration_id: str, operation: str, 
                              data: Dict[str, Any] = None) -> IntegrationResult:
        """Execute operation on integration"""
        if integration_id not in self.integrations:
            return IntegrationResult(
                integration_id=integration_id,
                operation=operation,
                success=False,
                data=None,
                error_message="Integration not found",
                timestamp=datetime.now(),
                execution_time=0.0
            )
        
        config = self.integrations[integration_id]
        handler = self.integration_handlers.get(integration_id)
        
        if not handler:
            return IntegrationResult(
                integration_id=integration_id,
                operation=operation,
                success=False,
                data=None,
                error_message="Handler not initialized",
                timestamp=datetime.now(),
                execution_time=0.0
            )
        
        try:
            start_time = datetime.now()
            
            # Execute operation based on integration type and operation
            if config.type == IntegrationType.EVILGINX:
                if operation == "create_phishlet":
                    result = await handler.create_phishlet(data or {})
                elif operation == "start_campaign":
                    result = await handler.start_campaign(data or {})
                elif operation == "get_campaign_stats":
                    campaign_id = data.get("campaign_id") if data else None
                    result = await handler.get_campaign_stats(campaign_id)
                else:
                    result = IntegrationResult(
                        integration_id=integration_id,
                        operation=operation,
                        success=False,
                        data=None,
                        error_message=f"Unknown operation: {operation}",
                        timestamp=datetime.now(),
                        execution_time=0.0
                    )
            
            elif config.type == IntegrationType.GOPHISH:
                if operation == "import_templates":
                    templates = data.get("templates", []) if data else []
                    result = await handler.import_templates(templates)
                else:
                    result = IntegrationResult(
                        integration_id=integration_id,
                        operation=operation,
                        success=False,
                        data=None,
                        error_message=f"Unknown operation: {operation}",
                        timestamp=datetime.now(),
                        execution_time=0.0
                    )
            
            elif config.type == IntegrationType.WEBHOOK:
                event_type = data.get("event_type", operation) if data else operation
                result = await handler.send_webhook(event_type, data or {})
            
            else:
                result = IntegrationResult(
                    integration_id=integration_id,
                    operation=operation,
                    success=False,
                    data=None,
                    error_message=f"Unsupported integration type: {config.type}",
                    timestamp=datetime.now(),
                    execution_time=0.0
                )
            
            # Calculate execution time
            end_time = datetime.now()
            result.execution_time = (end_time - start_time).total_seconds()
            
            # Store result
            self.results_history.append(result)
            self._update_stats(result)
            
            return result
            
        except Exception as e:
            result = IntegrationResult(
                integration_id=integration_id,
                operation=operation,
                success=False,
                data=None,
                error_message=str(e),
                timestamp=datetime.now(),
                execution_time=0.0
            )
            
            self.results_history.append(result)
            self._update_stats(result)
            
            return result
    
    async def send_webhook(self, integration_id: str, event_type: str, 
                          data: Dict[str, Any]) -> IntegrationResult:
        """Send webhook notification"""
        return await self.execute_operation(integration_id, "send_webhook", 
                                         {"event_type": event_type, **data})
    
    def register_webhook_handler(self, event_type: str, handler: Callable):
        """Register webhook event handler"""
        if event_type not in self.webhook_handlers:
            self.webhook_handlers[event_type] = []
        
        self.webhook_handlers[event_type].append(handler)
    
    async def handle_webhook_event(self, event_type: str, data: Dict[str, Any]):
        """Handle webhook event"""
        if event_type in self.webhook_handlers:
            for handler in self.webhook_handlers[event_type]:
                try:
                    await handler(data)
                except Exception as e:
                    logging.error(f"Error in webhook handler for {event_type}: {e}")
    
    async def remove_integration(self, integration_id: str) -> bool:
        """Remove integration"""
        if integration_id not in self.integrations:
            return False
        
        config = self.integrations[integration_id]
        
        # Stop sync task
        if integration_id in self.sync_tasks:
            self.sync_tasks[integration_id].cancel()
            del self.sync_tasks[integration_id]
        
        # Close handler
        if integration_id in self.integration_handlers:
            handler = self.integration_handlers[integration_id]
            if hasattr(handler, 'close'):
                await handler.close()
            del self.integration_handlers[integration_id]
        
        # Remove integration
        del self.integrations[integration_id]
        
        # Update stats
        self.stats["total_integrations"] -= 1
        if config.is_active:
            self.stats["active_integrations"] -= 1
        
        logging.info(f"Integration removed: {integration_id}")
        return True
    
    def get_integration(self, integration_id: str) -> Optional[Dict[str, Any]]:
        """Get integration information"""
        if integration_id not in self.integrations:
            return None
        
        config = self.integrations[integration_id]
        
        return {
            "integration_id": config.integration_id,
            "name": config.name,
            "type": config.type.value,
            "endpoint_url": config.endpoint_url,
            "is_active": config.is_active,
            "status": config.status.value,
            "created_at": config.created_at.isoformat(),
            "last_sync": config.last_sync.isoformat() if config.last_sync else None,
            "error_message": config.error_message,
            "sync_interval": config.sync_interval
        }
    
    def list_integrations(self) -> List[Dict[str, Any]]:
        """List all integrations"""
        return [self.get_integration(int_id) for int_id in self.integrations.keys()]
    
    def get_operation_history(self, integration_id: str = None, 
                            limit: int = 50) -> List[Dict[str, Any]]:
        """Get operation history"""
        history = self.results_history
        
        if integration_id:
            history = [r for r in history if r.integration_id == integration_id]
        
        # Sort by timestamp (newest first)
        history.sort(key=lambda x: x.timestamp, reverse=True)
        
        return [
            {
                "integration_id": r.integration_id,
                "operation": r.operation,
                "success": r.success,
                "error_message": r.error_message,
                "timestamp": r.timestamp.isoformat(),
                "execution_time": r.execution_time
            }
            for r in history[:limit]
        ]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get integration statistics"""
        self.stats["total_integrations"] = len(self.integrations)
        self.stats["active_integrations"] = sum(1 for config in self.integrations.values() if config.is_active)
        
        return self.stats.copy()
    
    def _update_stats(self, result: IntegrationResult):
        """Update statistics"""
        self.stats["total_operations"] += 1
        if result.success:
            self.stats["successful_operations"] += 1
        else:
            self.stats["failed_operations"] += 1
    
    async def cleanup(self):
        """Cleanup resources"""
        # Cancel all sync tasks
        for task in self.sync_tasks.values():
            task.cancel()
        
        # Close all handlers
        for handler in self.integration_handlers.values():
            if hasattr(handler, 'close'):
                await handler.close()
        
        self.sync_tasks.clear()
        self.integration_handlers.clear()


class CustomIntegration:
    """Custom integration handler"""
    
    def __init__(self, config: IntegrationConfig):
        self.config = config
        self.session = None
    
    async def initialize(self):
        """Initialize custom integration"""
        self.session = aiohttp.ClientSession()
    
    async def close(self):
        """Close custom integration"""
        if self.session:
            await self.session.close()


# Global integration manager
integration_manager = IntegrationManager()
