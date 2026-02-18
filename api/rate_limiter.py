"""
VANTABLACK Rate Limiter - API Rate Limiting
==========================================

Advanced rate limiting system:
- User-based rate limiting
- Endpoint-based rate limiting
- Sliding window algorithm
- Redis support (optional)
- Custom rate limit policies
"""

import time
import asyncio
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import defaultdict, deque
import logging
import json


@dataclass
class RateLimitRule:
    """Rate limit rule definition"""
    name: str
    requests_per_window: int
    window_seconds: int
    burst_size: int = 0
    priority: int = 1
    description: str = ""
    
    def __post_init__(self):
        if self.burst_size == 0:
            self.burst_size = self.requests_per_window // 4


@dataclass
class RateLimitResult:
    """Rate limit check result"""
    allowed: bool
    remaining: int
    reset_time: datetime
    retry_after: Optional[int] = None
    rule_name: str = ""
    current_usage: int = 0


class SlidingWindowRateLimiter:
    """Sliding window rate limiter implementation"""
    
    def __init__(self):
        # User-based rate limits: {user_id: {endpoint: deque of timestamps}}
        self.user_limits: Dict[str, Dict[str, deque]] = defaultdict(lambda: defaultdict(deque))
        
        # Global rate limits: {endpoint: deque of timestamps}
        self.global_limits: Dict[str, deque] = defaultdict(deque)
        
        # Rate limit rules
        self.rules: Dict[str, RateLimitRule] = {}
        
        # Statistics
        self.stats = {
            "total_requests": 0,
            "blocked_requests": 0,
            "active_windows": 0,
            "rules_active": 0
        }
        
        # Cleanup task
        self.cleanup_task: Optional[asyncio.Task] = None
        
        # Default rules
        self._setup_default_rules()
    
    def _setup_default_rules(self):
        """Setup default rate limit rules"""
        default_rules = [
            RateLimitRule(
                name="default",
                requests_per_window=100,
                window_seconds=60,
                burst_size=20,
                priority=1,
                description="Default rate limit for all endpoints"
            ),
            RateLimitRule(
                name="template_generate",
                requests_per_window=10,
                window_seconds=60,
                burst_size=5,
                priority=2,
                description="Template generation rate limit"
            ),
            RateLimitRule(
                name="campaign_create",
                requests_per_window=5,
                window_seconds=60,
                burst_size=2,
                priority=2,
                description="Campaign creation rate limit"
            ),
            RateLimitRule(
                name="analysis_run",
                requests_per_window=20,
                window_seconds=60,
                burst_size=5,
                priority=2,
                description="Analysis execution rate limit"
            ),
            RateLimitRule(
                name="marketplace_search",
                requests_per_window=50,
                window_seconds=60,
                burst_size=10,
                priority=1,
                description="Marketplace search rate limit"
            ),
            RateLimitRule(
                name="marketplace_download",
                requests_per_window=20,
                window_seconds=60,
                burst_size=5,
                priority=2,
                description="Marketplace download rate limit"
            ),
            RateLimitRule(
                name="optimization_start",
                requests_per_window=3,
                window_seconds=300,  # 5 minutes
                burst_size=1,
                priority=3,
                description="Template optimization rate limit"
            ),
            RateLimitRule(
                name="auth_login",
                requests_per_window=5,
                window_seconds=300,  # 5 minutes
                burst_size=2,
                priority=3,
                description="Authentication login rate limit"
            ),
            RateLimitRule(
                name="admin_operations",
                requests_per_window=50,
                window_seconds=60,
                burst_size=10,
                priority=2,
                description="Admin operations rate limit"
            )
        ]
        
        for rule in default_rules:
            self.rules[rule.name] = rule
    
    def add_rule(self, rule: RateLimitRule):
        """Add a new rate limit rule"""
        self.rules[rule.name] = rule
        logging.info(f"Rate limit rule added: {rule.name}")
    
    def remove_rule(self, rule_name: str) -> bool:
        """Remove a rate limit rule"""
        if rule_name in self.rules:
            del self.rules[rule_name]
            logging.info(f"Rate limit rule removed: {rule_name}")
            return True
        return False
    
    async def check_limit(self, user_id: str, endpoint: str, 
                         rule_name: str = None) -> RateLimitResult:
        """Check if request is allowed under rate limits"""
        self.stats["total_requests"] += 1
        
        # Determine which rule to use
        if rule_name and rule_name in self.rules:
            rule = self.rules[rule_name]
        else:
            # Find matching rule for endpoint
            rule = self._find_rule_for_endpoint(endpoint)
        
        if not rule:
            # No specific rule, use default
            rule = self.rules.get("default")
            if not rule:
                # No rules configured, allow everything
                return RateLimitResult(
                    allowed=True,
                    remaining=999999,
                    reset_time=datetime.now() + timedelta(seconds=60),
                    rule_name="unlimited"
                )
        
        # Check user-specific limit
        user_result = await self._check_user_limit(user_id, endpoint, rule)
        
        # Check global limit
        global_result = await self._check_global_limit(endpoint, rule)
        
        # Return the more restrictive result
        if not user_result.allowed:
            self.stats["blocked_requests"] += 1
            return user_result
        elif not global_result.allowed:
            self.stats["blocked_requests"] += 1
            return global_result
        else:
            # Both allowed, return user result (more specific)
            return user_result
    
    def _find_rule_for_endpoint(self, endpoint: str) -> Optional[RateLimitRule]:
        """Find the most specific rule for an endpoint"""
        # Direct match
        if endpoint in self.rules:
            return self.rules[endpoint]
        
        # Pattern matching
        for rule_name, rule in self.rules.items():
            if rule_name in endpoint:
                return rule
        
        return None
    
    async def _check_user_limit(self, user_id: str, endpoint: str, 
                               rule: RateLimitRule) -> RateLimitResult:
        """Check user-specific rate limit"""
        now = time.time()
        window_start = now - rule.window_seconds
        
        # Get or create user window
        user_window = self.user_limits[user_id][endpoint]
        
        # Clean old entries
        while user_window and user_window[0] < window_start:
            user_window.popleft()
        
        # Check if under limit
        current_usage = len(user_window)
        
        if current_usage >= rule.requests_per_window:
            # Rate limited
            oldest_request = user_window[0] if user_window else now
            reset_time = datetime.fromtimestamp(oldest_request + rule.window_seconds)
            retry_after = int(reset_time.timestamp() - now)
            
            return RateLimitResult(
                allowed=False,
                remaining=0,
                reset_time=reset_time,
                retry_after=retry_after,
                rule_name=rule.name,
                current_usage=current_usage
            )
        
        # Check burst limit
        if rule.burst_size > 0:
            recent_window = now - 10  # Last 10 seconds for burst
            recent_requests = sum(1 for timestamp in user_window if timestamp >= recent_window)
            
            if recent_requests >= rule.burst_size:
                # Burst limited
                reset_time = datetime.fromtimestamp(now + 10)
                retry_after = 10
                
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_time=reset_time,
                    retry_after=retry_after,
                    rule_name=f"{rule.name}_burst",
                    current_usage=current_usage
                )
        
        # Allow request
        user_window.append(now)
        remaining = rule.requests_per_window - len(user_window)
        reset_time = datetime.fromtimestamp(window_start + rule.window_seconds)
        
        return RateLimitResult(
            allowed=True,
            remaining=remaining,
            reset_time=reset_time,
            rule_name=rule.name,
            current_usage=current_usage
        )
    
    async def _check_global_limit(self, endpoint: str, 
                                 rule: RateLimitRule) -> RateLimitResult:
        """Check global rate limit"""
        now = time.time()
        window_start = now - rule.window_seconds
        
        # Get or create global window
        global_window = self.global_limits[endpoint]
        
        # Clean old entries
        while global_window and global_window[0] < window_start:
            global_window.popleft()
        
        # Check if under limit
        current_usage = len(global_window)
        
        if current_usage >= rule.requests_per_window:
            # Rate limited
            oldest_request = global_window[0] if global_window else now
            reset_time = datetime.fromtimestamp(oldest_request + rule.window_seconds)
            retry_after = int(reset_time.timestamp() - now)
            
            return RateLimitResult(
                allowed=False,
                remaining=0,
                reset_time=reset_time,
                retry_after=retry_after,
                rule_name=f"{rule.name}_global",
                current_usage=current_usage
            )
        
        # Allow request
        global_window.append(now)
        remaining = rule.requests_per_window - len(global_window)
        reset_time = datetime.fromtimestamp(window_start + rule.window_seconds)
        
        return RateLimitResult(
            allowed=True,
            remaining=remaining,
            reset_time=reset_time,
            rule_name=f"{rule.name}_global",
            current_usage=current_usage
        )
    
    def get_user_usage(self, user_id: str, endpoint: str = None) -> Dict[str, Any]:
        """Get current usage for a user"""
        usage_data = {}
        
        if endpoint:
            # Specific endpoint
            if user_id in self.user_limits and endpoint in self.user_limits[user_id]:
                window = self.user_limits[user_id][endpoint]
                usage_data[endpoint] = {
                    "current_usage": len(window),
                    "timestamps": list(window)
                }
        else:
            # All endpoints
            if user_id in self.user_limits:
                for ep, window in self.user_limits[user_id].items():
                    usage_data[ep] = {
                        "current_usage": len(window),
                        "timestamps": list(window)
                    }
        
        return usage_data
    
    def get_global_usage(self, endpoint: str = None) -> Dict[str, Any]:
        """Get current global usage"""
        usage_data = {}
        
        if endpoint:
            # Specific endpoint
            if endpoint in self.global_limits:
                window = self.global_limits[endpoint]
                usage_data[endpoint] = {
                    "current_usage": len(window),
                    "timestamps": list(window)
                }
        else:
            # All endpoints
            for ep, window in self.global_limits.items():
                usage_data[ep] = {
                    "current_usage": len(window),
                    "timestamps": list(window)
                }
        
        return usage_data
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics"""
        # Count active windows
        active_user_windows = sum(len(endpoints) for endpoints in self.user_limits.values())
        active_global_windows = len(self.global_limits)
        
        self.stats.update({
            "active_user_windows": active_user_windows,
            "active_global_windows": active_global_windows,
            "total_active_windows": active_user_windows + active_global_windows,
            "rules_configured": len(self.rules)
        })
        
        return self.stats.copy()
    
    def reset_user_limits(self, user_id: str, endpoint: str = None):
        """Reset rate limits for a user"""
        if user_id in self.user_limits:
            if endpoint:
                if endpoint in self.user_limits[user_id]:
                    del self.user_limits[user_id][endpoint]
                    logging.info(f"Reset rate limit for user {user_id} on endpoint {endpoint}")
            else:
                del self.user_limits[user_id]
                logging.info(f"Reset all rate limits for user {user_id}")
    
    def reset_global_limits(self, endpoint: str = None):
        """Reset global rate limits"""
        if endpoint:
            if endpoint in self.global_limits:
                del self.global_limits[endpoint]
                logging.info(f"Reset global rate limit for endpoint {endpoint}")
        else:
            self.global_limits.clear()
            logging.info("Reset all global rate limits")
    
    async def cleanup_expired_windows(self):
        """Clean up expired windows"""
        now = time.time()
        cleaned_count = 0
        
        # Clean user windows
        for user_id in list(self.user_limits.keys()):
            for endpoint in list(self.user_limits[user_id].keys()):
                window = self.user_limits[user_id][endpoint]
                window_start = now - 3600  # 1 hour
                
                # Remove old entries
                original_size = len(window)
                while window and window[0] < window_start:
                    window.popleft()
                
                # Remove empty windows
                if not window:
                    del self.user_limits[user_id][endpoint]
                    cleaned_count += original_size
            
            # Remove users with no windows
            if not self.user_limits[user_id]:
                del self.user_limits[user_id]
        
        # Clean global windows
        for endpoint in list(self.global_limits.keys()):
            window = self.global_limits[endpoint]
            window_start = now - 3600  # 1 hour
            
            # Remove old entries
            original_size = len(window)
            while window and window[0] < window_start:
                window.popleft()
            
            # Remove empty windows
            if not window:
                del self.global_limits[endpoint]
                cleaned_count += original_size
        
        if cleaned_count > 0:
            logging.info(f"Cleaned up {cleaned_count} expired rate limit entries")
        
        return cleaned_count
    
    def export_config(self) -> Dict[str, Any]:
        """Export rate limiter configuration"""
        return {
            "rules": {
                name: {
                    "requests_per_window": rule.requests_per_window,
                    "window_seconds": rule.window_seconds,
                    "burst_size": rule.burst_size,
                    "priority": rule.priority,
                    "description": rule.description
                }
                for name, rule in self.rules.items()
            },
            "stats": self.get_stats()
        }
    
    def import_config(self, config: Dict[str, Any]):
        """Import rate limiter configuration"""
        if "rules" in config:
            for rule_name, rule_data in config["rules"].items():
                rule = RateLimitRule(
                    name=rule_name,
                    requests_per_window=rule_data["requests_per_window"],
                    window_seconds=rule_data["window_seconds"],
                    burst_size=rule_data.get("burst_size", 0),
                    priority=rule_data.get("priority", 1),
                    description=rule_data.get("description", "")
                )
                self.rules[rule_name] = rule
        
        logging.info("Rate limiter configuration imported")


class RateLimiter:
    """Main rate limiter interface"""
    
    def __init__(self):
        self.sliding_window = SlidingWindowRateLimiter()
        self.cleanup_task: Optional[asyncio.Task] = None
        
        # Start cleanup task
        self._start_cleanup_task()
    
    def _start_cleanup_task(self):
        """Start background cleanup task"""
        if self.cleanup_task is None or self.cleanup_task.done():
            self.cleanup_task = asyncio.create_task(self._cleanup_loop())
    
    async def _cleanup_loop(self):
        """Background cleanup loop"""
        while True:
            try:
                await asyncio.sleep(300)  # Clean every 5 minutes
                await self.sliding_window.cleanup_expired_windows()
            except Exception as e:
                logging.error(f"Error in rate limiter cleanup: {e}")
    
    async def check_limit(self, user_id: str, endpoint: str, 
                         rule_name: str = None) -> RateLimitResult:
        """Check if request is allowed under rate limits"""
        return await self.sliding_window.check_limit(user_id, endpoint, rule_name)
    
    def add_rule(self, rule: RateLimitRule):
        """Add a new rate limit rule"""
        self.sliding_window.add_rule(rule)
    
    def remove_rule(self, rule_name: str) -> bool:
        """Remove a rate limit rule"""
        return self.sliding_window.remove_rule(rule_name)
    
    def get_user_usage(self, user_id: str, endpoint: str = None) -> Dict[str, Any]:
        """Get current usage for a user"""
        return self.sliding_window.get_user_usage(user_id, endpoint)
    
    def get_global_usage(self, endpoint: str = None) -> Dict[str, Any]:
        """Get current global usage"""
        return self.sliding_window.get_global_usage(endpoint)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics"""
        return self.sliding_window.get_stats()
    
    def reset_user_limits(self, user_id: str, endpoint: str = None):
        """Reset rate limits for a user"""
        self.sliding_window.reset_user_limits(user_id, endpoint)
    
    def reset_global_limits(self, endpoint: str = None):
        """Reset global rate limits"""
        self.sliding_window.reset_global_limits(endpoint)
    
    def export_config(self) -> Dict[str, Any]:
        """Export rate limiter configuration"""
        return self.sliding_window.export_config()
    
    def import_config(self, config: Dict[str, Any]):
        """Import rate limiter configuration"""
        self.sliding_window.import_config(config)


# FastAPI dependency
"""
from fastapi import HTTPException, status
from datetime import datetime

async def rate_limit_check(user_id: str, endpoint: str, rule_name: str = None):
    rate_limiter = RateLimiter()
    result = await rate_limiter.check_limit(user_id, endpoint, rule_name)
    
    if not result.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={
                "X-RateLimit-Limit": str(result.rule.requests_per_window),
                "X-RateLimit-Remaining": str(result.remaining),
                "X-RateLimit-Reset": str(int(result.reset_time.timestamp())),
                "Retry-After": str(result.retry_after) if result.retry_after else None
            }
        )
    
    return result
"""
