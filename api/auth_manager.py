"""
VANTABLACK Authentication Manager - Security & Authorization
=========================================================

Comprehensive authentication and authorization system:
- JWT token management
- Role-based access control
- API key authentication
- Session management
- Security policies
"""

import jwt
import bcrypt
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import logging
import hashlib
import json
import redis.asyncio as redis
from fastapi.concurrency import run_in_threadpool


class UserRole(Enum):
    """User roles"""
    ADMIN = "admin"
    RED_TEAM = "red_team"
    ANALYST = "analyst"
    VIEWER = "viewer"


class Permission(Enum):
    """System permissions"""
    # Template permissions
    TEMPLATE_CREATE = "template_create"
    TEMPLATE_READ = "template_read"
    TEMPLATE_UPDATE = "template_update"
    TEMPLATE_DELETE = "template_delete"
    
    # Campaign permissions
    CAMPAIGN_CREATE = "campaign_create"
    CAMPAIGN_READ = "campaign_read"
    CAMPAIGN_UPDATE = "campaign_update"
    CAMPAIGN_DELETE = "campaign_delete"
    CAMPAIGN_EXECUTE = "campaign_execute"
    
    # Analysis permissions
    ANALYSIS_RUN = "analysis_run"
    ANALYSIS_READ = "analysis_read"
    
    # Marketplace permissions
    MARKETPLACE_READ = "marketplace_read"
    MARKETPLACE_SUBMIT = "marketplace_submit"
    MARKETPLACE_MODERATE = "marketplace_moderate"
    
    # System permissions
    SYSTEM_ADMIN = "system_admin"
    USER_MANAGE = "user_manage"
    SYSTEM_MONITOR = "system_monitor"


@dataclass
class User:
    """User model"""
    user_id: str
    username: str
    email: str
    password_hash: str
    role: UserRole
    permissions: List[Permission]
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]
    api_keys: List[str]
    sessions: List[str]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["role"] = self.role.value
        d["permissions"] = [p.value for p in self.permissions]
        d["created_at"] = self.created_at.isoformat()
        d["last_login"] = self.last_login.isoformat() if self.last_login else None
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "User":
        return cls(
            user_id=data["user_id"],
            username=data["username"],
            email=data["email"],
            password_hash=data["password_hash"],
            role=UserRole(data["role"]),
            permissions=[Permission(p) for p in data["permissions"]],
            is_active=data["is_active"],
            created_at=datetime.fromisoformat(data["created_at"]),
            last_login=datetime.fromisoformat(data["last_login"]) if data["last_login"] else None,
            api_keys=data["api_keys"],
            sessions=data["sessions"]
        )


@dataclass
class Session:
    """Session model"""
    session_id: str
    user_id: str
    created_at: datetime
    expires_at: datetime
    last_activity: datetime
    ip_address: str
    user_agent: str
    is_active: bool

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["created_at"] = self.created_at.isoformat()
        d["expires_at"] = self.expires_at.isoformat()
        d["last_activity"] = self.last_activity.isoformat()
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Session":
        return cls(
            session_id=data["session_id"],
            user_id=data["user_id"],
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            last_activity=datetime.fromisoformat(data["last_activity"]),
            ip_address=data["ip_address"],
            user_agent=data["user_agent"],
            is_active=data["is_active"]
        )


@dataclass
class APIKey:
    """API Key model"""
    key_id: str
    user_id: str
    key_hash: str
    name: str
    permissions: List[Permission]
    created_at: datetime
    expires_at: Optional[datetime]
    last_used: Optional[datetime]
    is_active: bool

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["permissions"] = [p.value for p in self.permissions]
        d["created_at"] = self.created_at.isoformat()
        d["expires_at"] = self.expires_at.isoformat() if self.expires_at else None
        d["last_used"] = self.last_used.isoformat() if self.last_used else None
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "APIKey":
        return cls(
            key_id=data["key_id"],
            user_id=data["user_id"],
            key_hash=data["key_hash"],
            name=data["name"],
            permissions=[Permission(p) for p in data["permissions"]],
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]) if data["expires_at"] else None,
            last_used=datetime.fromisoformat(data["last_used"]) if data["last_used"] else None,
            is_active=data["is_active"]
        )


class AuthManager:
    """Authentication and authorization manager"""
    
    def __init__(self, secret_key: str = None, redis_url: str = "redis://localhost"):
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        self.algorithm = "HS256"
        self.token_expiry = timedelta(hours=24)
        self.session_expiry = timedelta(days=7)
        self.redis = redis.from_url(redis_url, decode_responses=True)
        
        # Role permissions mapping
        self.role_permissions = {
            UserRole.ADMIN: list(Permission),
            UserRole.RED_TEAM: [
                Permission.TEMPLATE_CREATE, Permission.TEMPLATE_READ, Permission.TEMPLATE_UPDATE,
                Permission.CAMPAIGN_CREATE, Permission.CAMPAIGN_READ, Permission.CAMPAIGN_UPDATE, Permission.CAMPAIGN_EXECUTE,
                Permission.ANALYSIS_RUN, Permission.ANALYSIS_READ,
                Permission.MARKETPLACE_READ, Permission.MARKETPLACE_SUBMIT
            ],
            UserRole.ANALYST: [
                Permission.TEMPLATE_READ, Permission.CAMPAIGN_READ,
                Permission.ANALYSIS_RUN, Permission.ANALYSIS_READ,
                Permission.MARKETPLACE_READ
            ],
            UserRole.VIEWER: [
                Permission.TEMPLATE_READ, Permission.CAMPAIGN_READ,
                Permission.ANALYSIS_READ, Permission.MARKETPLACE_READ
            ]
        }
    
    async def _initialize_default_admin(self):
        """Initialize default admin user in Redis"""
        admin_user_id = "admin_default"
        if not await self.redis.exists(f"user:{admin_user_id}"):
            admin_password = await self._hash_password("admin123")  # Change in production
            admin_user = User(
                user_id=admin_user_id,
                username="admin",
                email="admin@vantablack.local",
                password_hash=admin_password,
                role=UserRole.ADMIN,
                permissions=self.role_permissions[UserRole.ADMIN],
                is_active=True,
                created_at=datetime.now(),
                last_login=None,
                api_keys=[],
                sessions=[]
            )
            async with self.redis.pipeline(transaction=True) as pipe:
                await pipe.hset(f"user:{admin_user_id}", mapping=admin_user.to_dict())
                await pipe.set(f"user:by_username:{admin_user.username}", admin_user_id)
                await pipe.set(f"user:by_email:{admin_user.email}", admin_user_id)
                await pipe.execute()
    
    async def _hash_password(self, password: str) -> str:
        """Hash password using bcrypt in a thread pool"""
        salt = await run_in_threadpool(bcrypt.gensalt)
        return await run_in_threadpool(bcrypt.hashpw, password.encode('utf-8'), salt).decode('utf-8')

    async def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash in a thread pool"""
        return await run_in_threadpool(bcrypt.checkpw, password.encode('utf-8'), password_hash.encode('utf-8'))
    
    def _generate_jwt_token(self, user: User, expires_delta: timedelta = None) -> str:
        """Generate JWT token for user"""
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + self.token_expiry
        
        payload = {
            "user_id": user.user_id,
            "username": user.username,
            "role": user.role.value,
            "permissions": [p.value for p in user.permissions],
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access_token"
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def _generate_api_key(self) -> str:
        """Generate secure API key"""
        return f"vk_{secrets.token_urlsafe(32)}"
    
    def _hash_api_key(self, api_key: str) -> str:
        """Hash API key for storage"""
        return hashlib.sha256(api_key.encode()).hexdigest()
    
    async def create_user(self, username: str, email: str, password: str, 
                         role: UserRole = UserRole.RED_TEAM) -> str:
        """Create new user in Redis"""
        await self._initialize_default_admin()
        
        # Check if user already exists
        if await self.redis.exists(f"user:by_username:{username}") or \
           await self.redis.exists(f"user:by_email:{email}"):
            raise ValueError("User with this username or email already exists")
        
        # Create user
        user_id = f"user_{secrets.token_urlsafe(16)}"
        password_hash = await self._hash_password(password)
        
        user = User(
            user_id=user_id,
            username=username,
            email=email,
            password_hash=password_hash,
            role=role,
            permissions=self.role_permissions[role],
            is_active=True,
            created_at=datetime.now(),
            last_login=None,
            api_keys=[],
            sessions=[]
        )
        
        async with self.redis.pipeline(transaction=True) as pipe:
            await pipe.hset(f"user:{user_id}", mapping=user.to_dict())
            await pipe.set(f"user:by_username:{user.username}", user_id)
            await pipe.set(f"user:by_email:{user.email}", user_id)
            await pipe.execute()
        
        logging.info(f"User created: {username} ({user_id})")
        return user_id
    
    async def authenticate_user(self, username: str, password: str, 
                              ip_address: str = "127.0.0.1",
                              user_agent: str = "Unknown") -> Optional[Dict[str, Any]]:
        """Authenticate user with username/password against Redis"""
        await self._initialize_default_admin()
        
        # Find user ID by username
        user_id = await self.redis.get(f"user:by_username:{username}")
        if not user_id:
            return None
        
        # Get user data
        user_data = await self.redis.hgetall(f"user:{user_id}")
        if not user_data:
            return None
        
        user = User.from_dict(user_data)
        
        if not user.is_active:
            return None
        
        if not await self._verify_password(password, user.password_hash):
            return None
        
        # Update last login
        user.last_login = datetime.now()
        
        # Create session
        session_id = secrets.token_urlsafe(32)
        session = Session(
            session_id=session_id,
            user_id=user.user_id,
            created_at=datetime.now(),
            expires_at=datetime.now() + self.session_expiry,
            last_activity=datetime.now(),
            ip_address=ip_address,
            user_agent=user_agent,
            is_active=True
        )
        
        user.sessions.append(session_id)
        
        # Save session and updated user data to Redis
        async with self.redis.pipeline(transaction=True) as pipe:
            await pipe.hset(f"session:{session_id}", mapping=session.to_dict())
            await pipe.hset(f"user:{user_id}", "last_login", user.last_login.isoformat())
            await pipe.hset(f"user:{user_id}", "sessions", json.dumps(user.sessions))
            await pipe.expire(f"session:{session_id}", self.session_expiry)
            await pipe.execute()
        
        # Generate JWT token
        token = self._generate_jwt_token(user)
        
        logging.info(f"User authenticated: {username} ({user.user_id})")
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": int(self.token_expiry.total_seconds()),
            "user_id": user.user_id,
            "username": user.username,
            "role": user.role.value,
            "permissions": [p.value for p in user.permissions],
            "session_id": session_id
        }
    
    async def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token and return user info from Redis"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            user_id = payload.get("user_id")
            if not user_id:
                return None
            
            user_data = await self.redis.hgetall(f"user:{user_id}")
            if not user_data:
                return None
            
            user = User.from_dict(user_data)
            if not user.is_active:
                return None
            
            return {
                "user_id": user.user_id,
                "username": user.username,
                "email": user.email,
                "role": user.role.value,
                "permissions": [p.value for p in user.permissions],
                "created_at": user.created_at.isoformat(),
                "last_login": user.last_login.isoformat() if user.last_login else None
            }
            
        except jwt.ExpiredSignatureError:
            logging.warning("Token expired")
            return None
        except jwt.InvalidTokenError as e:
            logging.warning(f"Invalid token: {e}")
            return None
    
    async def verify_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Verify API key and return user info"""
        key_hash = self._hash_api_key(api_key)
        
        api_key_obj = None
        for key in self.api_keys.values():
            if key.key_hash == key_hash and key.is_active:
                api_key_obj = key
                break
        
        if not api_key_obj:
            return None
        
        # Check if expired
        if api_key_obj.expires_at and api_key_obj.expires_at < datetime.now():
            return None
        
        user = self.users.get(api_key_obj.user_id)
        if not user or not user.is_active:
            return None
        
        # Update last used
        api_key_obj.last_used = datetime.now()
        
        return {
            "user_id": user.user_id,
            "username": user.username,
            "email": user.email,
            "role": user.role.value,
            "permissions": [p.value for p in api_key_obj.permissions],
            "api_key_id": api_key_obj.key_id,
            "api_key_name": api_key_obj.name
        }
    
    async def create_api_key(self, user_id: str, name: str, 
                           permissions: List[Permission] = None,
                           expires_in_days: int = None) -> str:
        """Create API key for user"""
        user = self.users.get(user_id)
        if not user:
            raise ValueError("User not found")
        
        # Generate API key
        api_key = self._generate_api_key()
        key_hash = self._hash_api_key(api_key)
        key_id = f"key_{secrets.token_urlsafe(16)}"
        
        # Set permissions
        if permissions is None:
            permissions = user.permissions
        
        # Set expiry
        expires_at = None
        if expires_in_days:
            expires_at = datetime.now() + timedelta(days=expires_in_days)
        
        # Create API key object
        api_key_obj = APIKey(
            key_id=key_id,
            user_id=user_id,
            key_hash=key_hash,
            name=name,
            permissions=permissions,
            created_at=datetime.now(),
            expires_at=expires_at,
            last_used=None,
            is_active=True
        )
        
        self.api_keys[key_id] = api_key_obj
        user.api_keys.append(key_id)
        
        logging.info(f"API key created: {name} for user {user_id}")
        
        return api_key
    
    async def revoke_api_key(self, user_id: str, key_id: str) -> bool:
        """Revoke API key"""
        user = self.users.get(user_id)
        if not user:
            return False
        
        if key_id not in self.api_keys:
            return False
        
        api_key_obj = self.api_keys[key_id]
        if api_key_obj.user_id != user_id:
            return False
        
        # Deactivate API key
        api_key_obj.is_active = False
        
        # Remove from user
        if key_id in user.api_keys:
            user.api_keys.remove(key_id)
        
        logging.info(f"API key revoked: {key_id} for user {user_id}")
        return True
    
    async def check_permission(self, user_info: Dict[str, Any], 
                            required_permission: Permission) -> bool:
        """Check if user has required permission"""
        user_permissions = user_info.get("permissions", [])
        return required_permission.value in user_permissions
    
    async def check_role(self, user_info: Dict[str, Any], required_role: UserRole) -> bool:
        """Check if user has required role or higher"""
        user_role = UserRole(user_info.get("role", "viewer"))
        
        # Role hierarchy
        role_hierarchy = {
            UserRole.VIEWER: 0,
            UserRole.ANALYST: 1,
            UserRole.RED_TEAM: 2,
            UserRole.ADMIN: 3
        }
        
        return role_hierarchy.get(user_role, 0) >= role_hierarchy.get(required_role, 0)
    
    async def invalidate_session(self, session_id: str) -> bool:
        """Invalidate user session"""
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        session.is_active = False
        
        # Remove from user
        user = self.users.get(session.user_id)
        if user and session_id in user.sessions:
            user.sessions.remove(session_id)
        
        # Delete session
        del self.sessions[session_id]
        
        logging.info(f"Session invalidated: {session_id}")
        return True
    
    async def invalidate_all_user_sessions(self, user_id: str) -> int:
        """Invalidate all sessions for user"""
        user = self.users.get(user_id)
        if not user:
            return 0
        
        invalidated_count = 0
        sessions_to_remove = []
        
        for session_id in user.sessions:
            if session_id in self.sessions:
                self.sessions[session_id].is_active = False
                del self.sessions[session_id]
                sessions_to_remove.append(session_id)
                invalidated_count += 1
        
        # Remove from user
        user.sessions = []
        
        logging.info(f"All sessions invalidated for user {user_id}: {invalidated_count} sessions")
        return invalidated_count
    
    async def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions"""
        now = datetime.now()
        expired_sessions = []
        
        for session_id, session in self.sessions.items():
            if session.expires_at < now or not session.is_active:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            session = self.sessions[session_id]
            
            # Remove from user
            user = self.users.get(session.user_id)
            if user and session_id in user.sessions:
                user.sessions.remove(session_id)
            
            del self.sessions[session_id]
        
        if expired_sessions:
            logging.info(f"Cleaned up {len(expired_sessions)} expired sessions")
        
        return len(expired_sessions)
    
    async def cleanup_expired_api_keys(self) -> int:
        """Clean up expired API keys"""
        now = datetime.now()
        expired_keys = []
        
        for key_id, api_key in self.api_keys.items():
            if api_key.expires_at and api_key.expires_at < now:
                expired_keys.append(key_id)
        
        for key_id in expired_keys:
            api_key = self.api_keys[key_id]
            
            # Remove from user
            user = self.users.get(api_key.user_id)
            if user and key_id in user.api_keys:
                user.api_keys.remove(key_id)
            
            del self.api_keys[key_id]
        
        if expired_keys:
            logging.info(f"Cleaned up {len(expired_keys)} expired API keys")
        
        return len(expired_keys)
    
    def get_user_info(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user information"""
        user = self.users.get(user_id)
        if not user:
            return None
        
        return {
            "user_id": user.user_id,
            "username": user.username,
            "email": user.email,
            "role": user.role.value,
            "permissions": [p.value for p in user.permissions],
            "is_active": user.is_active,
            "created_at": user.created_at.isoformat(),
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "api_keys_count": len(user.api_keys),
            "sessions_count": len(user.sessions)
        }
    
    def get_user_api_keys(self, user_id: str) -> List[Dict[str, Any]]:
        """Get user API keys"""
        user = self.users.get(user_id)
        if not user:
            return []
        
        api_keys = []
        for key_id in user.api_keys:
            if key_id in self.api_keys:
                api_key = self.api_keys[key_id]
                api_keys.append({
                    "key_id": api_key.key_id,
                    "name": api_key.name,
                    "permissions": [p.value for p in api_key.permissions],
                    "created_at": api_key.created_at.isoformat(),
                    "expires_at": api_key.expires_at.isoformat() if api_key.expires_at else None,
                    "last_used": api_key.last_used.isoformat() if api_key.last_used else None,
                    "is_active": api_key.is_active
                })
        
        return api_keys
    
    def get_user_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """Get user sessions"""
        user = self.users.get(user_id)
        if not user:
            return []
        
        sessions = []
        for session_id in user.sessions:
            if session_id in self.sessions:
                session = self.sessions[session_id]
                sessions.append({
                    "session_id": session.session_id,
                    "created_at": session.created_at.isoformat(),
                    "expires_at": session.expires_at.isoformat(),
                    "last_activity": session.last_activity.isoformat(),
                    "ip_address": session.ip_address,
                    "user_agent": session.user_agent,
                    "is_active": session.is_active
                })
        
        return sessions
    
    def get_system_stats(self) -> Dict[str, Any]:
        """Get system authentication statistics"""
        total_users = len(self.users)
        active_users = sum(1 for user in self.users.values() if user.is_active)
        total_sessions = len(self.sessions)
        active_sessions = sum(1 for session in self.sessions.values() if session.is_active)
        total_api_keys = len(self.api_keys)
        active_api_keys = sum(1 for key in self.api_keys.values() if key.is_active)
        
        role_distribution = {}
        for user in self.users.values():
            role = user.role.value
            role_distribution[role] = role_distribution.get(role, 0) + 1
        
        return {
            "users": {
                "total": total_users,
                "active": active_users,
                "role_distribution": role_distribution
            },
            "sessions": {
                "total": total_sessions,
                "active": active_sessions
            },
            "api_keys": {
                "total": total_api_keys,
                "active": active_api_keys
            }
        }


# Dependency functions for FastAPI
async def get_current_user(token: str) -> Optional[Dict[str, Any]]:
    """Get current user from token"""
    auth_manager = AuthManager()
    return await auth_manager.verify_token(token)


async def require_permission(user_info: Dict[str, Any], permission: Permission) -> bool:
    """Require specific permission"""
    auth_manager = AuthManager()
    return await auth_manager.check_permission(user_info, permission)


async def require_role(user_info: Dict[str, Any], role: UserRole) -> bool:
    """Require specific role or higher"""
    auth_manager = AuthManager()
    return await auth_manager.check_role(user_info, role)


# Security middleware for FastAPI
"""
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    user_info = await get_current_user(token)
    if not user_info:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user_info

async def require_admin(current_user: dict = Depends(get_current_user)):
    if not await require_role(current_user, UserRole.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user

async def require_red_team(current_user: dict = Depends(get_current_user)):
    if not await require_role(current_user, UserRole.RED_TEAM):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Red Team access required"
        )
    return current_user
"""
