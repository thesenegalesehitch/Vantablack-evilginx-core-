"""
VANTABLACK Plugin Sandbox - Security Isolation
==============================================

Plugin sandbox for secure execution:
- Resource limiting
- Permission control
- Security policies
- Isolation mechanisms
- Monitoring and auditing
"""

import os
import sys
import resource
import signal
import subprocess
import tempfile
import shutil
import logging
import psutil
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import threading
import time
import json


class SandboxPolicy(Enum):
    """Sandbox security policies"""
    RESTRICTED = "restricted"
    STANDARD = "standard"
    PERMISSIVE = "permissive"
    UNLIMITED = "unlimited"


@dataclass
class SandboxLimits:
    """Resource limits for sandbox"""
    max_cpu_time: float = 60.0  # seconds
    max_memory: int = 256 * 1024 * 1024  # 256MB
    max_disk_space: int = 100 * 1024 * 1024  # 100MB
    max_network_connections: int = 10
    max_file_descriptors: int = 100
    max_processes: int = 5
    allowed_modules: List[str] = None
    blocked_modules: List[str] = None
    allowed_paths: List[str] = None
    blocked_paths: List[str] = None
    network_access: bool = False
    file_system_access: bool = True
    system_calls: List[str] = None
    
    def __post_init__(self):
        if self.allowed_modules is None:
            self.allowed_modules = ['json', 'datetime', 'time', 'logging', 'math', 'random']
        if self.blocked_modules is None:
            self.blocked_modules = ['os.system', 'subprocess', 'eval', 'exec', 'compile']
        if self.allowed_paths is None:
            self.allowed_paths = ['/tmp', '/var/tmp']
        if self.blocked_paths is None:
            self.blocked_paths = ['/etc', '/sys', '/proc', '/root']
        if self.system_calls is None:
            self.system_calls = ['read', 'write', 'open', 'close', 'stat', 'fstat', 'lstat']


@dataclass
class SandboxSession:
    """Sandbox execution session"""
    session_id: str
    plugin_id: str
    policy: SandboxPolicy
    limits: SandboxLimits
    created_at: datetime
    last_activity: datetime
    process_id: Optional[int] = None
    temp_dir: Optional[str] = None
    status: str = "created"
    resource_usage: Dict[str, Any] = None
    violations: List[Dict[str, Any]] = None
    execution_time: float = 0.0
    
    def __post_init__(self):
        if self.resource_usage is None:
            self.resource_usage = {}
        if self.violations is None:
            self.violations = []


class PluginSandbox:
    """Plugin sandbox manager"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.sessions: Dict[str, SandboxSession] = {}
        self.active_processes: Dict[int, SandboxSession] = {}
        self.monitoring_thread = None
        self.monitoring_active = False
        
        # Default policies
        self.policies = {
            SandboxPolicy.RESTRICTED: SandboxLimits(
                max_cpu_time=30.0,
                max_memory=128 * 1024 * 1024,
                max_disk_space=50 * 1024 * 1024,
                max_network_connections=0,
                network_access=False,
                file_system_access=False
            ),
            SandboxPolicy.STANDARD: SandboxLimits(
                max_cpu_time=60.0,
                max_memory=256 * 1024 * 1024,
                max_disk_space=100 * 1024 * 1024,
                max_network_connections=5,
                network_access=False,
                file_system_access=True
            ),
            SandboxPolicy.PERMISSIVE: SandboxLimits(
                max_cpu_time=300.0,
                max_memory=512 * 1024 * 1024,
                max_disk_space=500 * 1024 * 1024,
                max_network_connections=20,
                network_access=True,
                file_system_access=True
            ),
            SandboxPolicy.UNLIMITED: SandboxLimits(
                max_cpu_time=float('inf'),
                max_memory=sys.maxsize,
                max_disk_space=sys.maxsize,
                max_network_connections=1000,
                network_access=True,
                file_system_access=True
            )
        }
        
        # Statistics
        self.stats = {
            "total_sessions": 0,
            "active_sessions": 0,
            "violations": 0,
            "terminated_sessions": 0,
            "average_execution_time": 0.0
        }
        
        # Start monitoring
        self.start_monitoring()
    
    def start_monitoring(self):
        """Start resource monitoring"""
        if not self.monitoring_active:
            self.monitoring_active = True
            self.monitoring_thread = threading.Thread(target=self._monitor_resources, daemon=True)
            self.monitoring_thread.start()
            self.logger.info("Sandbox monitoring started")
    
    def stop_monitoring(self):
        """Stop resource monitoring"""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        self.logger.info("Sandbox monitoring stopped")
    
    def _monitor_resources(self):
        """Monitor resource usage"""
        while self.monitoring_active:
            try:
                # Check all active sessions
                sessions_to_check = list(self.sessions.values())
                
                for session in sessions_to_check:
                    if session.status == "running" and session.process_id:
                        self._check_session_limits(session)
                
                time.sleep(1)  # Check every second
                
            except Exception as e:
                self.logger.error(f"Error in resource monitoring: {e}")
                time.sleep(5)
    
    def _check_session_limits(self, session: SandboxSession):
        """Check if session exceeds limits"""
        try:
            if not session.process_id:
                return
            
            # Get process
            process = psutil.Process(session.process_id)
            
            # Check CPU time
            cpu_times = process.cpu_times()
            total_cpu_time = cpu_times.user + cpu_times.system
            
            if total_cpu_time > session.limits.max_cpu_time:
                self._record_violation(session, "cpu_time_exceeded", {
                    "limit": session.limits.max_cpu_time,
                    "actual": total_cpu_time
                })
                self._terminate_session(session)
                return
            
            # Check memory usage
            memory_info = process.memory_info()
            if memory_info.rss > session.limits.max_memory:
                self._record_violation(session, "memory_exceeded", {
                    "limit": session.limits.max_memory,
                    "actual": memory_info.rss
                })
                self._terminate_session(session)
                return
            
            # Check process count
            children = process.children(recursive=True)
            if len(children) + 1 > session.limits.max_processes:
                self._record_violation(session, "processes_exceeded", {
                    "limit": session.limits.max_processes,
                    "actual": len(children) + 1
                })
                self._terminate_session(session)
                return
            
            # Update resource usage
            session.resource_usage = {
                "cpu_time": total_cpu_time,
                "memory_usage": memory_info.rss,
                "process_count": len(children) + 1,
                "file_descriptors": len(process.open_files()),
                "network_connections": len(process.connections()),
                "timestamp": datetime.now().isoformat()
            }
            
        except psutil.NoSuchProcess:
            # Process already terminated
            session.status = "terminated"
        except Exception as e:
            self.logger.error(f"Error checking session limits: {e}")
    
    def _record_violation(self, session: SandboxSession, violation_type: str, details: Dict[str, Any]):
        """Record security violation"""
        violation = {
            "type": violation_type,
            "timestamp": datetime.now().isoformat(),
            "details": details
        }
        
        session.violations.append(violation)
        self.stats["violations"] += 1
        
        self.logger.warning(f"Sandbox violation: {session.plugin_id} - {violation_type}")
    
    def _terminate_session(self, session: SandboxSession):
        """Terminate session due to violation"""
        try:
            if session.process_id:
                process = psutil.Process(session.process_id)
                process.terminate()
                
                # Wait for graceful termination
                try:
                    process.wait(timeout=5)
                except psutil.TimeoutExpired:
                    # Force kill
                    process.kill()
                    process.wait(timeout=5)
            
            session.status = "terminated"
            self.stats["terminated_sessions"] += 1
            
            self.logger.warning(f"Session terminated due to violations: {session.session_id}")
            
        except Exception as e:
            self.logger.error(f"Error terminating session: {e}")
    
    def create_session(self, plugin_id: str, policy: SandboxPolicy = SandboxPolicy.STANDARD,
                      custom_limits: SandboxLimits = None) -> str:
        """Create sandbox session"""
        session_id = f"sandbox_{int(datetime.now().timestamp())}_{plugin_id}"
        
        # Get limits
        if custom_limits:
            limits = custom_limits
        else:
            limits = self.policies[policy]
        
        # Create temporary directory
        temp_dir = tempfile.mkdtemp(prefix=f"vantablack_sandbox_{plugin_id}_")
        
        # Create session
        session = SandboxSession(
            session_id=session_id,
            plugin_id=plugin_id,
            policy=policy,
            limits=limits,
            created_at=datetime.now(),
            last_activity=datetime.now(),
            temp_dir=temp_dir
        )
        
        self.sessions[session_id] = session
        self.stats["total_sessions"] += 1
        self.stats["active_sessions"] += 1
        
        self.logger.info(f"Sandbox session created: {session_id} for plugin {plugin_id}")
        return session_id
    
    async def execute_in_sandbox(self, session_id: str, code: str, 
                                globals_dict: Dict[str, Any] = None) -> Any:
        """Execute code in sandbox"""
        if session_id not in self.sessions:
            raise ValueError("Session not found")
        
        session = self.sessions[session_id]
        
        if session.status != "created":
            raise ValueError(f"Session not in created state: {session.status}")
        
        try:
            # Prepare execution environment
            if globals_dict is None:
                globals_dict = {}
            
            # Add safe builtins
            safe_builtins = {
                '__builtins__': {
                    'print': print,
                    'len': len,
                    'str': str,
                    'int': int,
                    'float': float,
                    'bool': bool,
                    'list': list,
                    'dict': dict,
                    'tuple': tuple,
                    'set': set,
                    'range': range,
                    'enumerate': enumerate,
                    'zip': zip,
                    'min': min,
                    'max': max,
                    'sum': sum,
                    'sorted': sorted,
                    'reversed': reversed,
                    'abs': abs,
                    'round': round,
                    'any': any,
                    'all': all,
                    'isinstance': isinstance,
                    'type': type,
                    'Exception': Exception,
                    'ValueError': ValueError,
                    'TypeError': TypeError,
                    'KeyError': KeyError,
                    'AttributeError': AttributeError,
                    'ImportError': ImportError,
                    'ModuleNotFoundError': ModuleNotFoundError
                }
            }
            
            # Add allowed modules
            import datetime
            import time
            import json
            import math
            import random
            import logging
            
            safe_modules = {
                'datetime': datetime,
                'time': time,
                'json': json,
                'math': math,
                'random': random,
                'logging': logging
            }
            
            globals_dict.update(safe_builtins)
            globals_dict.update(safe_modules)
            
            # Execute code
            start_time = time.time()
            session.status = "running"
            
            try:
                result = eval(code, globals_dict)
                execution_time = time.time() - start_time
                session.execution_time = execution_time
                
                # Update stats
                self._update_execution_stats(execution_time)
                
                return result
                
            except Exception as e:
                execution_time = time.time() - start_time
                session.execution_time = execution_time
                
                self._record_violation(session, "execution_error", {
                    "error": str(e),
                    "execution_time": execution_time
                })
                
                raise e
            
            finally:
                session.status = "completed"
                session.last_activity = datetime.now()
        
        except Exception as e:
            session.status = "error"
            session.last_activity = datetime.now()
            self.logger.error(f"Sandbox execution error: {e}")
            raise
    
    def execute_command_in_sandbox(self, session_id: str, command: str, 
                                  args: List[str] = None, env: Dict[str, str] = None) -> Dict[str, Any]:
        """Execute command in sandbox"""
        if session_id not in self.sessions:
            raise ValueError("Session not found")
        
        session = self.sessions[session_id]
        
        if session.status != "created":
            raise ValueError(f"Session not in created state: {session.status}")
        
        try:
            # Prepare command
            if args is None:
                args = []
            
            # Prepare environment
            if env is None:
                env = {}
            
            # Restrict environment
            safe_env = {
                'PATH': '/usr/bin:/bin',
                'HOME': session.temp_dir,
                'TMPDIR': session.temp_dir,
                'PYTHONPATH': session.temp_dir
            }
            safe_env.update(env)
            
            # Execute command
            session.status = "running"
            start_time = time.time()
            
            process = subprocess.Popen(
                [command] + args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=safe_env,
                cwd=session.temp_dir,
                preexec_fn=self._setup_sandbox_limits(session)
            )
            
            session.process_id = process.pid
            self.active_processes[process.pid] = session
            
            try:
                stdout, stderr = process.communicate(timeout=session.limits.max_cpu_time)
                execution_time = time.time() - start_time
                session.execution_time = execution_time
                
                # Update stats
                self._update_execution_stats(execution_time)
                
                result = {
                    "return_code": process.returncode,
                    "stdout": stdout.decode('utf-8'),
                    "stderr": stderr.decode('utf-8'),
                    "execution_time": execution_time
                }
                
                session.status = "completed"
                session.last_activity = datetime.now()
                
                return result
                
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                
                self._record_violation(session, "timeout", {
                    "limit": session.limits.max_cpu_time,
                    "execution_time": time.time() - start_time
                })
                
                session.status = "timeout"
                session.last_activity = datetime.now()
                
                return {
                    "return_code": -1,
                    "stdout": "",
                    "stderr": "Command timed out",
                    "execution_time": time.time() - start_time
                }
            
            finally:
                if process.pid in self.active_processes:
                    del self.active_processes[process.pid]
        
        except Exception as e:
            session.status = "error"
            session.last_activity = datetime.now()
            self.logger.error(f"Sandbox command execution error: {e}")
            raise
    
    def _setup_sandbox_limits(self, session: SandboxSession):
        """Setup resource limits for sandbox"""
        def setup_limits():
            # Set CPU time limit
            if session.limits.max_cpu_time != float('inf'):
                resource.setrlimit(resource.RLIMIT_CPU, (session.limits.max_cpu_time, session.limits.max_cpu_time))
            
            # Set memory limit
            if session.limits.max_memory != sys.maxsize:
                resource.setrlimit(resource.RLIMIT_AS, (session.limits.max_memory, session.limits.max_memory))
            
            # Set file size limit
            if session.limits.max_disk_space != sys.maxsize:
                resource.setrlimit(resource.RLIMIT_FSIZE, (session.limits.max_disk_space, session.limits.max_disk_space))
            
            # Set process limit
            if session.limits.max_processes != sys.maxsize:
                resource.setrlimit(resource.RLIMIT_NPROC, (session.limits.max_processes, session.limits.max_processes))
            
            # Set file descriptor limit
            if session.limits.max_file_descriptors != sys.maxsize:
                resource.setrlimit(resource.RLIMIT_NOFILE, (session.limits.max_file_descriptors, session.limits.max_file_descriptors))
        
        return setup_limits
    
    def _update_execution_stats(self, execution_time: float):
        """Update execution statistics"""
        if self.stats["total_sessions"] > 0:
            total_time = self.stats["average_execution_time"] * (self.stats["total_sessions"] - 1) + execution_time
            self.stats["average_execution_time"] = total_time / self.stats["total_sessions"]
    
    def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session information"""
        if session_id not in self.sessions:
            return None
        
        session = self.sessions[session_id]
        
        return {
            "session_id": session.session_id,
            "plugin_id": session.plugin_id,
            "policy": session.policy.value,
            "status": session.status,
            "created_at": session.created_at.isoformat(),
            "last_activity": session.last_activity.isoformat(),
            "process_id": session.process_id,
            "execution_time": session.execution_time,
            "resource_usage": session.resource_usage,
            "violations": session.violations,
            "limits": asdict(session.limits)
        }
    
    def list_sessions(self, plugin_id: str = None, status: str = None) -> List[Dict[str, Any]]:
        """List sandbox sessions"""
        sessions = []
        
        for session in self.sessions.values():
            if plugin_id and session.plugin_id != plugin_id:
                continue
            
            if status and session.status != status:
                continue
            
            sessions.append({
                "session_id": session.session_id,
                "plugin_id": session.plugin_id,
                "policy": session.policy.value,
                "status": session.status,
                "created_at": session.created_at.isoformat(),
                "execution_time": session.execution_time,
                "violation_count": len(session.violations)
            })
        
        return sessions
    
    def terminate_session(self, session_id: str) -> bool:
        """Terminate sandbox session"""
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        
        try:
            # Terminate process
            if session.process_id:
                process = psutil.Process(session.process_id)
                process.terminate()
                
                try:
                    process.wait(timeout=5)
                except psutil.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            
            # Clean up temp directory
            if session.temp_dir and os.path.exists(session.temp_dir):
                shutil.rmtree(session.temp_dir)
            
            # Remove from active sessions
            del self.sessions[session_id]
            self.stats["active_sessions"] -= 1
            
            self.logger.info(f"Sandbox session terminated: {session_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error terminating session {session_id}: {e}")
            return False
    
    def cleanup_expired_sessions(self, max_age_hours: int = 24) -> int:
        """Clean up expired sessions"""
        expired_sessions = []
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        
        for session_id, session in self.sessions.items():
            if session.created_at < cutoff_time and session.status in ["completed", "terminated", "error"]:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            self.terminate_session(session_id)
        
        if expired_sessions:
            self.logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
        
        return len(expired_sessions)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get sandbox statistics"""
        self.stats["active_sessions"] = len([s for s in self.sessions.values() if s.status == "running"])
        return self.stats.copy()
    
    async def cleanup(self):
        """Cleanup sandbox resources"""
        self.logger.info("Cleaning up sandbox...")
        
        # Stop monitoring
        self.stop_monitoring()
        
        # Terminate all sessions
        for session_id in list(self.sessions.keys()):
            self.terminate_session(session_id)
        
        # Clear data
        self.sessions.clear()
        self.active_processes.clear()
        
        self.logger.info("Sandbox cleanup complete")
