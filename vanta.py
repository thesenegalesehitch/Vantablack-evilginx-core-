#!/usr/bin/env python3
import os
import sys
import subprocess
import time
import signal
import platform
import threading
import httpx
from typing import List, Dict
import psutil
from core.banner import print_alex_banner

def print_banner():
    print_alex_banner()

LANGUAGE = "EN"
TRANSLATIONS: Dict[str, Dict[str, str]] = {
    "EN": {
        "menu_title": "[*] VANTABLACK Interactive Menu",
        "menu_options": "1) List Features\n2) Start Services\n3) Open API Docs\n4) Configuration\n5) Logs Access\n6) Language Switch (EN/FR)\n7) Ghost Protocol\n8) Quishing Generator\n9) Generate Report\n10) Run Network Module (Proxy)\n11) Run Templates\n12) Analyze Phishlets\n13) Auto Setup\n14) System Info\n15) God Mode\n0) Exit",
        "prompt": "Select an option: ",
        "features_header": "[*] Available Features",
        "features": "- API Server (FastAPI)\n- Frontend Dashboard (React)\n- Template System\n- Behavioral Analysis\n- Mutation Engine\n- Reverse Engineering\n- OSINT Workers\n- Terraform Infrastructure\n- Ghost Protocol\n- War Room Dashboard",
        "starting_services": "[*] Starting services...",
        "services_started": "[+] Services started",
        "api_docs_opened": "[+] Opening API docs",
        "config_header": "[*] Current Configuration",
        "logs_header": "[*] Logs",
        "logs_missing": "[!] No log file configured. View console output.",
        "switch_lang": "[+] Language switched",
        "ghost_triggered": "[+] Ghost Protocol triggered",
        "enter_url": "Enter URL: ",
        "report_generated": "[+] Report generation triggered",
        "invalid_option": "[!] Invalid option",
        "stopping_services": "[*] Stopping services...",
        "services_stopped": "[+] Services stopped",
        "health_check": "[*] API Health Check",
        "health_ok": "[+] API healthy",
        "health_fail": "[!] API not reachable",
        "enter_phishlet": "Enter phishlet name or path (e.g., twitter or phishlets/twitter.yaml): ",
        "starting_proxy": "[*] Starting proxy engine...",
        "proxy_started": "[+] Proxy engine started on port 8080",
        "enter_platform": "Enter platform (e.g., twitter, google): ",
        "enter_type": "Enter template type (login/register/payment/survey): ",
        "running_templates": "[*] Running template generation...",
        "templates_done": "[+] Template generation complete",
        "running_phishlets": "[*] Running phishlet analysis...",
        "phishlets_done": "[+] Phishlet analysis complete",
        "auto_setup": "[*] Auto setup in progress...",
        "setup_done": "[+] Setup complete",
        "system_info_header": "[*] System Info",
        "os_name": "OS:",
        "os_version": "Version:",
        "python_version": "Python:",
        "node_version": "Node:",
        "cpu_cores": "CPU cores:",
        "mem_total": "Memory:",
        "godmode_start": "[*] Starting God Mode...",
        "godmode_done": "[+] God Mode active",
    },
    "FR": {
        "menu_title": "[*] Menu Interactif VANTABLACK",
        "menu_options": "1) Lister les fonctionnalités\n2) Démarrer les services\n3) Ouvrir la documentation API\n4) Configuration\n5) Accès aux logs\n6) Changer la langue (EN/FR)\n7) Ghost Protocol\n8) Générateur Quishing\n9) Générer le rapport\n10) Lancer le module réseau (Proxy)\n11) Exécuter les templates\n12) Analyser les phishlets\n13) Installation automatique\n14) Infos système\n15) God Mode\n0) Quitter",
        "prompt": "Sélectionnez une option : ",
        "features_header": "[*] Fonctionnalités disponibles",
        "features": "- Serveur API (FastAPI)\n- Tableau de bord Frontend (React)\n- Système de templates\n- Analyse comportementale\n- Moteur de mutation\n- Ingénierie inverse\n- Workers OSINT\n- Infrastructure Terraform\n- Ghost Protocol\n- Tableau de bord War Room",
        "starting_services": "[*] Démarrage des services...",
        "services_started": "[+] Services démarrés",
        "api_docs_opened": "[+] Ouverture de la documentation API",
        "config_header": "[*] Configuration actuelle",
        "logs_header": "[*] Logs",
        "logs_missing": "[!] Aucun fichier de logs configuré. Voir la console.",
        "switch_lang": "[+] Langue changée",
        "ghost_triggered": "[+] Ghost Protocol déclenché",
        "enter_url": "Entrez l'URL : ",
        "report_generated": "[+] Génération du rapport déclenchée",
        "invalid_option": "[!] Option invalide",
        "stopping_services": "[*] Arrêt des services...",
        "services_stopped": "[+] Services arrêtés",
        "health_check": "[*] Vérification de santé de l'API",
        "health_ok": "[+] API opérationnelle",
        "health_fail": "[!] API inaccessible",
        "enter_phishlet": "Entrez le nom ou chemin du phishlet (ex: twitter ou phishlets/twitter.yaml) : ",
        "starting_proxy": "[*] Démarrage du moteur proxy...",
        "proxy_started": "[+] Moteur proxy démarré sur le port 8080",
        "enter_platform": "Entrez la plateforme (ex: twitter, google) : ",
        "enter_type": "Entrez le type de template (login/register/payment/survey) : ",
        "running_templates": "[*] Exécution de la génération de template...",
        "templates_done": "[+] Génération de template terminée",
        "running_phishlets": "[*] Analyse des phishlets...",
        "phishlets_done": "[+] Analyse des phishlets terminée",
        "auto_setup": "[*] Installation automatique en cours...",
        "setup_done": "[+] Installation terminée",
        "system_info_header": "[*] Informations système",
        "os_name": "Système:",
        "os_version": "Version:",
        "python_version": "Python:",
        "node_version": "Node:",
        "cpu_cores": "CPU:",
        "mem_total": "Mémoire:",
        "godmode_start": "[*] Démarrage du God Mode...",
        "godmode_done": "[+] God Mode actif",
    },
}

def T(key: str) -> str:
    return TRANSLATIONS.get(LANGUAGE, TRANSLATIONS["EN"]).get(key, key)

class ProcessManager:
    def __init__(self):
        self.processes: List[subprocess.Popen] = []
    def add(self, p: subprocess.Popen):
        self.processes.append(p)
    def stop_all(self):
        for p in self.processes:
            try:
                p.terminate()
            except Exception:
                pass
        self.processes = []

def check_dependencies():
    print("[*] Checking dependencies...")
    
    # Check Python
    if sys.version_info < (3, 9):
        print("[!] Python 3.9+ is required.")
        sys.exit(1)
        
    # Check Node.js
    try:
        subprocess.run(["node", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        print("[!] Node.js is not installed. Please install Node.js (v16+) for the frontend.")
        sys.exit(1)

    print("[+] All core dependencies found.")

def setup():
    print("\n[*] Starting Setup Process...")
    
    # Install Python deps
    print("[*] Installing Python dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements-v4.txt"])
    
    # Install Frontend deps
    print("[*] Installing Frontend dependencies (this may take a while)...")
    frontend_dir = os.path.join(os.getcwd(), "web", "frontend")
    if os.path.exists(frontend_dir):
        os.chdir(frontend_dir)
        if platform.system() == "Windows":
            subprocess.check_call(["npm.cmd", "install"])
        else:
            subprocess.check_call(["npm", "install"])
        os.chdir(os.path.dirname(os.path.dirname(os.getcwd()))) # Go back to root
    else:
        print(f"[!] Frontend directory not found at {frontend_dir}")
    
    print("\n[+] Setup Complete! You can now run Vantablack.")

def start_api_server() -> subprocess.Popen:
    from core.config import settings
    cmd = [
        sys.executable, "-m", "uvicorn",
        "api.rest_api:app",
        "--host", "0.0.0.0",
        "--port", "8000",
        "--reload"
    ]
    if settings.ENABLE_TLS and settings.TLS_CERT_PATH and settings.TLS_KEY_PATH:
        cmd.extend(["--ssl-certfile", settings.TLS_CERT_PATH, "--ssl-keyfile", settings.TLS_KEY_PATH])
    return subprocess.Popen(cmd)

def start_frontend() -> subprocess.Popen:
    frontend_dir = os.path.join(os.getcwd(), "web", "frontend")
    cmd = ["npm.cmd", "start"] if platform.system() == "Windows" else ["npm", "start"]
    return subprocess.Popen(cmd, cwd=frontend_dir)

def start_proxy_engine(phishlet: str) -> subprocess.Popen:
    env = os.environ.copy()
    env["PHISHLET"] = phishlet
    return subprocess.Popen([sys.executable, "engine/proxy.py"], env=env)

def run_templates_cli(platform: str, template_type: str):
    print(T("running_templates"))
    cmd = [
        sys.executable, "templates/cli.py",
        "generate", "--platform", platform, "--type", template_type, "--responsive"
    ]
    try:
        subprocess.run(cmd, check=False)
    finally:
        print(T("templates_done"))

def run_phishlets_analysis(path: str):
    print(T("running_phishlets"))
    cmd = [
        sys.executable, "analysis/reverse_engineer/cli.py",
        "analyze", path, "--format", "json"
    ]
    try:
        subprocess.run(cmd, check=False)
    finally:
        print(T("phishlets_done"))

def open_url(url: str):
    if platform.system() == "Darwin":
        subprocess.run(["open", url])
    elif platform.system() == "Windows":
        os.startfile(url)
    else:
        subprocess.run(["xdg-open", url])

def api_health_check() -> bool:
    try:
        with httpx.Client(timeout=3.0) as client:
            r = client.get("http://127.0.0.1:8000/health")
            return r.status_code == 200
    except Exception:
        return False

def mask_value(v: str) -> str:
    if not isinstance(v, str):
        return str(v)
    if len(v) <= 8:
        return "*" * len(v)
    return v[:4] + "*" * (len(v) - 8) + v[-4:]

def show_configuration():
    try:
        from core.config import settings
        print(T("config_header"))
        print("REDIS_URL:", settings.REDIS_URL)
        print("OLLAMA_API_URL:", settings.OLLAMA_API_URL)
        print("DEFAULT_LLM_MODEL:", settings.DEFAULT_LLM_MODEL)
        print("SECRET_KEY:", mask_value(settings.SECRET_KEY))
        print("C2_DEFAULT_ENCRYPTION_KEY:", mask_value(settings.C2_DEFAULT_ENCRYPTION_KEY))
    except Exception:
        print("[!] Configuration unavailable")

def show_logs():
    print(T("logs_header"))
    log_file = os.path.join(os.getcwd(), "vantablack.log")
    if os.path.exists(log_file):
        try:
            with open(log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()[-100:]
                for line in lines:
                    print(line.rstrip())
        except Exception:
            print(T("logs_missing"))
    else:
        print(T("logs_missing"))

def perform_auto_setup():
    print(T("auto_setup"))
    check_dependencies()
    setup()
    print(T("setup_done"))

def show_system_info():
    print(T("system_info_header"))
    try:
        os_name = platform.system()
        os_ver = platform.release()
        py_ver = sys.version.split()[0]
        try:
            node_ver = subprocess.check_output(["node", "--version"]).decode().strip()
        except Exception:
            node_ver = "not installed"
        cpu = psutil.cpu_count(logical=True)
        mem = round(psutil.virtual_memory().total / (1024**3), 2)
        print(T("os_name"), os_name)
        print(T("os_version"), os_ver)
        print(T("python_version"), py_ver)
        print(T("node_version"), node_ver)
        print(T("cpu_cores"), cpu)
        print(T("mem_total"), f"{mem} GB")
    except Exception:
        print("[!] Unable to fetch system info")

def list_features():
    print(T("features_header"))
    print(T("features"))
    print(T("health_check"))
    print(T("health_ok") if api_health_check() else T("health_fail"))

def interactive_menu():
    manager = ProcessManager()
    while True:
        print("\n" + T("menu_title"))
        print(T("menu_options"))
        choice = input(T("prompt")).strip()
        if choice == "1":
            list_features()
        elif choice == "2":
            print(T("starting_services"))
            api_p = start_api_server()
            manager.add(api_p)
            time.sleep(1)
            fe_p = start_frontend()
            manager.add(fe_p)
            print(T("services_started"))
        elif choice == "3":
            print(T("api_docs_opened"))
            open_url("http://localhost:8000/docs")
        elif choice == "4":
            show_configuration()
        elif choice == "5":
            show_logs()
        elif choice == "6":
            global LANGUAGE
            LANGUAGE = "FR" if LANGUAGE == "EN" else "EN"
            print(T("switch_lang"))
        elif choice == "7":
            trigger_ghost_protocol()
            print(T("ghost_triggered"))
        elif choice == "8":
            url = input(T("enter_url")).strip()
            if url:
                trigger_quishing(url)
        elif choice == "9":
            trigger_report()
            print(T("report_generated"))
        elif choice == "10":
            phishlet = input(T("enter_phishlet")).strip() or "phishlets/twitter.yaml"
            print(T("starting_proxy"))
            proxy_p = start_proxy_engine(phishlet)
            manager.add(proxy_p)
            print(T("proxy_started"))
        elif choice == "11":
            platform = input(T("enter_platform")).strip() or "twitter"
            template_type = input(T("enter_type")).strip() or "login"
            run_templates_cli(platform, template_type)
        elif choice == "12":
            phishlet_path = input(T("enter_phishlet")).strip() or "phishlets/twitter.yaml"
            run_phishlets_analysis(phishlet_path)
        elif choice == "13":
            perform_auto_setup()
        elif choice == "14":
            show_system_info()
        elif choice == "15":
            print(T("godmode_start"))
            subprocess.Popen([sys.executable, "godmode.py"])
            print(T("godmode_done"))
        elif choice == "0":
            print(T("stopping_services"))
            manager.stop_all()
            print(T("services_stopped"))
            break
        else:
            print(T("invalid_option"))

def run(war_room=False, proxy_phishlet=None):
    print("\n[*] Launching VANTABLACK...")
    
    processes = []
    
    # Start Backend
    print("[*] Starting API Server...")
    # Run uvicorn as a module to handle imports correctly
    backend_process = subprocess.Popen([
        sys.executable, "-m", "uvicorn", 
        "api.rest_api:app", 
        "--host", "0.0.0.0", 
        "--port", "8000",
        "--reload"
    ])
    processes.append(backend_process)
    
    # Start Proxy Engine if requested
    if proxy_phishlet:
        print(f"\033[93m[*] STARTING PROXY ENGINE (Target: {proxy_phishlet})...\033[0m")
        proxy_env = os.environ.copy()
        proxy_env["PHISHLET"] = proxy_phishlet
        proxy_process = subprocess.Popen([
            sys.executable, "engine/proxy.py"
        ], env=proxy_env)
        processes.append(proxy_process)
    
    if war_room:
        print("\033[92m[*] INITIALIZING WAR ROOM DASHBOARD...\033[0m")
        war_room_path = os.path.abspath("templates/war_room.html")
        if platform.system() == "Darwin": # macOS
            try:
                subprocess.run(["open", war_room_path])
            except:
                pass
        elif platform.system() == "Windows":
            try:
                os.startfile(war_room_path)
            except:
                pass
        else: # Linux
            try:
                subprocess.run(["xdg-open", war_room_path])
            except:
                pass
            
        print("[+] WAR ROOM ACTIVE.")
    
    # Start Frontend
    print("[*] Starting Frontend Dashboard...")
    frontend_dir = os.path.join(os.getcwd(), "web", "frontend")
    os.chdir(frontend_dir)
    
    if platform.system() == "Windows":
        frontend_cmd = ["npm.cmd", "start"]
    else:
        frontend_cmd = ["npm", "start"]
        
    frontend_process = subprocess.Popen(frontend_cmd)
    processes.append(frontend_process)
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        for p in processes:
            p.terminate()
        sys.exit(0)

def trigger_ghost_protocol():
    """Execute Ghost Protocol directly"""
    script_path = os.path.join(os.getcwd(), "ghost_protocol.py")
    if os.path.exists(script_path):
        subprocess.run([sys.executable, script_path])
    else:
        print("[!] Ghost Protocol script not found.")

def trigger_quishing(url):
    """Execute Quishing Generator directly"""
    script_path = os.path.join(os.getcwd(), "quishing.py")
    if os.path.exists(script_path):
        subprocess.run([sys.executable, script_path, "--url", url])
    else:
        print("[!] Quishing script not found.")

def trigger_report():
    """Generate Professional Audit Report"""
    script_path = os.path.join(os.getcwd(), "reporting.py")
    if os.path.exists(script_path):
        subprocess.run([sys.executable, script_path])
        # Open report automatically
        report_path = os.path.abspath("AUDIT_REPORT_FINAL.html")
        if platform.system() == "Darwin":
            subprocess.run(["open", report_path])
        elif platform.system() == "Windows":
            os.startfile(report_path)
        else:
            subprocess.run(["xdg-open", report_path])
    else:
        print("[!] Reporting script not found.")

def trigger_safe_mode():
    """Launch Safe Mode Self-Audit"""
    script_path = os.path.join(os.getcwd(), "safe_mode.py")
    if os.path.exists(script_path):
        # We run it directly to capture output in this terminal
        subprocess.run([sys.executable, script_path])
    else:
        print("[!] Safe Mode script not found.")

def trigger_demo():
    """Launch The Final Show (Auto Demo Mode)"""
    print("\n\033[95m[*] INITIATING LEGENDARY DEMO SEQUENCE...\033[0m")
    time.sleep(1)
    
    # 1. Start War Room in Background
    print("[*] Phase 1: War Room Activation")
    war_room_path = os.path.abspath("templates/war_room.html")
    if platform.system() == "Darwin":
        subprocess.Popen(["open", war_room_path])
    elif platform.system() == "Windows":
        os.startfile(war_room_path)
    else:
        subprocess.Popen(["xdg-open", war_room_path])
    time.sleep(3)
    
    # 2. Simulate Attack Traffic
    print("[*] Phase 2: Simulating Global Traffic Injection...")
    for i in range(5):
        print(f"    [+] Injecting packet {i+1}/5 from compromised node...")
        time.sleep(0.5)
        
    # 3. Generate Report
    print("[*] Phase 3: Compiling Evidence (Audit Report)...")
    trigger_report()
    
    print("\n\033[92m[SUCCESS] DEMO COMPLETE. GRANDMA WOULD BE PROUD. ❤️\033[0m")

def main():
    print_banner()
    
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        
        if cmd == "--setup":
            check_dependencies()
            setup()
            
        elif cmd == "--war-room":
            run(war_room=True)
            
        elif cmd == "--proxy":
            if len(sys.argv) < 3:
                print("Usage: python3 vanta.py --proxy <phishlet_path>")
                sys.exit(1)
            phishlet = sys.argv[2]
            run(proxy_phishlet=phishlet)
            
        elif cmd == "--ghost":
            trigger_ghost_protocol()
            
        elif cmd == "--quishing":
            if len(sys.argv) < 3:
                print("Usage: python3 vanta.py --quishing <URL>")
                sys.exit(1)
            url = sys.argv[2]
            trigger_quishing(url)
            
        elif cmd == "--report":
            trigger_report()
            
        elif cmd == "--demo":
            trigger_demo()
            
        elif cmd == "--self-test":
            trigger_safe_mode()
            
        else:
            interactive_menu()
    else:
        interactive_menu()

if __name__ == "__main__":
    main()
