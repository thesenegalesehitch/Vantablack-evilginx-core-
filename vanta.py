#!/usr/bin/env python3
import os
import sys
import subprocess
import time
import signal
import platform

def print_banner():
    print("""
██╗   ██╗ █████╗ ███╗   ██╗████████╗ █████╗ ██████╗ ██╗      █████╗  ██████╗██╗  ██╗
██║   ██║██╔══██╗████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝
██║   ██║███████║██╔██╗ ██║   ██║   ███████║██████╔╝██║     ███████║██║     █████╔╝ 
╚██╗ ██╔╝██╔══██║██║╚██╗██║   ██║   ██╔══██║██╔══██╗██║     ██╔══██║██║     ██╔═██╗ 
 ╚████╔╝ ██║  ██║██║ ╚████║   ██║   ██║  ██║██████╔╝███████╗██║  ██║╚██████╗██║  ██╗
  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
                                                                      v4.0.0
    """)

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

def run(war_room=False):
    print("\n[*] Launching VANTABLACK...")
    
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
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        backend_process.terminate()
        frontend_process.terminate()
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
            run()
    else:
        run()

if __name__ == "__main__":
    main()
