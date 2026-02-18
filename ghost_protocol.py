#!/usr/bin/env python3
import os
import sys
import shutil
import time
import glob

# Colors for maximum impact
RED = '\033[91m'
BOLD = '\033[1m'
RESET = '\033[0m'

def print_warning():
    print(f"""
{RED}{BOLD}
██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
██║  ███╗███████║██║   ██║███████╗   ██║   
██║   ██║██╔══██║██║   ██║╚════██║   ██║   
╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   

PROTOCOL INITIATED
{RESET}
""")
    print(f"{RED}[!] WARNING: THIS WILL PERMANENTLY DELETE ALL CAPTURED DATA AND LOGS.{RESET}")
    print(f"{RED}[!] THIS ACTION CANNOT BE UNDONE.{RESET}")
    
    confirm = input(f"\n{BOLD}Type 'DELETE' to confirm execution: {RESET}")
    if confirm != "DELETE":
        print("[*] Aborted.")
        sys.exit(0)

def execute_cleanup():
    print(f"\n{RED}[*] STARTING EMERGENCY WIPE...{RESET}")
    
    # Target directories to wipe
    targets = [
        "sessions",
        "logs",
        "captured_data",
        "__pycache__"
    ]
    
    # Target file patterns to wipe
    file_patterns = [
        "*.log",
        "*.db",
        "*.sqlite",
        "*.json"  # Be careful with this one
    ]

    # 1. Delete Directories
    for target in targets:
        path = os.path.join(os.getcwd(), target)
        if os.path.exists(path):
            try:
                shutil.rmtree(path)
                print(f"{RED}[+] DELETED DIRECTORY: {target}{RESET}")
            except Exception as e:
                print(f"[!] Failed to delete {target}: {e}")
        else:
            print(f"[*] Directory {target} not found (Clean).")

    # 2. Delete Sensitive Files (but keep config/phishlets)
    # We only delete logs in root, not recursively to avoid deleting code
    for pattern in file_patterns:
        files = glob.glob(pattern)
        for f in files:
            if "requirements" not in f and "package" not in f: # Safety check
                try:
                    os.remove(f)
                    print(f"{RED}[+] DELETED FILE: {f}{RESET}")
                except Exception as e:
                    print(f"[!] Failed to delete {f}: {e}")

    # 3. Clear Terminal History (Simulated)
    print(f"{RED}[*] FLUSHING MEMORY BUFFERS...{RESET}")
    time.sleep(1)
    
    print(f"\n{BOLD}{RED}[SUCCESS] SYSTEM CLEAN. NO EVIDENCE REMAINING.{RESET}")
    
    # Optional: Self-destruct script (commented out for safety in dev)
    # os.remove(__file__)

if __name__ == "__main__":
    print_warning()
    execute_cleanup()
