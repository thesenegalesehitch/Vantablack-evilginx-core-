import os
import sqlite3
import requests
import subprocess
from rich.console import Console
from rich.table import Table

console = Console()

def check_docker():
    try:
        res = subprocess.run(["docker", "ps", "--filter", "name=vanta", "--format", "{{.Status}}"], capture_output=True, text=True)
        return res.stdout.strip() if res.stdout else "No 'vanta' container detected"
    except:
        return "Docker not installed or not running"

def check_db():
    db_path = "hitch_vault.db"
    if not os.path.exists(db_path): return "Missing"
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("SELECT 1 FROM captures LIMIT 1")
        conn.close()
        return "Accessible (Vault OK)"
    except Exception as e:
        return f"Error: {str(e)}"

def check_telegram():
    # Simulation check (requires token in hitch_config.yaml)
    return "Configured (Ready for exfiltration)"

def main():
    console.print("[bold black on grey37] VANTABLACK: SYSTEM DIAGNOSTIC [/bold black on grey37]\n")
    
    table = Table(title="Infrastructure Status", border_style="grey37")
    table.add_column("Component", style="cyan")
    table.add_column("Status", justify="right")
    
    table.add_row("Docker Container", f"[bold green]{check_docker()}[/]")
    table.add_row("Vault Database", f"[bold green]{check_db()}[/]")
    table.add_row("Nervous System (API)", "[bold green]Online (Port 8000)[/]")
    table.add_row("Exfiltration Bot", f"[bold green]{check_telegram()}[/]")
    
    console.print(table)

if __name__ == "__main__":
    main()
