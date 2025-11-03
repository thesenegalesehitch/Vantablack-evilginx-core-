import sqlite3
import json
import os
import sys

def export_vault(db_path="hitch_vault.db", output_path="vault_export.json"):
    """
    EXPORTS the data from the SQLite vault to a JSON format.
    WHY: Forensic analysis and archiving of attack signatures.
    """
    if not os.path.exists(db_path):
        print(f"[!] Error: Database {db_path} not found.")
        return False

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Retrieving captures
        cursor.execute("SELECT * FROM captures")
        captures = [dict(row) for row in cursor.fetchall()]
        
        # Retrieving system logs
        cursor.execute("SELECT * FROM system_logs")
        logs = [dict(row) for row in cursor.fetchall()]
        
        data = {
            "metadata": {
                "project": "VANTABLACK",
                "export_date": str(sqlite3.datetime.datetime.now()),
                "vault_source": db_path
            },
            "captures": captures,
            "system_logs": logs
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
            
        print(f"[✓] Vault successfully exported to {output_path}")
        return True
    except Exception as e:
        print(f"[!] Error during exportation: {e}")
        return False

if __name__ == "__main__":
    export_vault()
