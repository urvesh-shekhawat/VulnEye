import os
import sqlite3
import json

# On Vercel, use /tmp/scans.db since root is read-only.
if os.environ.get("VERCEL"):
    DB_NAME = "/tmp/scans.db"
else:
    DB_NAME = "scans.db"

def init_db():
    db_dir = os.path.dirname(DB_NAME)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reachable TEXT,
            status_code TEXT,
            https TEXT,
            risk TEXT,
            raw_results TEXT
        )
    """)

    # Self-healing column addition for existing databases
    try:
        cursor.execute("ALTER TABLE scan_history ADD COLUMN raw_results TEXT")
    except sqlite3.OperationalError:
        # Column already exists
        pass

    conn.commit()
    conn.close()

def get_connection():
    # Automatically initialize DB if running on Vercel and it was wiped from ephemeral /tmp
    if DB_NAME.startswith("/tmp/") and not os.path.exists(DB_NAME):
        init_db()
    
    # Run a quick check/migration to ensure raw_results column is present
    conn = sqlite3.connect(DB_NAME)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT raw_results FROM scan_history LIMIT 1")
    except sqlite3.OperationalError:
        try:
            cursor.execute("ALTER TABLE scan_history ADD COLUMN raw_results TEXT")
            conn.commit()
        except:
            pass
    return conn

def save_scan(results):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scan_history (url, reachable, status_code, https, risk, raw_results)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        results["url"],
        str(results["reachable"]),
        str(results["status_code"]),
        str(results["https"]),
        results["risk"],
        json.dumps(results)
    ))

    conn.commit()
    conn.close()

def get_all_scans():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, url, scan_time, reachable, status_code, https, risk
        FROM scan_history
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()
    return rows

def get_latest_scan_results(url):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT raw_results FROM scan_history
        WHERE url = ?
        ORDER BY id DESC LIMIT 1
    """, (url,))

    row = cursor.fetchone()
    conn.close()

    if row and row[0]:
        try:
            return json.loads(row[0])
        except Exception:
            pass
    return None