import sqlite3

DB_NAME = "scans.db"

def init_db():
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
            risk TEXT
        )
    """)

    conn.commit()
    conn.close()

def save_scan(results):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scan_history (url, reachable, status_code, https, risk)
        VALUES (?, ?, ?, ?, ?)
    """, (
        results["url"],
        str(results["reachable"]),
        str(results["status_code"]),
        str(results["https"]),
        results["risk"]
    ))

    conn.commit()
    conn.close()

def get_all_scans():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, url, scan_time, reachable, status_code, https, risk
        FROM scan_history
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()
    return rows