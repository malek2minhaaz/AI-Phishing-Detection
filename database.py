import sqlite3

conn = sqlite3.connect("phishing.db")
cursor = conn.cursor()

# SCAN HISTORY TABLE — with scan_type to distinguish URL vs email scans
cursor.execute("""
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    verdict TEXT NOT NULL,
    risk TEXT NOT NULL,
    score INTEGER NOT NULL,
    scan_date TEXT NOT NULL,
    scan_type TEXT DEFAULT 'url'
)
""")

conn.commit()
conn.close()

print("Database created successfully!")
