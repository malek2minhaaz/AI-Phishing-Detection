from flask import Flask, render_template, request
from datetime import datetime
import sqlite3
import os

from model import detect_phishing
from email_model import detect_email_phishing
from virustotal import scan_url_virustotal

app = Flask(__name__)


# =========================
# DATABASE SETUP
# =========================

def init_db():

    conn = sqlite3.connect("phishing.db")

    cursor = conn.cursor()

    cursor.execute("""

        CREATE TABLE IF NOT EXISTS scan_history (

            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            verdict TEXT,
            risk TEXT,
            score INTEGER,
            scan_date TEXT

        )

    """)

    conn.commit()
    conn.close()


# Initialize database automatically
init_db()


# =========================
# HOME PAGE
# =========================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# =========================
# URL ANALYSIS
# =========================

@app.route("/analyze", methods=["POST"])
def analyze():

    url = request.form.get("url")

    if not url:

        return render_template(
            "result.html",
            error="No URL provided"
        )

    # AI PHISHING DETECTION
    result = detect_phishing(url)

    # VIRUSTOTAL ANALYSIS
    try:

        vt_result = scan_url_virustotal(url)

    except Exception as e:

        vt_result = {
            "status": "Unable to fetch VirusTotal data",
            "error": str(e)
        }

    # SAVE HISTORY
    try:

        conn = sqlite3.connect("phishing.db")

        cursor = conn.cursor()

        cursor.execute("""

            INSERT INTO scan_history(

                url,
                verdict,
                risk,
                score,
                scan_date

            )

            VALUES(?,?,?,?,?)

        """, (

            url,
            result["verdict"],
            result["risk"],
            result["score"],
            str(datetime.now())

        ))

        conn.commit()
        conn.close()

    except Exception as e:

        print("Database Error:", e)

    return render_template(

        "result.html",

        url=url,
        result=result,
        vt_result=vt_result

    )


# =========================
# DASHBOARD
# =========================

@app.route("/dashboard")
def dashboard():

    conn = sqlite3.connect("phishing.db")

    cursor = conn.cursor()

    # GET ALL SCANS
    cursor.execute("""

        SELECT id, url, verdict, risk, score, scan_date
        FROM scan_history
        ORDER BY id DESC

    """)

    rows = cursor.fetchall()

    # CONVERT TUPLES TO DICTIONARY
    scans = []

    for row in rows:

        scans.append({

            "id": row[0],
            "url": row[1],
            "verdict": row[2],
            "risk": row[3],
            "score": row[4],
            "scan_date": row[5]

        })

    # TOTAL SCANS
    cursor.execute("SELECT COUNT(*) FROM scan_history")
    total_scans = cursor.fetchone()[0]

    # PHISHING
    cursor.execute("""

        SELECT COUNT(*)
        FROM scan_history
        WHERE verdict='PHISHING'

    """)

    phishing_count = cursor.fetchone()[0]

    # SAFE
    cursor.execute("""

        SELECT COUNT(*)
        FROM scan_history
        WHERE verdict='SAFE'

    """)

    safe_count = cursor.fetchone()[0]

    # SUSPICIOUS
    cursor.execute("""

        SELECT COUNT(*)
        FROM scan_history
        WHERE verdict='SUSPICIOUS'

    """)

    suspicious_count = cursor.fetchone()[0]

    conn.close()

    return render_template(

        "dashboard.html",

        scans=scans,
        total_scans=total_scans,
        phishing_count=phishing_count,
        safe_count=safe_count,
        suspicious_count=suspicious_count

    )


# =========================
# EMAIL DETECTOR PAGE
# =========================

@app.route("/email-detector")
def email_detector():

    return render_template(
        "email_detector.html"
    )


# =========================
# EMAIL ANALYSIS
# =========================

@app.route("/analyze-email", methods=["POST"])
def analyze_email():

    email_text = request.form.get("email_text")

    result = detect_email_phishing(email_text)

    return render_template(

        "email_result.html",

        email_text=email_text,
        result=result

    )


# =========================
# HEALTH CHECK
# =========================

@app.route("/health")
def health():

    return "App is running successfully!"


# =========================
# RUN APPLICATION
# =========================

if __name__ == "__main__":

    app.run()