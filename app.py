from flask import Flask, render_template, request
from datetime import datetime

import sqlite3

from model import detect_phishing

from email_model import detect_email_phishing

from virustotal import scan_url_virustotal


app = Flask(__name__)


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

    url = request.form.get(

        "url"

    )

    # AI PHISHING DETECTION
    result = detect_phishing(

        url

    )

    # VIRUSTOTAL ANALYSIS
    vt_result = scan_url_virustotal(

        url

    )

    # DATABASE CONNECTION
    conn = sqlite3.connect(

        "phishing.db"

    )

    cursor = conn.cursor()

    # SAVE SCAN HISTORY
    cursor.execute(

        """
        INSERT INTO scan_history(

            url,
            verdict,
            risk,
            score,
            scan_date

        )

        VALUES(?,?,?,?,?)
        """,

        (

            url,

            result["verdict"],

            result["risk"],

            result["score"],

            str(datetime.now())

        )

    )

    conn.commit()

    conn.close()

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

    conn = sqlite3.connect(

        "phishing.db"

    )

    cursor = conn.cursor()

    # ALL HISTORY
    cursor.execute(

        """
        SELECT *
        FROM scan_history
        ORDER BY id DESC
        """
    )

    scans = cursor.fetchall()

    # TOTAL SCANS
    cursor.execute(

        """
        SELECT COUNT(*)
        FROM scan_history
        """
    )

    total_scans = cursor.fetchone()[0]

    # PHISHING
    cursor.execute(

        """
        SELECT COUNT(*)
        FROM scan_history
        WHERE verdict='PHISHING'
        """
    )

    phishing_count = cursor.fetchone()[0]

    # SAFE
    cursor.execute(

        """
        SELECT COUNT(*)
        FROM scan_history
        WHERE verdict='SAFE'
        """
    )

    safe_count = cursor.fetchone()[0]

    # SUSPICIOUS
    cursor.execute(

        """
        SELECT COUNT(*)
        FROM scan_history
        WHERE verdict='SUSPICIOUS'
        """
    )

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

    email_text = request.form.get(

        "email_text"

    )

    # EMAIL PHISHING DETECTION
    result = detect_email_phishing(

        email_text

    )

    return render_template(

        "email_result.html",

        email_text=email_text,

        result=result

    )


# =========================
# RUN APPLICATION
# =========================

if __name__ == "__main__":

    app.run(

        debug=True

    )