import re
import joblib
import os
import requests

# LOAD TRAINED AI MODEL
model = joblib.load("phishing_model.pkl")

# LOAD TF-IDF VECTORIZER
vectorizer = joblib.load("vectorizer.pkl")

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")


def get_ai_intelligence(url, verdict, score, reasons):
    """Call Claude API for dynamic threat intelligence analysis."""
    if not ANTHROPIC_API_KEY:
        return _fallback_intelligence(verdict)

    prompt = f"""You are a cybersecurity expert. Analyze this URL scan result and give a concise, specific threat intelligence report.

URL: {url}
Verdict: {verdict}
Threat Score: {score}/100
Detection Indicators: {", ".join(reasons)}

Write 3-4 sentences of specific, actionable threat intelligence. Be direct and informative.
Focus on: what type of attack this likely is, what the attacker wants, and what the user should do.
Do NOT use bullet points. Write in plain paragraphs only."""

    try:
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            },
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 300,
                "messages": [{"role": "user", "content": prompt}]
            },
            timeout=10
        )
        data = response.json()
        if "content" in data and data["content"]:
            return data["content"][0]["text"].strip()
    except Exception:
        pass

    return _fallback_intelligence(verdict)


def _fallback_intelligence(verdict):
    if verdict == "PHISHING":
        return (
            "This URL shows multiple phishing indicators and poses a HIGH risk. "
            "Avoid entering any credentials, personal information, or payment details. "
            "Potential risks include credential theft, financial fraud, and malware infection. "
            "Do not click links or download files from this source."
        )
    elif verdict == "SUSPICIOUS":
        return (
            "This URL contains suspicious characteristics that warrant caution. "
            "Verify the website legitimacy through official channels before interacting. "
            "Proceed only if you initiated the request and trust the source."
        )
    return (
        "No major phishing indicators detected in this URL. "
        "The website appears relatively safe based on AI and heuristic analysis. "
        "Always practice good security hygiene regardless of scan results."
    )


def detect_phishing(url):
    if not url or not isinstance(url, str):
        return {
            "score": 0, "verdict": "ERROR", "risk": "UNKNOWN",
            "reasons": ["Invalid URL provided"],
            "ai_confidence": 0, "intelligence": "Could not analyze this URL."
        }

    url = url.strip()
    score = 0
    reasons = []

    # =========================
    # AI PREDICTION
    # =========================
    url_vector = vectorizer.transform([url])
    prediction = model.predict(url_vector)[0]
    probability = model.predict_proba(url_vector).max()
    ai_confidence = round(probability * 100, 2)

    # =========================
    # RULE-BASED ANALYSIS
    # =========================
    suspicious_keywords = [
        "login", "verify", "bank", "secure", "account", "update",
        "paypal", "free", "crypto", "bonus", "suspended", "alert",
        "confirm", "winner", "claim", "urgent", "recovery", "locked"
    ]

    for keyword in suspicious_keywords:
        if keyword in url.lower():
            score += 12
            reasons.append(f"Suspicious keyword: '{keyword}'")

    # LONG URL
    if len(url) > 75:
        score += 10
        reasons.append(f"Unusually long URL ({len(url)} characters)")

    # @ SYMBOL
    if "@" in url:
        score += 20
        reasons.append("@ symbol in URL (used to mask real destination)")

    # TOO MANY HYPHENS
    hyphen_count = url.count("-")
    if hyphen_count >= 3:
        score += 15
        reasons.append(f"Excessive hyphens ({hyphen_count}) — common phishing pattern")

    # IP ADDRESS — fixed regex (was double-escaped)
    ip_pattern = r"(\d{1,3}\.){3}\d{1,3}"
    if re.search(ip_pattern, url):
        score += 25
        reasons.append("IP address used instead of domain name")

    # SUSPICIOUS TLDs
    suspicious_tlds = [".xyz", ".net", ".tk", ".ml", ".ga", ".cf", ".gq"]
    for tld in suspicious_tlds:
        if url.lower().endswith(tld) or f"{tld}/" in url.lower():
            score += 15
            reasons.append(f"Suspicious top-level domain: {tld}")
            break

    # SUBDOMAIN ABUSE (legitimate brand in subdomain)
    brands = ["paypal", "amazon", "google", "apple", "microsoft", "netflix", "bank"]
    try:
        domain_part = url.split("/")[2] if "/" in url else url
        parts = domain_part.split(".")
        if len(parts) > 2:
            subdomain = ".".join(parts[:-2]).lower()
            for brand in brands:
                if brand in subdomain:
                    score += 20
                    reasons.append(f"Brand name '{brand}' used in subdomain (impersonation)")
                    break
    except Exception:
        pass

    # =========================
    # AI + RULE COMBINATION
    # =========================
    if prediction == "phishing":
        score += 35
        reasons.append(f"AI model classified as phishing (confidence: {ai_confidence}%)")
    else:
        reasons.append(f"AI model classified as safe (confidence: {ai_confidence}%)")

    # CAP SCORE
    score = min(score, 100)

    # =========================
    # FINAL VERDICT
    # =========================
    if score >= 60:
        verdict = "PHISHING"
        risk = "HIGH"
    elif score >= 30:
        verdict = "SUSPICIOUS"
        risk = "MEDIUM"
    else:
        verdict = "SAFE"
        risk = "LOW"

    # =========================
    # DYNAMIC AI INTELLIGENCE
    # =========================
    intelligence = get_ai_intelligence(url, verdict, score, reasons)

    return {
        "score": score,
        "verdict": verdict,
        "risk": risk,
        "reasons": reasons,
        "ai_confidence": ai_confidence,
        "intelligence": intelligence
    }
