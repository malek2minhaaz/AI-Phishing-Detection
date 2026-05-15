import os
import requests
import re


ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")


def get_ai_email_intelligence(email_snippet, verdict, score, reasons):
    """Call Claude API for dynamic email threat intelligence."""
    if not ANTHROPIC_API_KEY:
        return _fallback_intelligence(verdict)

    # Truncate email for API call (keep first 400 chars)
    snippet = email_snippet[:400] + ("..." if len(email_snippet) > 400 else "")

    prompt = f"""You are a cybersecurity expert specializing in email phishing analysis.

Email content (truncated): {snippet}

Analysis results:
- Verdict: {verdict}
- Threat Score: {score}/100
- Detected indicators: {", ".join(reasons) if reasons else "None"}

Write 3-4 sentences of specific, actionable threat intelligence about this email.
Identify the likely attack type (credential harvesting, spear phishing, business email compromise, etc.),
what the attacker is trying to achieve, and what the recipient should do.
Be direct and specific. No bullet points — plain paragraphs only."""

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
            "This email contains strong phishing indicators consistent with credential harvesting "
            "or social engineering attacks. The sender likely wants you to click a link or provide "
            "sensitive information under false pretenses. Do not click any links, download attachments, "
            "or reply with personal information. Report this to your IT/security team."
        )
    elif verdict == "SUSPICIOUS":
        return (
            "This email has suspicious characteristics that could indicate a phishing attempt. "
            "Verify the sender through an independent channel before taking any action. "
            "If the email claims to be from a known organization, contact them directly."
        )
    return (
        "No major phishing indicators detected in this email. "
        "It appears relatively safe based on content analysis. "
        "Always stay cautious about unexpected emails requesting action or personal information."
    )


def detect_email_phishing(email_text):
    if not email_text or not isinstance(email_text, str):
        return {
            "score": 0, "verdict": "ERROR", "risk": "UNKNOWN",
            "reasons": ["No email content provided"], "intelligence": "Could not analyze."
        }

    email_text = email_text.strip()
    score = 0
    reasons = []
    seen_reasons = set()

    def add_reason(text, points):
        nonlocal score
        if text not in seen_reasons:
            seen_reasons.add(text)
            score += points
            reasons.append(text)

    # PHISHING KEYWORDS
    phishing_keywords = [
        ("verify", 10), ("urgent", 10), ("suspended", 12), ("click here", 15),
        ("bank", 8), ("password", 12), ("login", 10), ("confirm", 8),
        ("limited time", 10), ("security alert", 12), ("update account", 12),
        ("free money", 15), ("crypto", 8), ("gift card", 12), ("otp", 10),
        ("winner", 12), ("congratulations", 10), ("lottery", 15), ("inheritance", 15),
        ("bitcoin", 8), ("wire transfer", 12), ("western union", 15),
        ("your account has been", 12), ("unauthorized access", 10),
        ("verify your identity", 12), ("claim your reward", 15)
    ]

    for keyword, points in phishing_keywords:
        if keyword.lower() in email_text.lower():
            add_reason(f"Phishing keyword detected: '{keyword}'", points)

    # LINKS
    url_count = len(re.findall(r"https?://", email_text))
    if url_count == 1:
        add_reason("Contains a URL — verify before clicking", 10)
    elif url_count > 1:
        add_reason(f"Multiple URLs detected ({url_count}) — common in phishing emails", 20)

    # URGENCY — deduplicated
    urgency_words = ["immediately", "urgent", "now", "asap", "within 24 hours", "expires soon", "act now"]
    urgency_found = [w for w in urgency_words if w.lower() in email_text.lower()]
    if urgency_found:
        add_reason(f"Urgency language detected: {', '.join(urgency_found[:3])}", 15)

    # EXCESSIVE CAPS
    words = email_text.split()
    if words:
        caps_ratio = sum(1 for w in words if w.isupper() and len(w) > 2) / len(words)
        if caps_ratio > 0.15:
            add_reason(f"Excessive ALL-CAPS text ({caps_ratio*100:.0f}% of words)", 10)

    # SUSPICIOUS SENDER PATTERNS
    if re.search(r"no[_-]?reply@(?!.*\.(com|org|net|gov|edu))", email_text, re.I):
        add_reason("Suspicious no-reply address pattern", 10)

    # PERSONAL INFO REQUESTS
    personal_requests = ["ssn", "social security", "credit card", "card number", "cvv", "date of birth", "mother's maiden"]
    for req in personal_requests:
        if req.lower() in email_text.lower():
            add_reason(f"Requests sensitive personal information: '{req}'", 20)
            break

    # CAP SCORE
    score = min(score, 100)

    # FINAL VERDICT
    if score >= 60:
        verdict = "PHISHING"
        risk = "HIGH"
    elif score >= 30:
        verdict = "SUSPICIOUS"
        risk = "MEDIUM"
    else:
        verdict = "SAFE"
        risk = "LOW"

    intelligence = get_ai_email_intelligence(email_text, verdict, score, reasons)

    return {
        "score": score,
        "verdict": verdict,
        "risk": risk,
        "reasons": reasons,
        "intelligence": intelligence
    }
