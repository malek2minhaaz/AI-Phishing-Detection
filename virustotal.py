import requests
import base64
import time


API_KEY = "d0584a6660da67ee5be2eebe81e2fff62ac9e7ef6b4522b7b198773bf1816e65"


def scan_url_virustotal(url):

    headers = {

        "x-apikey": API_KEY

    }

    # STEP 1 — SUBMIT URL
    submit_url = "https://www.virustotal.com/api/v3/urls"

    response = requests.post(

        submit_url,

        headers=headers,

        data={"url": url}

    )

    if response.status_code != 200:

        return {

            "error": "Failed to submit URL to VirusTotal"

        }

    # ENCODE URL
    url_id = base64.urlsafe_b64encode(

        url.encode()

    ).decode().strip("=")

    # WAIT FOR ANALYSIS
    time.sleep(3)

    # STEP 2 — FETCH REPORT
    report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    report_response = requests.get(

        report_url,

        headers=headers

    )

    if report_response.status_code != 200:

        return {

            "error": "Unable to fetch VirusTotal data"

        }

    data = report_response.json()

    stats = data["data"]["attributes"]["last_analysis_stats"]

    reputation = data["data"]["attributes"].get(

        "reputation",

        0

    )

    return {

        "malicious": stats.get("malicious", 0),

        "suspicious": stats.get("suspicious", 0),

        "harmless": stats.get("harmless", 0),

        "undetected": stats.get("undetected", 0),

        "reputation": reputation

    }