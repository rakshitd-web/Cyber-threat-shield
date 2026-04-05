import requests
import socket
import os
from urllib.parse import urlparse

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")


def check_virustotal(url: str) -> dict:
    """Check URL against VirusTotal. Returns dict with result."""
    if not VIRUSTOTAL_API_KEY:
        return {"available": False, "reason": "VirusTotal API key not set"}
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            return {
                "available": True,
                "malicious": malicious,
                "suspicious": suspicious,
                "total": total,
                "flagged": malicious > 0 or suspicious > 0
            }
        elif r.status_code == 404:
            # URL not in VT database yet, submit it
            r2 = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=10
            )
            return {"available": True, "malicious": 0, "suspicious": 0, "total": 0, "flagged": False, "note": "Newly submitted to VirusTotal"}
        else:
            return {"available": False, "reason": f"VT returned {r.status_code}"}
    except Exception as e:
        return {"available": False, "reason": str(e)}


def check_domain_age(domain: str) -> dict:
    """Check domain age via WHOIS."""
    try:
        import whois
        from datetime import datetime, timezone
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            age_days = (now - creation_date).days
            return {
                "available": True,
                "age_days": age_days,
                "creation_date": str(creation_date.date()),
                "is_new": age_days < 180
            }
        return {"available": False, "reason": "No creation date found"}
    except Exception as e:
        return {"available": False, "reason": str(e)}


def follow_redirects(url: str) -> dict:
    """Follow redirect chain and return final URL + chain."""
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        r = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        chain = [resp.url for resp in r.history] + [r.url]
        final_url = r.url
        redirected = len(r.history) > 0
        suspicious = False
        if redirected:
            original_domain = urlparse(url).netloc.lower()
            final_domain = urlparse(final_url).netloc.lower()
            if original_domain != final_domain:
                suspicious = True
        return {
            "available": True,
            "redirected": redirected,
            "hops": len(r.history),
            "final_url": final_url,
            "chain": chain,
            "suspicious": suspicious
        }
    except Exception as e:
        return {"available": False, "reason": str(e)}