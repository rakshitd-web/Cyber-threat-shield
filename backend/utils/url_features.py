import re
import socket
import ssl
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import joblib

LEGITIMATE_TLDS = {
    "com": 0.52, "org": 0.38, "net": 0.35, "edu": 0.95,
    "gov": 0.99, "co": 0.45, "io": 0.40, "uk": 0.60,
    "us": 0.55, "ca": 0.60, "au": 0.60, "de": 0.65,
    "fr": 0.60, "jp": 0.65, "in": 0.50, "info": 0.20,
    "biz": 0.15, "xyz": 0.10, "top": 0.08, "click": 0.05
}


def is_valid_url(url: str):
    try:
        parsed = urlparse(url)
        return parsed.netloc != ""
    except:
        return False


def domain_exists(domain: str):
    try:
        socket.gethostbyname(domain)
        return True
    except:
        return False


def extract_features(url: str):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    if not is_valid_url(url):
        raise ValueError("Invalid URL format")

    parsed = urlparse(url)
    domain = parsed.netloc

    if not domain_exists(domain):
        raise ValueError("Domain does not exist")

    features = {}

    # URL based features only
    features["URLLength"] = len(url)
    features["DomainLength"] = len(domain)
    features["IsDomainIP"] = 1 if re.match(r"\d+\.\d+\.\d+\.\d+", domain) else 0

    tld = domain.split(".")[-1].lower() if "." in domain else ""
    features["TLDLength"] = len(tld)
    features["TLDLegitimateProb"] = LEGITIMATE_TLDS.get(tld, 0.15)

    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)
    special = sum(not c.isalnum() and c not in [".", "/", ":"] for c in url)

    features["NoOfLettersInURL"] = letters
    features["LetterRatioInURL"] = round(letters / len(url), 4) if url else 0
    features["NoOfDegitsInURL"] = digits
    features["DegitRatioInURL"] = round(digits / len(url), 4) if url else 0
    features["NoOfEqualsInURL"] = url.count("=")
    features["NoOfQMarkInURL"] = url.count("?")
    features["NoOfAmpersandInURL"] = url.count("&")
    features["NoOfOtherSpecialCharsInURL"] = special
    features["SpacialCharRatioInURL"] = round(special / len(url), 4) if url else 0

    parts = domain.split(".")
    features["NoOfSubDomain"] = max(0, len(parts) - 2)

    obfuscated = len(re.findall(r"%[0-9a-fA-F]{2}", url))
    features["HasObfuscation"] = 1 if obfuscated > 0 else 0
    features["NoOfObfuscatedChar"] = obfuscated
    features["ObfuscationRatio"] = round(obfuscated / len(url), 4) if url else 0

    features["CharContinuationRate"] = round(letters / (letters + digits + 1), 4)
    features["URLCharProb"] = round(letters / (len(url) + 1), 4)
    features["IsHTTPS"] = 1 if url.startswith("https://") else 0

    feature_order = joblib.load("models/feature_order.pkl")
    return [features.get(f, 0) for f in feature_order]


def get_feature_reasons(url: str):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path.lower()
    reasons = []

    if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
        reasons.append({"flag": "danger", "text": "URL uses an IP address instead of a domain name"})

    length = len(url)
    if length > 75:
        reasons.append({"flag": "danger", "text": f"URL is very long ({length} characters) — common in phishing"})
    elif length > 54:
        reasons.append({"flag": "warning", "text": f"URL is moderately long ({length} characters)"})

    if re.search(r"bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co", url):
        reasons.append({"flag": "danger", "text": "URL uses a shortening service to hide the real destination"})

    if "@" in url:
        reasons.append({"flag": "danger", "text": "URL contains '@' symbol — used to deceive browsers"})

    if url.count("//") > 1:
        reasons.append({"flag": "danger", "text": "URL contains double slash redirect"})

    if "-" in domain:
        reasons.append({"flag": "danger", "text": "Domain contains hyphen — common phishing tactic"})

    trusted_tlds = ["edu", "gov", "ac", "edu.in", "ac.in", "gov.in", "edu.au", "ac.uk"]
    is_trusted = any(domain.endswith(t) for t in trusted_tlds)
    if domain.count(".") > 2 and not is_trusted:
        reasons.append({"flag": "danger", "text": "Domain has multiple subdomains — suspicious nesting"})

    obfuscated = len(re.findall(r"%[0-9a-fA-F]{2}", url))
    if obfuscated > 0:
        reasons.append({"flag": "danger", "text": f"URL contains {obfuscated} obfuscated character(s)"})

    tld = domain.split(".")[-1].lower() if "." in domain else ""
    suspicious_tlds = ["xyz", "top", "click", "tk", "ml", "ga", "cf", "gq", "pw"]
    if tld in suspicious_tlds:
        reasons.append({"flag": "danger", "text": f"Suspicious TLD '.{tld}' — commonly used in phishing"})

    if url.startswith("https://"):
        reasons.append({"flag": "safe", "text": "Site uses HTTPS"})
    else:
        reasons.append({"flag": "danger", "text": "Site does not use HTTPS"})

    suspicious_paths = [".php", "support", "login", "verify", "secure",
                        "update", "account", "banking", "confirm", "signin", "webscr"]
    for p in suspicious_paths:
        if p in path:
            reasons.append({"flag": "warning", "text": f"URL path contains suspicious keyword: '{p}'"})

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                reasons.append({"flag": "safe", "text": "Site has a valid SSL certificate"})
    except:
        reasons.append({"flag": "danger", "text": "Site does not have a valid SSL certificate"})

    return reasons