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

    # --- URL based features ---
    features["URLLength"] = len(url)
    features["DomainLength"] = len(domain)
    features["IsDomainIP"] = 1 if re.match(r"\d+\.\d+\.\d+\.\d+", domain) else 0

    tld = domain.split(".")[-1].lower() if "." in domain else ""
    features["TLDLength"] = len(tld)
    features["TLDLegitimateProb"] = LEGITIMATE_TLDS.get(tld, 0.15)

    # URL character stats
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

    # Subdomains
    parts = domain.split(".")
    features["NoOfSubDomain"] = max(0, len(parts) - 2)

    # Obfuscation — hex encoding, unicode encoding in URL
    obfuscated = len(re.findall(r"%[0-9a-fA-F]{2}", url))
    features["HasObfuscation"] = 1 if obfuscated > 0 else 0
    features["NoOfObfuscatedChar"] = obfuscated
    features["ObfuscationRatio"] = round(obfuscated / len(url), 4) if url else 0

    # URL similarity index — ratio of alphanumeric to total chars (higher = more legit looking)
    alnum = sum(c.isalnum() for c in url)
    features["URLSimilarityIndex"] = round((alnum / len(url)) * 100, 2) if url else 0

    # Char continuation rate — longest run of same char type / length
    features["CharContinuationRate"] = round(letters / (letters + digits + 1), 4)

    # URL char probability — avg char frequency score (simplified)
    features["URLCharProb"] = round(letters / (len(url) + 1), 4)

    # HTTPS
    features["IsHTTPS"] = 1 if url.startswith("https://") else 0

    # --- Page content features ---
    soup = None
    response = None
    try:
        response = requests.get(url, timeout=8, verify=False,
                                headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(response.text, "html.parser")
    except:
        soup = None
        response = None

    if soup:
        all_tags = soup.find_all(True)
        features["LineOfCode"] = response.text.count("\n") if response else 0
        features["LargestLineLength"] = max((len(l) for l in response.text.splitlines()), default=0) if response else 0
        features["HasTitle"] = 1 if soup.title else 0
        title_text = soup.title.string.strip() if soup.title and soup.title.string else ""

        # Domain title match score
        domain_clean = domain.replace("www.", "").split(".")[0].lower()
        features["DomainTitleMatchScore"] = 100.0 if domain_clean in title_text.lower() else 0.0

        # URL title match
        url_words = set(re.findall(r"[a-zA-Z]{3,}", url.lower()))
        title_words = set(re.findall(r"[a-zA-Z]{3,}", title_text.lower()))
        match = url_words & title_words
        features["URLTitleMatchScore"] = round(len(match) / max(len(url_words), 1) * 100, 2)

        features["HasFavicon"] = 1 if soup.find("link", rel=lambda r: r and "icon" in r) else 0
        features["HasDescription"] = 1 if soup.find("meta", attrs={"name": "description"}) else 0
        features["IsResponsive"] = 1 if soup.find("meta", attrs={"name": "viewport"}) else 0
        features["HasSocialNet"] = 1 if any(s in response.text.lower() for s in ["facebook", "twitter", "instagram", "linkedin"]) else 0
        features["HasCopyrightInfo"] = 1 if "©" in response.text or "copyright" in response.text.lower() else 0
        features["HasSubmitButton"] = 1 if soup.find("input", {"type": "submit"}) or soup.find("button", {"type": "submit"}) else 0
        features["HasHiddenFields"] = 1 if soup.find("input", {"type": "hidden"}) else 0
        features["HasPasswordField"] = 1 if soup.find("input", {"type": "password"}) else 0
        features["HasExternalFormSubmit"] = 0
        forms = soup.find_all("form", action=True)
        for f in forms:
            action = f.get("action", "")
            if action.startswith("http") and domain not in action:
                features["HasExternalFormSubmit"] = 1
                break

        features["NoOfPopup"] = response.text.lower().count("window.open")
        features["NoOfiFrame"] = len(soup.find_all("iframe"))

        # Keyword checks
        text_lower = response.text.lower()
        features["Bank"] = 1 if any(w in text_lower for w in ["bank", "banking", "account"]) else 0
        features["Pay"] = 1 if any(w in text_lower for w in ["pay", "payment", "paypal"]) else 0
        features["Crypto"] = 1 if any(w in text_lower for w in ["bitcoin", "crypto", "wallet", "ethereum"]) else 0

        # Resource counts
        features["NoOfImage"] = len(soup.find_all("img"))
        features["NoOfCSS"] = len(soup.find_all("link", rel="stylesheet"))
        features["NoOfJS"] = len(soup.find_all("script"))

        # Ref counts
        all_links = soup.find_all("a", href=True)
        self_refs = sum(1 for a in all_links if domain in a["href"] or a["href"].startswith("/"))
        empty_refs = sum(1 for a in all_links if a["href"] in ["#", "", "javascript:void(0)"])
        external_refs = sum(1 for a in all_links if a["href"].startswith("http") and domain not in a["href"])
        features["NoOfSelfRef"] = self_refs
        features["NoOfEmptyRef"] = empty_refs
        features["NoOfExternalRef"] = external_refs

        # Redirects
        features["NoOfURLRedirect"] = len(response.history) if response else 0
        features["NoOfSelfRedirect"] = sum(
            1 for r in response.history if domain in r.url
        ) if response else 0

        # Robots
        try:
            rob = requests.get(f"https://{domain}/robots.txt", timeout=4, verify=False)
            features["Robots"] = 1 if rob.status_code == 200 else 0
        except:
            features["Robots"] = 0

    else:
        # Page not reachable — default all page features to 0
        defaults = [
            "LineOfCode", "LargestLineLength", "HasTitle", "DomainTitleMatchScore",
            "URLTitleMatchScore", "HasFavicon", "HasDescription", "IsResponsive",
            "HasSocialNet", "HasCopyrightInfo", "HasSubmitButton", "HasHiddenFields",
            "HasPasswordField", "HasExternalFormSubmit", "NoOfPopup", "NoOfiFrame",
            "Bank", "Pay", "Crypto", "NoOfImage", "NoOfCSS", "NoOfJS",
            "NoOfSelfRef", "NoOfEmptyRef", "NoOfExternalRef",
            "NoOfURLRedirect", "NoOfSelfRedirect", "Robots"
        ]
        for d in defaults:
            features[d] = 0

    feature_order = joblib.load("models/feature_order.pkl")
    return [features.get(f, 0) for f in feature_order]


def get_feature_reasons(url: str):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path.lower()
    reasons = []

    # IP address
    if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
        reasons.append({"flag": "danger", "text": "URL uses an IP address instead of a domain name"})

    # URL length
    length = len(url)
    if length > 75:
        reasons.append({"flag": "danger", "text": f"URL is very long ({length} characters) — common in phishing"})
    elif length > 54:
        reasons.append({"flag": "warning", "text": f"URL is moderately long ({length} characters)"})

    # Shortening service
    if re.search(r"bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co", url):
        reasons.append({"flag": "danger", "text": "URL uses a shortening service to hide the real destination"})

    # At symbol
    if "@" in url:
        reasons.append({"flag": "danger", "text": "URL contains '@' symbol — used to deceive browsers"})

    # Double slash
    if url.count("//") > 1:
        reasons.append({"flag": "danger", "text": "URL contains double slash redirect"})

    # Hyphen in domain
    if "-" in domain:
        reasons.append({"flag": "danger", "text": f"Domain contains hyphen — common phishing tactic"})

    # Subdomains
    if domain.count(".") > 2:
        reasons.append({"flag": "danger", "text": "Domain has multiple subdomains — suspicious nesting"})

    # Obfuscation
    obfuscated = len(re.findall(r"%[0-9a-fA-F]{2}", url))
    if obfuscated > 0:
        reasons.append({"flag": "danger", "text": f"URL contains {obfuscated} obfuscated character(s)"})

    # Suspicious TLD
    tld = domain.split(".")[-1].lower() if "." in domain else ""
    suspicious_tlds = ["xyz", "top", "click", "tk", "ml", "ga", "cf", "gq", "pw"]
    if tld in suspicious_tlds:
        reasons.append({"flag": "danger", "text": f"Suspicious TLD '.{tld}' — commonly used in phishing"})

    # HTTPS
    if url.startswith("https://"):
        reasons.append({"flag": "safe", "text": "Site uses HTTPS"})
    else:
        reasons.append({"flag": "danger", "text": "Site does not use HTTPS"})

    # Suspicious path keywords
    suspicious_paths = [".php", "support", "login", "verify", "secure",
                        "update", "account", "banking", "confirm", "signin", "webscr"]
    for p in suspicious_paths:
        if p in path:
            reasons.append({"flag": "warning", "text": f"URL path contains suspicious keyword: '{p}'"})

    # SSL check
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                reasons.append({"flag": "safe", "text": "Site has a valid SSL certificate"})
    except:
        reasons.append({"flag": "danger", "text": "Site does not have a valid SSL certificate"})

    return reasons