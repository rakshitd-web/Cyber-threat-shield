import re
import requests
import socket
import ssl
import whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime
import joblib


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

    # 1. having_IP_Address
    features["having_IP_Address"] = -1 if re.match(r"\d+\.\d+\.\d+\.\d+", domain) else 1

    # 2. URL_Length
    length = len(url)
    if length < 54:
        features["URL_Length"] = 1
    elif 54 <= length <= 75:
        features["URL_Length"] = 0
    else:
        features["URL_Length"] = -1

    # 3. Shortining_Service
    shortening_services = r"bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co"
    features["Shortining_Service"] = -1 if re.search(shortening_services, url) else 1

    # 4. having_At_Symbol
    features["having_At_Symbol"] = -1 if "@" in url else 1

    # 5. double_slash_redirecting
    features["double_slash_redirecting"] = -1 if url.count("//") > 1 else 1

    # 6. Prefix_Suffix
    features["Prefix_Suffix"] = -1 if "-" in domain else 1

    # 7. having_Sub_Domain
    if domain.count(".") == 1:
        features["having_Sub_Domain"] = 1
    elif domain.count(".") == 2:
        features["having_Sub_Domain"] = 0
    else:
        features["having_Sub_Domain"] = -1

    # 8. SSLfinal_State
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                features["SSLfinal_State"] = 1
    except:
        features["SSLfinal_State"] = -1

    # 9. HTTPS_token
    features["HTTPS_token"] = -1 if "https" in domain.lower() else 1

    # 10. Domain_registeration_length
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age = (datetime.now() - creation_date).days
        features["Domain_registeration_length"] = 1 if age > 365 else -1
    except:
        features["Domain_registeration_length"] = -1

    # 11. Fetch page content for anchor/link analysis
    soup = None
    try:
        response = requests.get(url, timeout=5, verify=False)
        soup = BeautifulSoup(response.text, "html.parser")
    except:
        soup = None

    # 12. URL_of_Anchor (most important feature at 23%)
    try:
        anchors = soup.find_all("a", href=True)
        total = len(anchors)
        if total == 0:
            features["URL_of_Anchor"] = -1
        else:
            suspicious = sum(
                1 for a in anchors
                if "#" in a["href"] or "javascript" in a["href"].lower() or a["href"] == ""
            )
            ratio = suspicious / total
            if ratio < 0.31:
                features["URL_of_Anchor"] = 1
            elif ratio <= 0.67:
                features["URL_of_Anchor"] = 0
            else:
                features["URL_of_Anchor"] = -1
    except:
        features["URL_of_Anchor"] = -1

    # 13. Links_in_tags
    try:
        tags = soup.find_all(["meta", "script", "link"])
        total = len(tags)
        if total == 0:
            features["Links_in_tags"] = -1
        else:
            external = sum(
                1 for t in tags
                if t.get("src") and domain not in t.get("src", "")
                or t.get("href") and domain not in t.get("href", "")
            )
            ratio = external / total
            if ratio < 0.17:
                features["Links_in_tags"] = 1
            elif ratio <= 0.81:
                features["Links_in_tags"] = 0
            else:
                features["Links_in_tags"] = -1
    except:
        features["Links_in_tags"] = -1

    # 14. Request_URL
    try:
        tags = soup.find_all(["img", "video", "audio"])
        total = len(tags)
        if total == 0:
            features["Request_URL"] = 1
        else:
            external = sum(
                1 for t in tags
                if t.get("src") and domain not in t.get("src", "")
            )
            ratio = external / total
            if ratio < 0.22:
                features["Request_URL"] = 1
            elif ratio <= 0.61:
                features["Request_URL"] = 0
            else:
                features["Request_URL"] = -1
    except:
        features["Request_URL"] = -1

    # 15. SFH (Server Form Handler)
    try:
        forms = soup.find_all("form", action=True)
        if not forms:
            features["SFH"] = 1
        else:
            sfh = forms[0]["action"]
            if sfh == "" or sfh == "about:blank":
                features["SFH"] = -1
            elif domain not in sfh and sfh.startswith("http"):
                features["SFH"] = 0
            else:
                features["SFH"] = 1
    except:
        features["SFH"] = -1

    # 16. Submitting_to_email
    try:
        forms = soup.find_all("form", action=True)
        features["Submitting_to_email"] = -1 if any(
            "mailto:" in f["action"] for f in forms
        ) else 1
    except:
        features["Submitting_to_email"] = 1

    # 17. on_mouseover
    try:
        features["on_mouseover"] = -1 if soup.find(onmouseover=True) else 1
    except:
        features["on_mouseover"] = 1

    # 18. RightClick
    try:
        scripts = " ".join(s.string for s in soup.find_all("script") if s.string)
        features["RightClick"] = -1 if "contextmenu" in scripts.lower() else 1
    except:
        features["RightClick"] = 1

    # 19. popUpWidnow
    try:
        scripts = " ".join(s.string for s in soup.find_all("script") if s.string)
        features["popUpWidnow"] = -1 if "window.open" in scripts.lower() else 1
    except:
        features["popUpWidnow"] = 1

    # 20. Iframe
    try:
        features["Iframe"] = -1 if soup.find("iframe") else 1
    except:
        features["Iframe"] = 1

    # 21. Abnormal_URL
    try:
        domain_info = whois.whois(domain)
        reg_domain = domain_info.domain_name
        if isinstance(reg_domain, list):
            reg_domain = reg_domain[0]
        features["Abnormal_URL"] = 1 if reg_domain and reg_domain.lower() in domain.lower() else -1
    except:
        features["Abnormal_URL"] = -1

    # 22. DNSRecord
    try:
        socket.gethostbyname(domain)
        features["DNSRecord"] = 1
    except:
        features["DNSRecord"] = -1

    # 23. age_of_domain
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age = (datetime.now() - creation_date).days
        features["age_of_domain"] = 1 if age > 180 else -1
    except:
        features["age_of_domain"] = -1

    # 24. Google_Index
    try:
        response = requests.get(
            f"https://www.google.com/search?q=site:{domain}",
            timeout=5,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        features["Google_Index"] = 1 if "did not match any documents" not in response.text else -1
    except:
        features["Google_Index"] = -1

    # Remaining features defaulted to 0
    for feature in ["Favicon", "port", "Redirect", "web_traffic",
                    "Page_Rank", "Links_pointing_to_page", "Statistical_report"]:
        features[feature] = 0

    feature_order = joblib.load("models/feature_order.pkl")
    return [features.get(f, 0) for f in feature_order]