import re
import requests
import socket
import ssl
import whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime

FEATURE_ORDER = [
"having_IP_Address",
"URL_Length",
"Shortining_Service",
"having_At_Symbol",
"double_slash_redirecting",
"Prefix_Suffix",
"having_Sub_Domain",
"HTTPS_token",
"Domain_registeration_length",
"Favicon",
"port",
"Request_URL",
"URL_of_Anchor",
"Links_in_tags",
"SFH",
"Submitting_to_email",
"Abnormal_URL",
"Redirect",
"on_mouseover",
"RightClick",
"popUpWidnow",
"Iframe",
"age_of_domain",
"DNSRecord",
"web_traffic",
"Page_Rank",
"Google_Index",
"Links_pointing_to_page",
"Statistical_report"
]


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

    # Auto add https if missing
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

    # 8. HTTPS_token
    features["HTTPS_token"] = -1 if "https" in domain.lower() else 1

    # Domain age
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        age = (datetime.now() - creation_date).days

        if age > 365:
            features["Domain_registeration_length"] = 1
        else:
            features["Domain_registeration_length"] = -1

    except:
        features["Domain_registeration_length"] = -1


    advanced_features = [
        "Favicon", "port", "Request_URL", "URL_of_Anchor",
        "Links_in_tags", "SFH", "Submitting_to_email",
        "Abnormal_URL", "Redirect", "on_mouseover",
        "RightClick", "popUpWidnow", "Iframe",
        "age_of_domain", "DNSRecord", "web_traffic",
        "Page_Rank", "Google_Index",
        "Links_pointing_to_page", "Statistical_report","SSLfinal_State"
    ]

    for feature in advanced_features:
        features[feature] = 0

    import joblib
    feature_order = joblib.load("models/feature_order.pkl")

    return [features.get(f, 0) for f in feature_order]