import requests
import pandas as pd
import socket
import ssl
import re
from urllib.parse import urlparse
from datetime import datetime
import warnings
warnings.filterwarnings("ignore")

LEGITIMATE_TLDS = {
    "com": 0.52, "org": 0.38, "net": 0.35, "edu": 0.95,
    "gov": 0.99, "co": 0.45, "io": 0.40, "uk": 0.60,
    "us": 0.55, "ca": 0.60, "au": 0.60, "de": 0.65,
    "fr": 0.60, "jp": 0.65, "in": 0.50, "info": 0.20,
    "biz": 0.15, "xyz": 0.10, "top": 0.08, "click": 0.05
}


def extract_features_from_url(url):
    try:
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url

        parsed = urlparse(url)
        domain = parsed.netloc
        if not domain:
            return None

        # Check domain resolves
        try:
            socket.gethostbyname(domain)
        except:
            return None

        features = {}
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
        features["LetterRatioInURL"] = round(letters / len(url), 4)
        features["NoOfDegitsInURL"] = digits
        features["DegitRatioInURL"] = round(digits / len(url), 4)
        features["NoOfEqualsInURL"] = url.count("=")
        features["NoOfQMarkInURL"] = url.count("?")
        features["NoOfAmpersandInURL"] = url.count("&")
        features["NoOfOtherSpecialCharsInURL"] = special
        features["SpacialCharRatioInURL"] = round(special / len(url), 4)

        parts = domain.split(".")
        features["NoOfSubDomain"] = max(0, len(parts) - 2)

        obfuscated = len(re.findall(r"%[0-9a-fA-F]{2}", url))
        features["HasObfuscation"] = 1 if obfuscated > 0 else 0
        features["NoOfObfuscatedChar"] = obfuscated
        features["ObfuscationRatio"] = round(obfuscated / len(url), 4)

        features["CharContinuationRate"] = round(letters / (letters + digits + 1), 4)
        features["URLCharProb"] = round(letters / (len(url) + 1), 4)
        features["IsHTTPS"] = 1 if url.startswith("https://") else 0

        # SSL check
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    features["HasValidSSL"] = 1
        except:
            features["HasValidSSL"] = 0

        # Hyphen in domain
        features["HasHyphen"] = 1 if "-" in domain else 0

        # Suspicious TLD
        suspicious_tlds = ["xyz", "top", "click", "tk", "ml", "ga", "cf", "gq", "pw"]
        features["HasSuspiciousTLD"] = 1 if tld in suspicious_tlds else 0

        # Shortening service
        features["IsShortened"] = 1 if re.search(r"bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co", url) else 0

        # At symbol
        features["HasAtSymbol"] = 1 if "@" in url else 0

        # Double slash
        features["HasDoubleSlash"] = 1 if url.count("//") > 1 else 0

        return features

    except Exception as e:
        return None


def fetch_phishing_urls(count=600):
    print("Fetching phishing URLs from OpenPhish...")
    try:
        r = requests.get("https://openphish.com/feed.txt", timeout=10)
        urls = r.text.strip().split("\n")
        print(f"Got {len(urls)} phishing URLs")
        return urls[:count]
    except Exception as e:
        print(f"OpenPhish failed: {e}")
        return []


def fetch_legitimate_urls(count=600):
    print("Fetching legitimate URLs from Majestic Million...")
    try:
        r = requests.get(
            "https://downloads.majestic.com/majestic_million.csv",
            timeout=30,
            stream=True
        )
        lines = []
        for i, line in enumerate(r.iter_lines()):
            if i == 0:
                continue  # skip header
            if i > count + 1:
                break
            domain = line.decode("utf-8").split(",")[2]
            lines.append(f"https://{domain}")
        print(f"Got {len(lines)} legitimate URLs")
        return lines
    except Exception as e:
        print(f"Majestic failed: {e}")
        # Fallback to hardcoded top sites
        print("Using fallback legitimate URLs...")
        return [
            "https://google.com", "https://youtube.com", "https://facebook.com",
            "https://twitter.com", "https://instagram.com", "https://linkedin.com",
            "https://microsoft.com", "https://apple.com", "https://amazon.com",
            "https://netflix.com", "https://github.com", "https://wikipedia.org",
            "https://reddit.com", "https://stackoverflow.com", "https://whatsapp.com",
            "https://telegram.org", "https://dropbox.com", "https://zoom.us",
            "https://slack.com", "https://spotify.com", "https://adobe.com",
            "https://paypal.com", "https://ebay.com", "https://yahoo.com",
            "https://bing.com", "https://twitch.tv", "https://pinterest.com",
            "https://tumblr.com", "https://wordpress.com", "https://medium.com"
        ]


def build_dataset(phishing_count=500, legit_count=500):
    phishing_urls = fetch_phishing_urls(phishing_count + 100)
    legit_urls = fetch_legitimate_urls(legit_count + 100)

    rows = []

    print(f"\nExtracting features from phishing URLs...")
    phishing_done = 0
    for url in phishing_urls:
        if phishing_done >= phishing_count:
            break
        features = extract_features_from_url(url)
        if features:
            features["label"] = 0  # 0 = phishing
            rows.append(features)
            phishing_done += 1
            if phishing_done % 50 == 0:
                print(f"  Phishing: {phishing_done}/{phishing_count}")

    print(f"\nExtracting features from legitimate URLs...")
    legit_done = 0
    for url in legit_urls:
        if legit_done >= legit_count:
            break
        features = extract_features_from_url(url)
        if features:
            features["label"] = 1  # 1 = legitimate
            rows.append(features)
            legit_done += 1
            if legit_done % 50 == 0:
                print(f"  Legitimate: {legit_done}/{legit_count}")

    df = pd.DataFrame(rows)
    df.to_csv("CustomPhishingDataset.csv", index=False)
    print(f"\nDataset saved: {len(df)} rows")
    print(f"Label counts: {df['label'].value_counts().to_dict()}")
    print("Columns:", df.columns.tolist())
    return df


if __name__ == "__main__":
    build_dataset(500, 500)