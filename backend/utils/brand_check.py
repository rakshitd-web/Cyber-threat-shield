from urllib.parse import urlparse
import re

# Known brands and their legitimate domains
KNOWN_BRANDS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "twitter": "twitter.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "whatsapp": "whatsapp.com",
    "linkedin": "linkedin.com",
    "bankofamerica": "bankofamerica.com",
    "wellsfargo": "wellsfargo.com",
    "chase": "chase.com",
    "citibank": "citibank.com",
    "hdfc": "hdfcbank.com",
    "icici": "icicibank.com",
    "sbi": "onlinesbi.com",
    "dropbox": "dropbox.com",
    "yahoo": "yahoo.com",
    "ebay": "ebay.com",
    "steam": "steampowered.com",
    "twitch": "twitch.tv",
    "adobe": "adobe.com",
    "docusign": "docusign.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "ups": "ups.com",
}


def check_brand_impersonation(url: str):
    """
    Returns (is_impersonating: bool, brand: str or None)
    """
    if not url.startswith("http"):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # Strip www.
    if domain.startswith("www."):
        domain = domain[4:]

    for brand, legit_domain in KNOWN_BRANDS.items():
        # Brand name appears in domain but it's not the legit domain
        if brand in domain and not (domain == legit_domain or domain.endswith("." + legit_domain)):
            return True, brand

    return False, None