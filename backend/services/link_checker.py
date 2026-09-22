from urllib.parse import urlparse
import requests
import socket
import ssl
from datetime import datetime
import tldextract
import re

def normalize_url(raw_url: str) -> str:
    """
    Takes whatever the user typed and turns it into a proper URL.
    Example: 'example.com' -> 'https://example.com'
    """
    raw_url = raw_url.strip()
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url
    return raw_url

def is_valid_url(url: str) -> bool:
    """
    Checks if a URL is properly structured (has a scheme and a valid-looking domain).
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    if not parsed.netloc:
        return False
    if " " in parsed.netloc:
        return False
    # basic domain shape check: letters/numbers/hyphens/dots only, plus optional port
    domain_pattern = r"^[a-zA-Z0-9.-]+(:\d+)?$"
    return bool(re.match(domain_pattern, parsed.netloc))

def resolve_domain(hostname: str) -> dict:
    """
    Checks if a domain name can be resolved to an IP address.
    Example: 'example.com' -> IP address like '93.184.216.34'
    """
    try:
        ip = socket.gethostbyname(hostname)
        return {"resolvable": True, "ip": ip, "hostname": hostname}
    except socket.gaierror:
        return {"resolvable": False, "ip": None, "hostname": hostname}

def check_ssl(hostname: str, port: int = 443) -> dict:
    """
    Checks if a domain has a valid SSL certificate (HTTPS security).
    """
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expires = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                issuer = dict(x[0] for x in cert["issuer"])
                return {
                    "https": True,
                    "valid_cert": True,
                    "issuer": issuer.get("organizationName", "Unknown"),
                    "expires": expires.isoformat(),
                }
    except Exception:
        return {"https": False, "valid_cert": False, "issuer": None, "expires": None}

def analyze_redirects(url: str) -> dict:
    """
    Follows a URL through any redirects and records the full chain.
    """
    try:
        response = requests.get(url, timeout=8, allow_redirects=True)
        chain = [r.url for r in response.history] + [response.url]
        return {
            "count": len(response.history),
            "chain": chain,
            "final_url": response.url,
            "final_status_code": response.status_code,
        }
    except requests.RequestException:
        return {
            "count": 0,
            "chain": [],
            "final_url": None,
            "final_status_code": None,
        }

def analyze_url_structure(url: str) -> dict:
    """
    Examines the shape/structure of a URL for anything unusual.
    """
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    subdomain_count = len(ext.subdomain.split(".")) if ext.subdomain else 0

    return {
        "length": len(url),
        "subdomains": subdomain_count,
        "params": len(parsed.query.split("&")) if parsed.query else 0,
        "suspicious_encoding": "%" in parsed.path or "%" in parsed.query,
    }

def check_security_headers(headers) -> dict:
    """
    Checks which important security-related HTTP headers are present.
    'headers' is the .headers object from a requests response.
    """
    return {
        "hsts": "Strict-Transport-Security" in headers,
        "csp": "Content-Security-Policy" in headers,
        "x_frame_options": "X-Frame-Options" in headers,
        "x_content_type_options": "X-Content-Type-Options" in headers,
    }

def compute_risk(ssl_info, redirects, headers, url_structure) -> dict:
    """
    Combines results from other checks into an overall risk level.
    """
    score = 0
    reasons = []

    if not ssl_info["https"]:
        score += 2
        reasons.append("HTTP instead of HTTPS")

    if not ssl_info["valid_cert"]:
        score += 2
        reasons.append("Invalid or missing SSL certificate")

    if redirects["count"] > 3:
        score += 2
        reasons.append("Excessive redirect chain")

    if url_structure["subdomains"] > 3:
        score += 1
        reasons.append("Unusual number of subdomains")

    if sum(headers.values()) <= 1:
        score += 1
        reasons.append("Missing most security headers")

    if score == 0:
        level = "LOW"
    elif score <= 3:
        level = "MEDIUM"
    else:
        level = "HIGH"

    if not reasons:
        reasons.append("No major technical issues detected")

    return {"risk_level": level, "risk_reasons": reasons}

def check_link_status(url):

    try:
        response = requests.get(url, timeout=5)

        return {
            "status_code": response.status_code,
            "reachable": True
        }

    except:
        return {
            "status_code": None,
            "reachable": False
        }

def scan_link(raw_url: str) -> dict:
    """
    Runs the full link scan: validation, DNS, SSL, redirects, structure,
    headers, and risk scoring. Returns one combined result.
    """
    url = normalize_url(raw_url)

    if not is_valid_url(url):
        return {"url": raw_url, "valid": False, "error": "Malformed URL"}

    hostname = urlparse(url).netloc

    domain_info = resolve_domain(hostname)
    ssl_info = check_ssl(hostname)
    redirect_info = analyze_redirects(url)
    structure_info = analyze_url_structure(url)

    try:
        response = requests.get(url, timeout=8)
        header_info = check_security_headers(response.headers)
    except requests.RequestException:
        header_info = {"hsts": False, "csp": False, "x_frame_options": False, "x_content_type_options": False}

    risk = compute_risk(ssl_info, redirect_info, header_info, structure_info)

    return {
        "url": raw_url,
        "normalized_url": url,
        "valid": True,
        "domain": domain_info,
        "ssl": ssl_info,
        "redirects": redirect_info,
        "url_structure": structure_info,
        "security_headers": header_info,
        **risk,
    }