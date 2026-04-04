import requests
import socket
import ssl
import whois
from datetime import datetime
from urllib.parse import urlparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


SECURITY_HEADERS = [
    "X-Frame-Options",
    "Content-Security-Policy",
    "X-XSS-Protection",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP Alternate",
    8443: "HTTPS Alternate",
    27017: "MongoDB"
}

SENSITIVE_PATHS = [
    "/admin", "/admin/", "/login", "/backup",
    "/config", "/.env", "/wp-admin", "/phpmyadmin",
    "/uploads", "/files", "/.git", "/api/docs",
    "/swagger", "/console"
]


def check_security_headers(url, response):
    results = []
    for header in SECURITY_HEADERS:
        if header.lower() in [h.lower() for h in response.headers]:
            results.append({"status": "safe", "text": f"Header '{header}' is present"})
        else:
            results.append({"status": "danger", "text": f"Missing security header: '{header}'"})
    return results


def check_ssl(domain):
    results = []
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expire_date = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_left = (expire_date - datetime.now()).days
                if days_left > 30:
                    results.append({"status": "safe", "text": f"SSL certificate is valid — expires in {days_left} days"})
                else:
                    results.append({"status": "danger", "text": f"SSL certificate expires in {days_left} days — renew soon"})
                results.append({"status": "safe", "text": f"SSL protocol: {ssock.version()}"})
    except ssl.SSLCertVerificationError:
        results.append({"status": "danger", "text": "SSL certificate verification failed — possibly self-signed"})
    except Exception as e:
        results.append({"status": "danger", "text": f"SSL check failed: {str(e)}"})
    return results


def check_open_ports(domain):
    results = []
    for port, service in COMMON_PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((domain, port))
            sock.close()
            if result == 0:
                if port in [21, 23, 3306, 5432, 6379, 27017]:
                    results.append({"status": "danger", "text": f"Port {port} ({service}) is open — potentially dangerous"})
                else:
                    results.append({"status": "info", "text": f"Port {port} ({service}) is open"})
        except:
            pass
    if not results:
        results.append({"status": "safe", "text": "No dangerous open ports detected"})
    return results


def check_sensitive_paths(url, domain):
    results = []
    base = f"https://{domain}"
    for path in SENSITIVE_PATHS:
        try:
            r = requests.get(base + path, timeout=4, verify=False, allow_redirects=False)
            if r.status_code == 200:
                results.append({"status": "danger", "text": f"Sensitive path accessible: {path} (HTTP 200)"})
            elif r.status_code == 403:
                results.append({"status": "warning", "text": f"Path exists but forbidden: {path} (HTTP 403)"})
        except:
            pass
    if not results:
        results.append({"status": "safe", "text": "No sensitive paths exposed"})
    return results


def check_cookie_security(response):
    results = []
    cookies = response.cookies
    if not cookies:
        results.append({"status": "info", "text": "No cookies found on this page"})
        return results
    for cookie in cookies:
        if not cookie.secure:
            results.append({"status": "danger", "text": f"Cookie '{cookie.name}' is missing Secure flag"})
        else:
            results.append({"status": "safe", "text": f"Cookie '{cookie.name}' has Secure flag"})
        if not cookie.has_nonstandard_attr("HttpOnly"):
            results.append({"status": "danger", "text": f"Cookie '{cookie.name}' is missing HttpOnly flag"})
        else:
            results.append({"status": "safe", "text": f"Cookie '{cookie.name}' has HttpOnly flag"})
    return results


def check_server_info(response):
    results = []
    server = response.headers.get("Server", None)
    powered_by = response.headers.get("X-Powered-By", None)
    if server:
        results.append({"status": "warning", "text": f"Server header exposes info: '{server}'"})
    else:
        results.append({"status": "safe", "text": "Server header is hidden"})
    if powered_by:
        results.append({"status": "warning", "text": f"X-Powered-By header exposes info: '{powered_by}'"})
    else:
        results.append({"status": "safe", "text": "X-Powered-By header is hidden"})
    return results


def check_whois(domain):
    results = []
    try:
        info = whois.whois(domain)
        creation_date = info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age = (datetime.now() - creation_date).days
        if age < 180:
            results.append({"status": "danger", "text": f"Domain is only {age} days old — newly registered"})
        else:
            results.append({"status": "safe", "text": f"Domain has been registered for {age} days"})
        registrar = info.registrar
        if registrar:
            results.append({"status": "info", "text": f"Registrar: {registrar}"})
    except Exception as e:
        results.append({"status": "warning", "text": f"WHOIS lookup failed: {str(e)}"})
    return results


def run_scan(url: str, checks: list):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc

    try:
        response = requests.get(url, timeout=8, verify=False)
    except Exception as e:
        raise ValueError(f"Could not reach the URL: {str(e)}")

    scan_results = {}

    if "headers" in checks:
        scan_results["Security Headers"] = check_security_headers(url, response)

    if "ssl" in checks:
        scan_results["SSL / TLS"] = check_ssl(domain)

    if "ports" in checks:
        scan_results["Open Ports"] = check_open_ports(domain)

    if "paths" in checks:
        scan_results["Sensitive Paths"] = check_sensitive_paths(url, domain)

    if "cookies" in checks:
        scan_results["Cookie Security"] = check_cookie_security(response)

    if "server" in checks:
        scan_results["Server Info Disclosure"] = check_server_info(response)

    if "whois" in checks:
        scan_results["WHOIS Info"] = check_whois(domain)

    return scan_results


def generate_txt_report(url: str, scan_results: dict) -> str:
    lines = []
    lines.append("=" * 60)
    lines.append("       CYBERTHREAT SHIELD - VULNERABILITY REPORT")
    lines.append("=" * 60)
    lines.append(f"URL: {url}")
    lines.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 60)

    for category, results in scan_results.items():
        lines.append(f"\n[ {category} ]")
        lines.append("-" * 40)
        for r in results:
            icon = "✅" if r["status"] == "safe" else ("⚠" if r["status"] == "warning" else ("ℹ" if r["status"] == "info" else "❌"))
            lines.append(f"  {icon} {r['text']}")

    lines.append("\n" + "=" * 60)
    lines.append("End of Report")
    lines.append("=" * 60)
    return "\n".join(lines)