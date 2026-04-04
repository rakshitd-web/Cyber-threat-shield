import requests
import socket
import ssl
import whois
import dns.resolver
from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup
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

COMMON_SUBDOMAINS = [
    "admin", "mail", "ftp", "dev", "staging",
    "test", "api", "vpn", "remote", "portal"
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


def check_dns_security(domain):
    results = []
    # DNSSEC
    try:
        dns.resolver.resolve(domain, "DNSKEY")
        results.append({"status": "safe", "text": "DNSSEC is enabled"})
    except:
        results.append({"status": "warning", "text": "DNSSEC is not enabled"})
    # SPF
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        spf_found = any("v=spf1" in str(r) for r in answers)
        if spf_found:
            results.append({"status": "safe", "text": "SPF record is present"})
        else:
            results.append({"status": "warning", "text": "No SPF record found — email spoofing possible"})
    except:
        results.append({"status": "warning", "text": "Could not check SPF record"})
    # DMARC
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc_found = any("v=DMARC1" in str(r) for r in answers)
        if dmarc_found:
            results.append({"status": "safe", "text": "DMARC record is present"})
        else:
            results.append({"status": "warning", "text": "No DMARC record found"})
    except:
        results.append({"status": "warning", "text": "No DMARC record found"})
    return results


def check_http_methods(url, domain):
    results = []
    dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]
    try:
        r = requests.options(url, timeout=5, verify=False)
        allowed = r.headers.get("Allow", "")
        for method in dangerous_methods:
            if method in allowed:
                results.append({"status": "danger", "text": f"Dangerous HTTP method enabled: {method}"})
        if not any(m in allowed for m in dangerous_methods):
            results.append({"status": "safe", "text": "No dangerous HTTP methods enabled"})
        if not allowed:
            results.append({"status": "info", "text": "Server did not disclose allowed HTTP methods"})
    except Exception as e:
        results.append({"status": "warning", "text": f"HTTP methods check failed: {str(e)}"})
    return results


def check_redirect_chain(url):
    results = []
    try:
        r = requests.get(url, timeout=8, verify=False, allow_redirects=True)
        history = r.history
        if len(history) == 0:
            results.append({"status": "safe", "text": "No redirects detected"})
        elif len(history) <= 2:
            results.append({"status": "info", "text": f"Redirect chain: {len(history)} redirect(s) — acceptable"})
        else:
            results.append({"status": "warning", "text": f"Long redirect chain: {len(history)} redirects — suspicious"})
        for i, resp in enumerate(history):
            results.append({"status": "info", "text": f"Redirect {i+1}: {resp.url} → HTTP {resp.status_code}"})
    except Exception as e:
        results.append({"status": "warning", "text": f"Redirect check failed: {str(e)}"})
    return results


def check_content_type_sniffing(response):
    results = []
    header = response.headers.get("X-Content-Type-Options", None)
    if header and header.lower() == "nosniff":
        results.append({"status": "safe", "text": "X-Content-Type-Options is set to 'nosniff'"})
    else:
        results.append({"status": "danger", "text": "X-Content-Type-Options header missing — MIME sniffing possible"})
    return results


def check_clickjacking(response):
    results = []
    xfo = response.headers.get("X-Frame-Options", None)
    csp = response.headers.get("Content-Security-Policy", "")
    if xfo:
        results.append({"status": "safe", "text": f"X-Frame-Options is set: '{xfo}' — clickjacking protected"})
    elif "frame-ancestors" in csp.lower():
        results.append({"status": "safe", "text": "CSP frame-ancestors directive present — clickjacking protected"})
    else:
        results.append({"status": "danger", "text": "No clickjacking protection found — site can be embedded in iframes"})
    return results


def check_email_security(domain):
    results = []
    # SPF
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        spf = [str(r) for r in answers if "v=spf1" in str(r)]
        if spf:
            results.append({"status": "safe", "text": f"SPF record found: {spf[0][:60]}..."})
        else:
            results.append({"status": "danger", "text": "No SPF record — domain vulnerable to email spoofing"})
    except:
        results.append({"status": "warning", "text": "Could not retrieve SPF record"})
    # DKIM
    try:
        dns.resolver.resolve(f"default._domainkey.{domain}", "TXT")
        results.append({"status": "safe", "text": "DKIM record found"})
    except:
        results.append({"status": "warning", "text": "No DKIM record found at default selector"})
    # DMARC
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc = [str(r) for r in answers if "v=DMARC1" in str(r)]
        if dmarc:
            results.append({"status": "safe", "text": f"DMARC record found: {dmarc[0][:60]}..."})
        else:
            results.append({"status": "danger", "text": "No DMARC record — email spoofing risk"})
    except:
        results.append({"status": "danger", "text": "No DMARC record found"})
    return results


def check_subdomain_exposure(domain):
    results = []
    found = []
    for sub in COMMON_SUBDOMAINS:
        try:
            full = f"{sub}.{domain}"
            socket.gethostbyname(full)
            found.append(full)
        except:
            pass
    if not found:
        results.append({"status": "safe", "text": "No common subdomains exposed"})
    else:
        for sub in found:
            results.append({"status": "warning", "text": f"Subdomain found: {sub}"})
    return results


def check_robots_txt(domain):
    results = []
    for path in ["/robots.txt", "/sitemap.xml"]:
        try:
            r = requests.get(f"https://{domain}{path}", timeout=5, verify=False)
            if r.status_code == 200:
                results.append({"status": "warning", "text": f"{path} is publicly accessible — may expose sensitive paths"})
                if "Disallow" in r.text:
                    disallowed = [line.split(": ")[1].strip() for line in r.text.splitlines() if line.startswith("Disallow")]
                    for d in disallowed[:5]:
                        results.append({"status": "info", "text": f"robots.txt disallows: {d}"})
            else:
                results.append({"status": "safe", "text": f"{path} is not publicly accessible"})
        except:
            results.append({"status": "safe", "text": f"{path} is not accessible"})
    return results


def check_rate_limiting(url):
    results = []
    try:
        r = requests.get(url, timeout=5, verify=False)
        rate_headers = ["X-RateLimit-Limit", "X-RateLimit-Remaining", "Retry-After", "RateLimit-Limit"]
        found = [h for h in rate_headers if h.lower() in [x.lower() for x in r.headers]]
        if found:
            results.append({"status": "safe", "text": f"Rate limiting headers detected: {', '.join(found)}"})
        else:
            results.append({"status": "warning", "text": "No rate limiting headers detected — brute force may be possible"})
    except Exception as e:
        results.append({"status": "warning", "text": f"Rate limit check failed: {str(e)}"})
    return results


def check_mixed_content(url, domain, response):
    results = []
    try:
        if not url.startswith("https://"):
            results.append({"status": "info", "text": "Site is not HTTPS — mixed content check skipped"})
            return results
        soup = BeautifulSoup(response.text, "html.parser")
        mixed = []
        for tag in soup.find_all(["img", "script", "link", "iframe"]):
            src = tag.get("src") or tag.get("href", "")
            if src.startswith("http://"):
                mixed.append(src)
        if mixed:
            for m in mixed[:5]:
                results.append({"status": "danger", "text": f"Mixed content found: {m[:80]}"})
        else:
            results.append({"status": "safe", "text": "No mixed content detected — all resources loaded over HTTPS"})
    except Exception as e:
        results.append({"status": "warning", "text": f"Mixed content check failed: {str(e)}"})
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
    if "dns" in checks:
        scan_results["DNS Security"] = check_dns_security(domain)
    if "methods" in checks:
        scan_results["HTTP Methods"] = check_http_methods(url, domain)
    if "redirects" in checks:
        scan_results["Redirect Chain"] = check_redirect_chain(url)
    if "sniffing" in checks:
        scan_results["Content Type Sniffing"] = check_content_type_sniffing(response)
    if "clickjacking" in checks:
        scan_results["Clickjacking Protection"] = check_clickjacking(response)
    if "email" in checks:
        scan_results["Email Security"] = check_email_security(domain)
    if "subdomains" in checks:
        scan_results["Subdomain Exposure"] = check_subdomain_exposure(domain)
    if "robots" in checks:
        scan_results["Robots.txt / Sitemap"] = check_robots_txt(domain)
    if "ratelimit" in checks:
        scan_results["Rate Limiting"] = check_rate_limiting(url)
    if "mixed" in checks:
        scan_results["Mixed Content"] = check_mixed_content(url, domain, response)

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