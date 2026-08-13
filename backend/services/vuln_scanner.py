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
        response_headers = {h.lower() for h in response.headers}
        if header.lower() in response_headers:
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


# ---------------------------------------------------------------------------
# Finding metadata
# ---------------------------------------------------------------------------

SEVERITY_RANK = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Info": 0,
}

FINDING_METADATA = {
    # Security headers
    "Missing security header: 'Content-Security-Policy'": {
        "severity": "Medium",
        "description": "Content-Security-Policy (CSP) restricts the sources from which browsers may load and execute content.",
        "attack": "If another client-side weakness such as XSS exists, the absence of CSP removes an important browser-side defense and can make malicious content execution easier.",
        "fix": "Configure a restrictive Content-Security-Policy appropriate for the application and test it before enforcing it."
    },
    "Missing security header: 'X-Frame-Options'": {
        "severity": "Medium",
        "description": "X-Frame-Options controls whether a page can be embedded in a frame by another site.",
        "attack": "An attacker may embed the application in a malicious page and attempt to trick a user into interacting with the hidden or disguised application.",
        "fix": "Set X-Frame-Options to DENY or SAMEORIGIN, or use the CSP frame-ancestors directive."
    },
    "Missing security header: 'X-XSS-Protection'": {
        "severity": "Low",
        "description": "This legacy header controlled older browser XSS filtering behavior and is largely obsolete in modern browsers.",
        "attack": "The absence of this legacy header generally does not create a direct modern-browser vulnerability, but it indicates incomplete security hardening.",
        "fix": "Prioritize a strong Content-Security-Policy and secure output encoding. Do not rely on X-XSS-Protection as the primary XSS defense."
    },
    "Missing security header: 'Strict-Transport-Security'": {
        "severity": "Medium",
        "description": "HSTS instructs browsers to use HTTPS for future connections to the domain.",
        "attack": "Without HSTS, a user can potentially be downgraded to an insecure HTTP connection during an interception or network attack.",
        "fix": "After confirming HTTPS works correctly, configure Strict-Transport-Security with an appropriate max-age and consider includeSubDomains."
    },
    "Missing security header: 'X-Content-Type-Options'": {
        "severity": "Low",
        "description": "X-Content-Type-Options with nosniff prevents browsers from MIME-sniffing certain responses.",
        "attack": "In some application configurations, MIME sniffing can cause content to be interpreted differently from the declared type, increasing the impact of content injection weaknesses.",
        "fix": "Set X-Content-Type-Options: nosniff."
    },
    "Missing security header: 'Referrer-Policy'": {
        "severity": "Low",
        "description": "Referrer-Policy controls how much referrer information is sent with outbound requests.",
        "attack": "An overly permissive referrer policy can leak URL information, including sensitive path or query data, to third-party destinations.",
        "fix": "Use a restrictive policy such as strict-origin-when-cross-origin or another policy appropriate for the application."
    },
    "Missing security header: 'Permissions-Policy'": {
        "severity": "Low",
        "description": "Permissions-Policy restricts access to browser capabilities such as camera, microphone, and geolocation.",
        "attack": "If powerful browser features are unnecessarily available to embedded or application content, the impact of another compromise may be increased.",
        "fix": "Define a restrictive Permissions-Policy and explicitly allow only features the application requires."
    },

    # SSL / TLS
    "SSL certificate verification failed": {
        "severity": "High",
        "description": "The TLS certificate could not be verified by the scanner.",
        "attack": "Users may be exposed to connection interception or certificate trust failures if the deployment is incorrectly configured.",
        "fix": "Install a valid certificate issued by a trusted certificate authority and configure the complete certificate chain correctly."
    },
    "SSL certificate expires": {
        "severity": "Medium",
        "description": "The TLS certificate is approaching expiration.",
        "attack": "An expired certificate can cause browser trust errors and may interrupt secure access to the application.",
        "fix": "Renew the certificate before expiration and automate certificate renewal where practical."
    },
    "SSL check failed": {
        "severity": "Medium",
        "description": "The scanner could not complete the TLS configuration check.",
        "attack": "A failed check is not proof of a vulnerability, but it can indicate a TLS configuration or connectivity problem that should be investigated.",
        "fix": "Verify that TCP/443 is reachable and that the server presents a valid certificate and supported TLS configuration."
    },

    # Network exposure
    "potentially dangerous": {
        "severity": "High",
        "description": "A commonly sensitive network service is reachable from the scanner.",
        "attack": "An exposed service can increase the attack surface. If the service is vulnerable, weakly authenticated, or misconfigured, an attacker may attempt unauthorized access or exploitation.",
        "fix": "Close unnecessary ports, restrict administrative services with firewall rules or network controls, and require strong authentication and secure configurations."
    },
    "Port 22 (SSH) is open": {
        "severity": "Low",
        "description": "SSH is reachable on the tested host.",
        "attack": "Exposed SSH increases the remotely reachable attack surface and can be targeted with credential attacks or exploitation of vulnerable server software.",
        "fix": "Restrict SSH access to trusted networks where possible, disable password authentication when appropriate, use key-based authentication, and keep the service patched."
    },

    # Sensitive paths
    "Sensitive path accessible": {
        "severity": "High",
        "description": "A commonly sensitive administrative, configuration, backup, source-control, or documentation path returned HTTP 200.",
        "attack": "An attacker can enumerate exposed resources and may retrieve administrative interfaces, configuration data, backups, source code, or API documentation.",
        "fix": "Remove unnecessary public resources and protect administrative/configuration endpoints with authentication and authorization. Do not expose secrets or source-control directories."
    },
    "Path exists but forbidden": {
        "severity": "Low",
        "description": "A commonly sensitive path exists but returned HTTP 403.",
        "attack": "The path itself is not publicly accessible, but its existence can reveal application structure and provide an enumeration target.",
        "fix": "Keep sensitive resources inaccessible from untrusted users and ensure directory or endpoint discovery does not expose unnecessary information."
    },

    # Cookies
    "missing Secure flag": {
        "severity": "Medium",
        "description": "The cookie is not marked Secure, so browsers may send it over non-HTTPS connections.",
        "attack": "If the cookie is sent over an insecure connection, an attacker able to observe network traffic may capture it.",
        "fix": "Set the Secure attribute on authentication and other sensitive cookies and enforce HTTPS."
    },
    "missing HttpOnly flag": {
        "severity": "High",
        "description": "The cookie is accessible to client-side scripts because HttpOnly is not set.",
        "attack": "If malicious JavaScript executes in the browser, it may be able to read the cookie and potentially expose session information.",
        "fix": "Set HttpOnly on sensitive cookies, especially session cookies, unless client-side access is explicitly required."
    },

    # Information disclosure
    "Server header exposes info": {
        "severity": "Low",
        "description": "The Server response header reveals server implementation information.",
        "attack": "Version or product information can help an attacker fingerprint the technology stack and prioritize known vulnerabilities.",
        "fix": "Minimize unnecessary server-identifying response headers and keep the underlying server software patched."
    },
    "X-Powered-By header exposes info": {
        "severity": "Low",
        "description": "The X-Powered-By response header reveals application framework or runtime information.",
        "attack": "Technology disclosure can make fingerprinting and vulnerability enumeration easier.",
        "fix": "Remove or suppress X-Powered-By where practical."
    },

    # Domain / DNS / email
    "newly registered": {
        "severity": "Info",
        "description": "The domain was registered recently.",
        "attack": "Domain age alone is not a vulnerability. Newly registered domains can, however, receive additional scrutiny because attackers sometimes use short-lived infrastructure.",
        "fix": "No direct remediation is required. Treat domain age as contextual information rather than proof of compromise."
    },
    "DNSSEC is not enabled": {
        "severity": "Medium",
        "description": "DNSSEC was not detected for the domain.",
        "attack": "Without DNSSEC validation, DNS integrity protections are reduced and DNS responses can be more exposed to certain spoofing or cache-poisoning scenarios.",
        "fix": "Deploy DNSSEC correctly through the authoritative DNS provider and registrar, and verify the DS/DNSKEY chain."
    },
    "No SPF record": {
        "severity": "Medium",
        "description": "No SPF record was detected for the domain.",
        "attack": "Attackers may attempt to send email that appears to originate from the domain. SPF alone is not sufficient to prevent all spoofing.",
        "fix": "Publish an SPF record listing authorized sending infrastructure and combine it with DKIM and DMARC."
    },
    "No DMARC record": {
        "severity": "Medium",
        "description": "No DMARC policy was detected for the domain.",
        "attack": "Attackers may spoof the domain in email, increasing the likelihood of phishing or impersonation reaching recipients.",
        "fix": "Publish a DMARC record and progressively move toward an enforcement policy such as quarantine or reject after validating legitimate senders."
    },
    "No DKIM record": {
        "severity": "Low",
        "description": "No DKIM record was found at the default selector checked by this scanner.",
        "attack": "Without DKIM, recipients may have fewer cryptographic signals to verify that messages were authorized by the domain.",
        "fix": "Configure DKIM for the actual mail provider and publish the provider's selector. Note that this scanner checks only the default selector."
    },

    # HTTP methods
    "Dangerous HTTP method enabled": {
        "severity": "Medium",
        "description": "The server advertises an HTTP method that is not normally required by many public web applications.",
        "attack": "Unnecessary methods can expand the attack surface. The actual impact depends on server configuration, authentication, and endpoint behavior.",
        "fix": "Disable methods that are not required and restrict required methods to authenticated or authorized endpoints where appropriate."
    },

    # Redirects
    "Long redirect chain": {
        "severity": "Low",
        "description": "The requested URL follows multiple redirects before reaching its final destination.",
        "attack": "Long or unexpected redirect chains can make destination analysis harder and may be abused to conceal malicious redirects.",
        "fix": "Remove unnecessary redirects and verify that every redirect destination is trusted and intentional."
    },

    # Content sniffing / clickjacking
    "X-Content-Type-Options header missing": {
        "severity": "Low",
        "description": "The response does not explicitly disable MIME sniffing.",
        "attack": "In certain content-injection configurations, browser MIME sniffing can cause resources to be interpreted as a different content type.",
        "fix": "Set X-Content-Type-Options: nosniff and return correct Content-Type values."
    },
    "No clickjacking protection found": {
        "severity": "Medium",
        "description": "The page does not provide a detected control preventing framing by other origins.",
        "attack": "An attacker may frame the application inside a malicious page and attempt to trick users into interacting with the framed interface.",
        "fix": "Set X-Frame-Options or, preferably for modern policies, CSP frame-ancestors."
    },

    # Subdomains / robots
    "Subdomain found": {
        "severity": "Low",
        "description": "A commonly named subdomain resolves for the domain.",
        "attack": "Additional subdomains increase the exposed attack surface and may contain development, staging, administrative, or legacy services.",
        "fix": "Inventory all subdomains, remove unused hosts, and ensure development or administrative environments are access-controlled."
    },
    "publicly accessible — may expose sensitive paths": {
        "severity": "Info",
        "description": "robots.txt or sitemap.xml is publicly accessible.",
        "attack": "These files are normally public, but robots.txt can reveal paths that administrators intended search engines not to crawl.",
        "fix": "Do not place secrets in robots.txt or sitemap.xml. Protect sensitive resources using authentication and authorization rather than robots.txt."
    },

    # Rate limiting
    "No rate limiting headers detected": {
        "severity": "Medium",
        "description": "The response did not expose common rate-limiting headers.",
        "attack": "Lack of visible rate-limit headers does not prove that rate limiting is absent, but insufficient request controls can make credential attacks and automated abuse easier.",
        "fix": "Implement server-side rate limiting appropriate to authentication, API, and resource-intensive endpoints. Return standard rate-limit information where useful."
    },

    # Mixed content
    "Mixed content found": {
        "severity": "Medium",
        "description": "An HTTPS page references a resource using HTTP.",
        "attack": "An attacker able to interfere with the insecure HTTP resource may modify content delivered to an otherwise HTTPS page.",
        "fix": "Load all page resources over HTTPS and update hard-coded HTTP URLs or use HTTPS-compatible resource URLs."
    },
}


def _metadata_for(text: str, status: str) -> dict:
    """
    Match a finding to remediation metadata using exact prefixes/keywords.
    The matching is intentionally deterministic and avoids expensive NLP/ML
    for a small, fixed scanner rule set.
    """
    for key, metadata in FINDING_METADATA.items():
        if key in text:
            return metadata

    # Safe/info messages do not require vulnerability remediation details.
    if status == "safe":
        return {
            "severity": "Info",
            "description": "No security weakness was detected by this check.",
            "attack": "No attack scenario is indicated by this finding.",
            "fix": "No remediation is required based on this result."
        }

    if status == "info":
        return {
            "severity": "Info",
            "description": "Informational result from the security scan.",
            "attack": "This result is not by itself evidence of a vulnerability.",
            "fix": "Review the result in the context of the application's security requirements."
        }

    if status == "warning":
        return {
            "severity": "Low",
            "description": "The scanner identified a condition that may warrant review.",
            "attack": "The condition may contribute to attack surface or information disclosure depending on the application configuration.",
            "fix": "Review the finding and apply appropriate hardening if the condition is unnecessary."
        }

    return {
        "severity": "Medium",
        "description": "The scanner identified a potentially security-relevant condition.",
        "attack": "An attacker may attempt to abuse the condition depending on the application's configuration and other controls.",
        "fix": "Review the affected component and apply the recommended security hardening."
    }


def enrich_scan_results(scan_results: dict) -> dict:
    """
    Add severity and remediation context to every scanner finding.
    Keeps the original status/text fields for frontend compatibility.
    """
    enriched = {}

    for category, results in scan_results.items():
        enriched[category] = []

        for result in results:
            metadata = _metadata_for(result["text"], result["status"])
            enriched[category].append({
                **result,
                "severity": metadata["severity"],
                "description": metadata["description"],
                "attack": metadata["attack"],
                "fix": metadata["fix"],
            })

    return enriched


def get_severity_summary(scan_results: dict) -> dict:
    summary = {severity: 0 for severity in SEVERITY_RANK}

    for results in scan_results.values():
        for result in results:
            severity = result.get("severity", "Info")
            summary[severity] = summary.get(severity, 0) + 1

    return summary


def generate_txt_report(url: str, scan_results: dict) -> str:
    """
    Generate a detailed text report containing:
    - finding
    - severity
    - explanation
    - general attack scenario
    - recommended remediation
    - severity summary
    """
    lines = [
        "=" * 72,
        "              CYBERTHREAT SHIELD - VULNERABILITY REPORT",
        "=" * 72,
        f"URL: {url}",
        f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 72,
    ]

    summary = get_severity_summary(scan_results)

    lines.extend([
        "",
        "SEVERITY SUMMARY",
        "-" * 40,
        f"Critical : {summary.get('Critical', 0)}",
        f"High     : {summary.get('High', 0)}",
        f"Medium   : {summary.get('Medium', 0)}",
        f"Low      : {summary.get('Low', 0)}",
        f"Info     : {summary.get('Info', 0)}",
        "",
    ])

    for category, results in scan_results.items():
        lines.extend([
            f"[ {category} ]",
            "-" * 72,
        ])

        for result in results:
            severity = result.get("severity", "Info")

            lines.extend([
                f"[ {severity.upper()} ] {result['text']}",
                "",
                "Description:",
                f"  {result.get('description', 'No description available.')}",
                "",
                "General Attack Scenario:",
                f"  {result.get('attack', 'No attack scenario available.')}",
                "",
                "Recommended Fix:",
                f"  {result.get('fix', 'Review and harden the affected component.')}",
                "",
                "-" * 72,
            ])

        lines.append("")

    lines.extend([
        "=" * 72,
        "IMPORTANT: Findings are based on non-invasive automated checks.",
        "A finding does not prove exploitability. Manual validation is required",
        "before treating a result as a confirmed vulnerability.",
        "=" * 72,
        "End of Report",
        "=" * 72,
    ])

    return "\n".join(lines)
