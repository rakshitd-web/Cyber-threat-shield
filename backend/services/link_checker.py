
from __future__ import annotations

import base64
import ipaddress
import os
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, urlunparse

try:
    import requests
except ImportError:
    requests = None
try:
    import dns.resolver
except ImportError:
    dns = None
try:
    import tldextract
except ImportError:
    tldextract = None

USER_AGENT = "CyberThreatShield-LinkScanner/2.0"
TIMEOUT = max(2, min(int(os.getenv("LINK_SCAN_TIMEOUT_SECONDS", "8")), 20))
MAX_REDIRECTS = max(0, min(int(os.getenv("LINK_SCAN_MAX_REDIRECTS", "8")), 15))
REDIRECT_CODES = {301, 302, 303, 307, 308}
SUSPICIOUS_TOKENS = ("login", "verify", "verification", "secure", "account", "update",
                     "password", "wallet", "banking", "signin", "confirm", "gift", "free",
                     "bonus", "claim", "support", "payment", "invoice", "webscr")


def _now():
    return datetime.now(timezone.utc).isoformat()


def _normalise_url(raw_url: str) -> str:
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise ValueError("Enter a URL to scan.")
    value = raw_url.strip()
    if any(ord(c) < 32 for c in value):
        raise ValueError("The URL contains control characters.")
    if "://" not in value:
        value = "https://" + value
    p = urlparse(value)
    if p.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if not p.hostname:
        raise ValueError("The URL does not contain a valid hostname.")
    if p.username is not None or p.password is not None:
        raise ValueError("URLs containing embedded usernames or passwords are not accepted.")
    try:
        port = p.port
    except ValueError as exc:
        raise ValueError("The URL contains an invalid port.") from exc
    host = p.hostname.encode("idna").decode("ascii").lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host + (f":{port}" if port is not None else "")
    return urlunparse((p.scheme.lower(), netloc, p.path or "/", p.params, p.query, ""))


def _public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return ip.is_global and not (ip.is_private or ip.is_loopback or ip.is_link_local or
                                     ip.is_multicast or ip.is_reserved or ip.is_unspecified)
    except ValueError:
        return False


def _resolve_public_host(host: str) -> list[str]:
    try:
        ip = ipaddress.ip_address(host)
        if not _public_ip(str(ip)):
            raise ValueError("Scanning private or non-public IP addresses is blocked.")
        return [str(ip)]
    except ValueError as exc:
        if str(exc) == "Scanning private or non-public IP addresses is blocked.":
            raise
    try:
        addresses = sorted({str(ipaddress.ip_address(row[4][0]))
                            for row in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
    except socket.gaierror as exc:
        raise ValueError(f"DNS resolution failed for {host}: {exc}") from exc
    if not addresses:
        raise ValueError(f"No IP addresses were returned for {host}.")
    if any(not _public_ip(addr) for addr in addresses):
        raise ValueError("The hostname resolves to a private or non-public IP address; scan blocked.")
    return addresses


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _domain_parts(host: str) -> dict:
    result = {"hostname": host, "registered_domain": host, "subdomain": "",
              "suffix": host.rsplit(".", 1)[-1] if "." in host else "",
              "is_ip": _is_ip(host), "ip": host if _is_ip(host) else None}
    if result["is_ip"]:
        return result
    if tldextract is not None:
        try:
            ext = tldextract.extract(host)
            registered = ".".join(x for x in (ext.domain, ext.suffix) if x)
            result.update(registered_domain=registered or host, subdomain=ext.subdomain, suffix=ext.suffix)
            return result
        except Exception:
            pass
    labels = host.split(".")
    if len(labels) >= 2:
        result["registered_domain"] = ".".join(labels[-2:])
        result["subdomain"] = ".".join(labels[:-2])
    return result


def _dns_records(host: str) -> dict:
    result = {"available": dns is not None, "records": {}, "errors": []}
    if dns is None:
        result["errors"].append("dnspython is not installed; DNS enrichment is unavailable.")
        return result
    for kind in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        try:
            answers = dns.resolver.resolve(host, kind, lifetime=3)
            result["records"][kind] = [a.to_text()[:500] for a in list(answers)[:20]]
        except Exception as exc:
            result["records"][kind] = []
            if kind in {"A", "AAAA", "MX", "NS"}:
                result["errors"].append(f"{kind}: {type(exc).__name__}")
    return result


def _cert_name(value) -> str | None:
    try:
        return ", ".join(f"{k}={v}" for group in value for k, v in group)
    except Exception:
        return None


def _tls_info(host: str) -> dict:
    result = {"https": True, "valid": False, "subject": None, "issuer": None,
              "not_before": None, "not_after": None, "days_remaining": None, "error": None}
    try:
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as conn:
                cert = conn.getpeercert()
        result.update(valid=True, subject=_cert_name(cert.get("subject", [])),
                      issuer=_cert_name(cert.get("issuer", [])),
                      not_before=cert.get("notBefore"), not_after=cert.get("notAfter"))
        if cert.get("notAfter"):
            expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            result["days_remaining"] = (expiry - datetime.now(timezone.utc)).days
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
    return result


def _http_scan(start_url: str) -> dict:
    result = {"reachable": False, "status_code": None, "final_url": start_url, "headers": {},
              "redirects": {"count": 0, "chain": [], "details": []}, "error": None,
              "content_type": None, "server": None}
    if requests is None:
        result["error"] = "The requests package is not installed."
        return result
    current = start_url
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
    try:
        for _ in range(MAX_REDIRECTS + 1):
            p = urlparse(current)
            if p.scheme not in {"http", "https"} or not p.hostname:
                raise ValueError("Redirect target is not a valid HTTP/HTTPS URL.")
            # Validate every redirect destination before issuing a request to it.
            _resolve_public_host(p.hostname)
            try:
                response = session.get(current, timeout=TIMEOUT, allow_redirects=False,
                                       stream=True, verify=True)
            except requests.RequestException as exc:
                result["error"] = f"{type(exc).__name__}: {str(exc)[:250]}"
                break
            result.update(reachable=True, status_code=response.status_code, final_url=current,
                          headers={str(k).lower(): str(v)[:1000] for k, v in response.headers.items()},
                          content_type=response.headers.get("Content-Type"),
                          server=response.headers.get("Server"))
            status, location = response.status_code, response.headers.get("Location")
            response.close()
            if status not in REDIRECT_CODES or not location:
                break
            target = _normalise_url(urljoin(current, location))
            result["redirects"]["chain"].append(target)
            result["redirects"]["details"].append({"status_code": status, "url": current, "location": target})
            result["redirects"]["count"] += 1
            if result["redirects"]["count"] > MAX_REDIRECTS:
                result["error"] = f"Redirect limit ({MAX_REDIRECTS}) exceeded."
                break
            current = target
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {str(exc)[:250]}"
    finally:
        session.close()
    return result


def _url_structure(url: str) -> dict:
    p = urlparse(url)
    host = p.hostname or ""
    return {"length": len(url), "hostname": host, "scheme": p.scheme, "path": p.path,
            "params": p.query, "query_length": len(p.query),
            "subdomain_count": max(0, len(host.split(".")) - 2), "has_ip": _is_ip(host),
            "has_at_symbol": "@" in url, "has_punycode": "xn--" in host.lower(),
            "has_percent_encoding": bool(re.search(r"%[0-9a-fA-F]{2}", url)),
            "has_double_slash_in_path": "//" in p.path,
            "suspicious_tokens": sorted({x for x in SUSPICIOUS_TOKENS if x in url.lower()})}


def _security_headers(headers: dict) -> dict:
    expected = {
        "strict-transport-security": "Helps enforce HTTPS in supporting browsers.",
        "content-security-policy": "Restricts the sources from which page content can load.",
        "x-content-type-options": "Helps prevent MIME-type sniffing.",
        "x-frame-options": "Can reduce clickjacking risk.",
        "referrer-policy": "Controls referrer information sent to other sites.",
        "permissions-policy": "Restricts access to selected browser features.",
    }
    checks, missing = {}, []
    for key, purpose in expected.items():
        present = key in headers
        checks[key] = {"present": present, "value": headers.get(key), "purpose": purpose}
        if not present:
            missing.append(key)
    return {"checks": checks, "missing": missing, "count_missing": len(missing)}


def _rdap_lookup(host: str) -> dict:
    result = {"available": False, "domain": None, "events": [], "error": None}
    if requests is None:
        result["error"] = "requests package is not installed."
        return result
    parts = _domain_parts(host)
    domain = parts["registered_domain"]
    if parts["is_ip"] or "." not in domain:
        result["error"] = "RDAP domain lookup is not applicable to this hostname."
        return result
    try:
        response = requests.get("https://rdap.org/domain/" + domain, timeout=TIMEOUT,
                                headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json"})
        if response.status_code != 200:
            result["error"] = f"RDAP returned HTTP {response.status_code}."
            return result
        data = response.json()
        result.update(available=True, domain=data.get("ldhName") or domain)
        result["events"] = [{"action": e.get("eventAction"), "date": e.get("eventDate")}
                            for e in data.get("events", []) if e.get("eventAction") and e.get("eventDate")]
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
    return result


def _threat_intelligence(url: str) -> dict:
    result = {
        "google_safe_browsing": {"configured": False, "checked": False, "known_threat": False, "matches": [], "error": None},
        "virustotal": {"configured": False, "checked": False, "known_threat": False, "detections": None, "total_engines": None, "error": None},
    }
    if requests is None:
        for item in result.values():
            item["error"] = "requests package is not installed."
        return result
    google_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if google_key:
        item = result["google_safe_browsing"]
        item["configured"] = True
        payload = {"client": {"clientId": "cyberthreat-shield", "clientVersion": "2.0"},
                   "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                                    "POTENTIALLY_HARMFUL_APPLICATION"],
                                  "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                                  "threatEntries": [{"url": url}]}}
        try:
            response = requests.post("https://safebrowsing.googleapis.com/v4/threatMatches:find",
                                     params={"key": google_key}, json=payload, timeout=TIMEOUT)
            if response.ok:
                matches = response.json().get("matches", [])
                item.update(checked=True, known_threat=bool(matches),
                            matches=[{"threatType": m.get("threatType"), "platformType": m.get("platformType")}
                                     for m in matches[:10]])
            else:
                item["error"] = f"Google Safe Browsing returned HTTP {response.status_code}."
        except Exception as exc:
            item["error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if vt_key:
        item = result["virustotal"]
        item["configured"] = True
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                                    headers={"x-apikey": vt_key, "User-Agent": USER_AGENT}, timeout=TIMEOUT)
            if response.status_code == 200:
                stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                detections = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
                total = sum(int(v) for v in stats.values() if isinstance(v, (int, float)))
                item.update(checked=True, known_threat=detections > 0, detections=detections, total_engines=total)
            elif response.status_code == 404:
                item["error"] = "URL not found in VirusTotal; it was not submitted for scanning."
            else:
                item["error"] = f"VirusTotal returned HTTP {response.status_code}."
        except Exception as exc:
            item["error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
    return result


def _compute_risk(url: str, structure: dict, domain: dict, tls: dict, http: dict,
                  security: dict, rdap: dict, threat: dict) -> dict:
    findings, score = [], 0

    def add(code, title, points, severity, details, recommendation, evidence=None):
        nonlocal score
        score += points
        findings.append({"code": code, "title": title, "points": points, "severity": severity,
                         "details": details, "recommendation": recommendation, "evidence": evidence})

    if structure["has_ip"]:
        add("ip_hostname", "URL uses an IP address", 15, "medium", "The URL uses an IP address instead of a conventional domain name.", "Verify the destination through a trusted source.", structure["hostname"])
    if structure["has_punycode"]:
        add("punycode", "Punycode hostname detected", 12, "medium", "Internationalized hostnames can be used for lookalike-domain attacks.", "Check the hostname carefully for visually similar characters.", structure["hostname"])
    if structure["has_at_symbol"]:
        add("at_symbol", "At-sign present in URL", 12, "medium", "An at-sign can make the apparent URL destination misleading.", "Inspect the parsed hostname, not just the displayed URL.")
    if structure["length"] > 180:
        add("long_url", "Unusually long URL", 8, "low", "Long URLs can obscure the destination.", "Confirm the hostname and query parameters.")
    if structure["subdomain_count"] >= 4:
        add("many_subdomains", "Large number of subdomains", 8, "low", "The hostname contains several subdomain levels.", "Confirm that the complete hostname is expected.", structure["hostname"])
    if structure["has_percent_encoding"]:
        add("percent_encoding", "Percent-encoded URL characters", 4, "low", "Percent encoding can obscure URL content.", "Inspect the URL if it was received unexpectedly.")
    if structure["suspicious_tokens"]:
        add("suspicious_tokens", "Potentially deceptive URL keywords", 8, "low", "The URL contains words sometimes used in credential theft or misleading offers.", "Do not enter credentials unless the site is independently verified.", structure["suspicious_tokens"])
    if domain.get("suffix") in {"zip", "mov"}:
        add("uncommon_tld", "TLD sometimes used in misleading links", 3, "low", "This TLD can also resemble a common file extension.", "Verify the registered domain before opening the link.", domain.get("suffix"))
    if urlparse(url).scheme == "http":
        add("no_https", "Connection does not use HTTPS", 15, "medium", "The URL uses unencrypted HTTP.", "Do not submit passwords or payment information.")
    elif not tls.get("valid"):
        add("tls_problem", "TLS certificate could not be validated", 18, "high", "A valid TLS certificate could not be confirmed.", "Do not bypass browser certificate warnings.", tls.get("error"))

    cross_domain = []
    for hop in http.get("redirects", {}).get("details", http.get("redirects", {}).get("chain", [])):
        destination = hop.get("location") if isinstance(hop, dict) else str(hop)
        target_host = (urlparse(destination).hostname or "").lower()
        if target_host and target_host != (urlparse(url).hostname or "").lower():
            cross_domain.append(destination)
    if cross_domain:
        add("cross_domain_redirect", "Cross-domain redirect detected", 5, "low", "At least one redirect points to a different hostname; this can be legitimate but deserves review.", "Confirm each redirect destination belongs to the expected service.", cross_domain)
    if security.get("count_missing", 0) >= 4:
        add("missing_security_headers", "Several security headers are missing", 5, "low", "Several recommended browser security headers are absent.", "Site operators should review the missing headers.", security.get("missing"))

    for event in rdap.get("events", []):
        if event.get("action", "").lower() in {"registration", "registered"} and event.get("date"):
            try:
                registered = datetime.fromisoformat(event["date"].replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - registered.astimezone(timezone.utc)).days
                domain["age_days"] = age_days
                if 0 <= age_days < 30:
                    add("new_domain", "Recently registered domain", 12, "medium", f"The domain appears to have been registered {age_days} days ago.", "Verify the site through an independent trusted source.", event["date"])
                break
            except Exception:
                pass

    google = threat.get("google_safe_browsing", {})
    vt = threat.get("virustotal", {})
    known = bool(google.get("known_threat") or vt.get("known_threat"))
    if google.get("known_threat"):
        add("google_safe_browsing_match", "Google Safe Browsing reported a threat", 100, "critical", "Google Safe Browsing returned a threat match for this URL.", "Do not open the link; follow your security reporting process.", google.get("matches"))
    if vt.get("known_threat"):
        add("virustotal_detections", "VirusTotal reports detections", 70, "critical", "VirusTotal engines classified the URL as malicious or suspicious.", "Avoid opening the link and verify through your security process.", {"detections": vt.get("detections"), "total_engines": vt.get("total_engines")})
    score = max(0, min(100, score))
    level = "Critical" if known else "High" if score >= 60 else "Medium" if score >= 30 else "Low"
    return {"score": score, "level": level, "findings": findings, "known_threat": known,
            "disclaimer": "This heuristic assessment cannot guarantee that a URL is safe or malicious."}


def _scan_link_core(raw_url: str) -> dict:
    """Scan one public HTTP/HTTPS URL; return a JSON-serializable report."""
    started = time.monotonic()
    try:
        url = _normalise_url(raw_url)
        parsed = urlparse(url)
        host = parsed.hostname or ""
        ips = _resolve_public_host(host)
    except Exception as exc:
        return {"success": False, "url": raw_url if isinstance(raw_url, str) else "", "error": str(exc),
                "risk": {"score": 0, "level": "Unknown", "findings": [], "known_threat": False},
                "collection_status": {"completed": False, "timestamp": _now()}}

    domain = _domain_parts(host)
    domain["ip"] = ips[0] if ips else None
    domain["ip_addresses"] = ips
    dns_data = _dns_records(host)
    tls = _tls_info(host) if parsed.scheme == "https" else {
        "https": False, "valid": False, "subject": None, "issuer": None, "not_before": None,
        "not_after": None, "days_remaining": None, "error": "The URL uses HTTP; no TLS certificate was checked."}
    http = _http_scan(url)
    headers = http.get("headers", {})
    security = _security_headers(headers)
    structure = _url_structure(url)
    rdap = _rdap_lookup(host)
    threat = _threat_intelligence(url)
    risk = _compute_risk(url, structure, domain, tls, http, security, rdap, threat)
    legacy = {"url": url,
              "domain": {"hostname": host, "ip": ips[0] if ips else None, "ips": ips, "registered_domain": domain.get("registered_domain")},
              "ssl": {"https": parsed.scheme == "https", "valid": tls.get("valid"), **tls},
              "redirects": http.get("redirects", {"count": 0, "chain": []}),
              "url_structure": structure,
              "http": {k: http.get(k) for k in ("reachable", "status_code", "final_url", "content_type", "server", "error")},
              "security_headers": security, "risk": risk}
    return {"success": True, "url": url, "scanned_at": _now(),
            "duration_seconds": round(time.monotonic() - started, 3), "domain": domain, "dns": dns_data,
            "ssl": tls, "redirects": http.get("redirects", {"count": 0, "chain": []}),
            "http": {"reachable": http.get("reachable"), "status_code": http.get("status_code"),
                     "final_url": http.get("final_url"), "headers": headers, "content_type": http.get("content_type"),
                     "server": http.get("server"), "error": http.get("error")},
            "url_structure": structure, "security_headers": security, "rdap": rdap,
            "threat_intelligence": threat, "risk": risk, "legacy_summary": legacy,
            "collection_status": {"completed": True, "timestamp": _now(), "notes": [
                "Public DNS, TLS, HTTP, RDAP and optional threat-intelligence checks are best-effort.",
                "Threat-intelligence checks require API keys in the server environment.",
                "A low risk score does not prove that a URL is safe."]}}



def scan_link(raw_url: str) -> dict:
    """Frontend-compatible public scan function.

    Keeps the detailed technical payload while exposing the flat fields that
    link_scanner.html expects.
    """
    result = _scan_link_core(raw_url)

    # A validation failure is returned as a structured result; expose the
    # fields the frontend uses so it can show an understandable error state.
    if not result.get("success"):
        return {
            **result,
            "valid": False,
            "normalized_url": "",
            "risk_level": "UNKNOWN",
            "risk_score": 0,
            "risk_reasons": [result.get("error", "The URL could not be scanned.")],
            "findings": [],
        }

    risk = result.get("risk") or {}
    domain = result.get("domain") or {}
    tls = result.get("ssl") or {}
    http = result.get("http") or {}
    structure = result.get("url_structure") or {}
    security = result.get("security_headers") or {}
    redirects = result.get("redirects") or {}
    rdap = result.get("rdap") or {}

    checks = security.get("checks") or {}

    def header_present(name: str) -> bool:
        # Read the normalized detailed representation; do not infer presence
        # from whether the target website itself is trustworthy.
        item = checks.get(name)
        if isinstance(item, dict):
            return bool(item.get("present"))
        return name in (http.get("headers") or {})

    # Convert detailed findings to the names expected by the current template.
    findings = []
    for item in risk.get("findings", []):
        if not isinstance(item, dict):
            continue
        findings.append({
            **item,
            "id": item.get("code"),
            "explanation": item.get("details", item.get("explanation", "")),
        })

    reasons = [
        f"{item.get('title', 'Finding')}: {item.get('details', '')}".strip()
        for item in findings
    ]

    redirect_chain = redirects.get("chain", [])
    redirect_details = redirects.get("details", [])
    # Prefer structured hops so the frontend can display HTTP status and target.
    display_chain = redirect_details if redirect_details else redirect_chain

    normalized_ssl = {
        **tls,
        "https": bool(tls.get("https")),
        "valid_cert": bool(tls.get("valid")),
        "expires": tls.get("not_after") or "-",
    }

    normalized_redirects = {
        **redirects,
        "count": redirects.get("count", len(redirect_chain)),
        "chain": display_chain,
        "final_status_code": http.get("status_code"),
        "final_url": http.get("final_url") or result.get("url"),
    }

    normalized_structure = {
        **structure,
        "subdomains": structure.get("subdomain_count", 0),
        "params": structure.get("params", ""),
        "suspicious_encoding": bool(
            structure.get("has_percent_encoding")
            or structure.get("has_punycode")
            or structure.get("has_at_symbol")
        ),
    }

    normalized_security = {
        **security,
        "hsts": header_present("strict-transport-security"),
        "csp": header_present("content-security-policy"),
        "x_frame_options": header_present("x-frame-options"),
        "x_content_type_options": header_present("x-content-type-options"),
    }

    collection_status = result.get("collection_status") or {}
    return {
        **result,
        "valid": True,
        "normalized_url": result.get("url", ""),
        "risk_level": str(risk.get("level", "Unknown")).upper(),
        "risk_score": risk.get("score", 0),
        "risk_reasons": reasons,
        "findings": findings,
        "risk_disclaimer": risk.get("disclaimer") or
            "Risk scores are heuristic and do not prove that a website is safe or malicious.",
        "confirmed_threat_match": bool(risk.get("known_threat")),
        "scoring_model": "Weighted heuristic scoring with optional threat-intelligence checks",
        "domain": {
            **domain,
            "hostname": domain.get("hostname") or (result.get("url") and urlparse(result["url"]).hostname),
            "ip": domain.get("ip") or (
                (domain.get("ip_addresses") or [None])[0]
            ),
            "resolvable": bool(domain.get("ip_addresses")),
        },
        "ssl": normalized_ssl,
        "redirects": normalized_redirects,
        "url_structure": normalized_structure,
        "security_headers": normalized_security,
        "registration": rdap,
        "scan_duration_ms": round(float(result.get("duration_seconds", 0)) * 1000),
        "scanner_version": "2.1",
        "collection_status": collection_status,
    }
