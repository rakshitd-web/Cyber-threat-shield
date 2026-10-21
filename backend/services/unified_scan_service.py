from __future__ import annotations

from urllib.parse import urlparse
import ipaddress
import socket

from services.link_checker import scan_link
from services.vuln_scanner import (
    run_scan,
    enrich_scan_results,
    get_severity_summary,
)
from utils.brand_check import check_brand_impersonation, KNOWN_BRANDS as KNOWN_BRANDS_MAP
from utils.url_features import extract_features, get_feature_reasons
from services.threat_intel import check_virustotal, check_domain_age, follow_redirects
from services.ml_model import predict


VULNERABILITY_CHECKS = [
    "headers", "ssl", "ports", "paths", "cookies", "server",
    "whois", "dns", "methods", "redirects", "sniffing",
    "clickjacking", "email", "subdomains", "robots", "ratelimit", "mixed"
]


def _normalise_and_validate_url(raw_url: str) -> str:
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise ValueError("Enter a website URL.")

    value = raw_url.strip()
    if any(ord(char) < 32 for char in value):
        raise ValueError("The URL contains invalid control characters.")
    if "://" not in value:
        value = "https://" + value

    parsed = urlparse(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a valid HTTP or HTTPS URL.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing embedded usernames or passwords are not accepted.")

    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("The URL contains an invalid port.") from exc

    host = parsed.hostname
    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_global:
            raise ValueError("Scanning private or non-public IP addresses is blocked.")
    except ValueError as exc:
        if str(exc) == "Scanning private or non-public IP addresses is blocked.":
            raise
        # Hostnames are resolved and checked here to reject internal destinations.
        try:
            addresses = {
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            }
        except socket.gaierror as dns_exc:
            raise ValueError(f"Could not resolve hostname: {host}") from dns_exc
        if not addresses or any(not address.is_global for address in addresses):
            raise ValueError("The hostname resolves to a private or non-public IP address; scan blocked.")

    return value


def _run_phishing_scan(url: str) -> dict:
    parsed = urlparse(url)
    domain = parsed.hostname or ""
    vt_result = check_virustotal(url)
    domain_age = check_domain_age(domain)
    redirect_result = follow_redirects(url)

    is_impersonating, brand = check_brand_impersonation(url)
    features = extract_features(url)
    prediction, confidence = predict(features)
    result = "Phishing" if prediction == 0 else "Legitimate"
    warning = None

    if is_impersonating:
        result = "Phishing"
        confidence = max(float(confidence), 0.90)
        warning = (
            f"URL contains '{brand}' but is not the official "
            f"{KNOWN_BRANDS_MAP.get(brand, brand)} domain."
        )

    if vt_result.get("available") and vt_result.get("flagged"):
        result = "Phishing"
        confidence = max(float(confidence), 0.95)

    reasons = get_feature_reasons(url)
    if is_impersonating:
        reasons.insert(0, {
            "flag": "danger",
            "text": (
                f"Domain impersonates '{brand}' — not the official "
                f"{KNOWN_BRANDS_MAP.get(brand, brand)} domain"
            ),
        })

    if vt_result.get("available"):
        if vt_result.get("flagged"):
            reasons.insert(0, {
                "flag": "danger",
                "text": (
                    f"VirusTotal flagged this URL: {vt_result.get('malicious', 0)} "
                    f"malicious and {vt_result.get('suspicious', 0)} suspicious "
                    f"engines out of {vt_result.get('total', 0)}."
                ),
            })
        else:
            reasons.insert(0, {
                "flag": "safe",
                "text": f"VirusTotal did not flag this URL across {vt_result.get('total', 0)} engines.",
            })

    if redirect_result.get("available") and redirect_result.get("suspicious"):
        reasons.insert(0, {
            "flag": "danger",
            "text": f"Redirects to a different domain: {redirect_result.get('final_url')}",
        })

    if domain_age.get("available") and domain_age.get("is_new"):
        reasons.append({
            "flag": "warning",
            "text": f"Domain is newly registered ({domain_age.get('age_days')} days old). Domain age alone does not prove phishing.",
        })

    return {
        "status": result,
        "confidence": round(float(confidence), 4),
        "warning": warning,
        "reasons": reasons,
        "threat_intelligence": vt_result,
        "domain_age": domain_age,
        "redirect_analysis": redirect_result,
    }


def run_unified_scan(raw_url: str) -> dict:
    url = _normalise_and_validate_url(raw_url)
    report = {
        "url": url,
        "modules": {},
        "overall_status": "Review required",
        "disclaimer": (
            "Automated results are indicators, not a guarantee of safety. "
            "Only scan websites you own or are explicitly authorized to assess."
        ),
    }

    # Each module is isolated so one module failure does not erase other results.
    try:
        link_result = scan_link(url)
        report["modules"]["link_scanner"] = {
            "success": bool(link_result.get("success", link_result.get("valid", False))),
            "risk_level": link_result.get("risk_level", "UNKNOWN"),
            "risk_score": link_result.get("risk_score", 0),
            "confirmed_threat_match": link_result.get("confirmed_threat_match", False),
            "findings": link_result.get("findings", []),
            "error": link_result.get("error"),
        }
    except Exception as exc:
        report["modules"]["link_scanner"] = {"success": False, "error": str(exc)}

    try:
        raw_vuln = run_scan(url, VULNERABILITY_CHECKS)
        vuln_results = enrich_scan_results(raw_vuln)
        report["modules"]["vulnerability_detection"] = {
            "success": True,
            "results": vuln_results,
            "severity_summary": get_severity_summary(vuln_results),
        }
    except Exception as exc:
        report["modules"]["vulnerability_detection"] = {"success": False, "error": str(exc)}

    try:
        report["modules"]["phishing_detection"] = {
            "success": True,
            **_run_phishing_scan(url),
        }
    except Exception as exc:
        report["modules"]["phishing_detection"] = {"success": False, "error": str(exc)}

    link = report["modules"].get("link_scanner", {})
    phishing = report["modules"].get("phishing_detection", {})
    if link.get("confirmed_threat_match") or phishing.get("status") == "Phishing":
        report["overall_status"] = "High risk"
    elif any(
        item.get("success") is False
        for item in report["modules"].values()
    ):
        report["overall_status"] = "Partial scan"
    elif link.get("risk_level") in {"HIGH", "CRITICAL"}:
        report["overall_status"] = "High risk"
    else:
        report["overall_status"] = "Review findings"

    return report
