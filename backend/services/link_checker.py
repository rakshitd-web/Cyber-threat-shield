    cross_domain = []
    for hop in redirects.get("chain", []):
        dest = hop.get("location")
        if dest and urlparse(dest).hostname and urlparse(dest).hostname != structure.get("hostname"):
            cross_domain.append(dest)
    if cross_domain:
        add("cross_domain_redirect", "Cross-domain redirect detected", 5, "low", "At least one redirect points to a different hostname; this can be legitimate but deserves review.", "Confirm that each destination belongs to the expected service.", cross_domain)
    if structure.get("punycode_hostname"):
        add("punycode", "Internationalized/punycode hostname", 8, "medium", "The hostname contains punycode. This is not inherently malicious but can be used in lookalike domains.", "Inspect the rendered hostname carefully.")
    if structure.get("contains_ip_address"):
        add("ip_hostname", "URL uses an IP address instead of a domain", 8, "medium", "IP-based URLs can be legitimate but are common in disposable or deceptive infrastructure.", "Verify the destination owner and expected use.")
    if structure.get("contains_at_symbol"):
        add("at_symbol", "URL contains an @ symbol", 10, "medium", "An @ character in a URL can confuse readers about the actual hostname.", "Inspect the parsed hostname, not only the displayed URL.")
    if structure.get("subdomains", 0) > 3:
        add("many_subdomains", "Unusually deep subdomain structure", 4, "low", f"The hostname has {structure['subdomains']} subdomain labels.", "Check whether the hostname belongs to the expected registered domain.")
    if structure.get("suspicious_encoding"):
        add("encoded_url", "Percent-encoded URL characters", 3, "low", "The URL contains percent-encoded characters. Encoding is often legitimate but may obscure the path.", "Decode and inspect the URL path and query before opening it.")
    if structure.get("length", 0) > 200:
        add("long_url", "Unusually long URL", 3, "low", f"URL length is {structure['length']} characters.", "Inspect long query parameters and encoded paths.")
    if structure.get("suspicious_tokens"):
        add("suspicious_terms", "Security-sensitive terms in URL", 2, "low", "The URL contains terms often used on account and login pages; this is weak contextual evidence only.", "Check the domain independently and do not enter credentials unless the site is verified.", structure["suspicious_tokens"])
    missing = headers.get("missing", [])
    if len(missing) >= 5:
        add("headers_missing", "Several recommended security headers are missing", 5, "low", f"Missing headers: {', '.join(missing)}.", "Review headers appropriate to the site's functionality; header absence alone does not establish phishing.", missing)
    elif len(missing) >= 3:
        add("headers_missing", "Some recommended security headers are missing", 3, "low", f"Missing headers: {', '.join(missing)}.", "Review headers appropriate to the site's functionality.", missing)
    if rdap.get("available") and rdap.get("creation_date"):
        try:
            created = datetime.fromisoformat(rdap["creation_date"].replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - created.astimezone(timezone.utc)).days
            if 0 <= age_days <= 30:
                add("new_domain", "Recently registered domain", 8, "medium", f"RDAP indicates the domain was registered approximately {age_days} day(s) ago.", "Treat this as contextual evidence and verify the organization through independent channels.", {"age_days": age_days})
        except (ValueError, TypeError):
            pass

    score = min(100, score)
    if score >= 75:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"
    confirmed_threat = any(f["id"] == "known_threat" for f in findings) or (vt.get("checked") and vt_mal >= 3)
    if confirmed_threat:
        score = 100
        level = "CRITICAL"
    if not findings:
        findings.append({"id": "no_indicators", "title": "No configured risk indicators triggered", "points": 0, "severity": "info", "explanation": "The checks completed did not trigger the current heuristic rules. This is not proof that the site is safe.", "recommendation": "Continue to verify the domain and use caution with unexpected links.", "evidence": None})
    return {"risk_score": score, "risk_level": level, "risk_reasons": [f["title"] for f in findings if f["points"] > 0], "findings": findings, "scoring_model": "weighted-heuristic-v2", "confirmed_threat_match": confirmed_threat, "risk_disclaimer": "A low score does not prove a website is safe. Reputation coverage depends on configured providers and available evidence."}


def scan_link(raw_url: str) -> dict[str, Any]:
    started = time.perf_counter()
    url = normalize_url(raw_url)
    base: dict[str, Any] = {"url": raw_url, "normalized_url": url, "scanned_at": utc_now(), "scanner_version": "2.0"}
    if not is_valid_url(url):
        return {**base, "valid": False, "error": "Malformed URL. Enter a valid HTTP or HTTPS URL."}
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    ok, reason, ips = _validate_public_target(url)
    if not ok:
        return {**base, "valid": False, "error": f"Scan blocked by destination safety policy: {reason}", "domain": {"hostname": hostname, "ip_addresses": ips, "resolvable": bool(ips)}, "security_note": "The scanner blocks private and non-public destinations to reduce SSRF risk."}

    domain_info = resolve_domain(hostname)
    structure = analyze_url_structure(url)
    # Use the registrable domain for RDAP where possible.
    registered_domain = structure.get("registered_domain") or hostname
    rdap = collect_rdap(registered_domain)
    dns_info = collect_dns_records(hostname)
    ssl_info = check_ssl(hostname, parsed.port or (443 if parsed.scheme == "https" else 443)) if parsed.scheme == "https" else {"https": False, "valid_cert": False, "issuer": None, "expires": None, "subject": None, "san_domains": [], "tls_version": None, "cipher": None, "days_until_expiry": None, "error": "URL uses HTTP; TLS was not attempted."}
    redirects = analyze_redirects(url)
    http_info = collect_http_details(url, redirects)
    header_info = check_security_headers(http_info.get("all_response_headers", {}))
    threat_intel = {"google_safe_browsing": google_safe_browsing_lookup(url), "virustotal": virustotal_lookup(url)}
    risk = compute_risk(ssl_info, redirects, header_info, structure, threat_intel, rdap)

    result = {
        **base, "valid": True,
        "domain": domain_info,
        "registration": rdap,
        "dns": dns_info,
        "ssl": ssl_info,
        "redirects": redirects,
        "http": http_info,
        "url_structure": structure,
        "security_headers": header_info,
        "threat_intelligence": threat_intel,
        **risk,
        "scan_duration_ms": round((time.perf_counter() - started) * 1000, 2),
        "collection_status": {
            "dns": "partial" if dns_info.get("errors") else "completed",
            "registration": "completed" if rdap.get("available") else "unavailable",
            "tls": "completed" if ssl_info.get("https") or parsed.scheme == "http" else "failed_or_unavailable",
            "http": "completed" if http_info.get("reachable") else "failed_or_unavailable",
            "google_safe_browsing": "completed" if threat_intel["google_safe_browsing"].get("checked") else "not_configured_or_failed",
            "virustotal": "completed" if threat_intel["virustotal"].get("checked") else "not_configured_or_failed",
        },
    }
    # Backward-compatible summary fields used by the current frontend.
    result["legacy_summary"] = {
        "hostname": domain_info.get("hostname"), "ip": domain_info.get("ip"),
        "resolvable": domain_info.get("resolvable"), "https": ssl_info.get("https"),
        "valid_cert": ssl_info.get("valid_cert"), "issuer": ssl_info.get("issuer"), "expires": ssl_info.get("expires"),
        "redirect_count": redirects.get("count"), "final_status_code": redirects.get("final_status_code"),
        "final_url": redirects.get("final_url"),
    }
    return result
