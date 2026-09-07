import requests
from typing import Optional


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _normalize(value: Optional[str]) -> str:
    """
    Normalize a hardware/software identifier for searching.
    """
    if not value:
        return ""

    return str(value).strip()


def search_nvd(keyword: str, results_per_page: int = 20) -> dict:
    """
    Search the NIST National Vulnerability Database using a keyword.

    This function only performs vulnerability lookup.
    It does not classify a device as malicious by itself.
    """

    keyword = _normalize(keyword)

    if not keyword:
        return {
            "available": False,
            "results": [],
            "reason": "No search keyword supplied"
        }

    try:
        response = requests.get(
            NVD_API_URL,
            params={
                "keywordSearch": keyword,
                "resultsPerPage": results_per_page
            },
            timeout=15
        )

        if response.status_code != 200:
            return {
                "available": False,
                "results": [],
                "reason": f"NVD returned HTTP {response.status_code}"
            }

        data = response.json()

        vulnerabilities = []

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})

            cve_id = cve.get("id")

            descriptions = cve.get("descriptions", [])

            description = ""

            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            metrics = cve.get("metrics", {})

            cvss_score = None
            severity = "UNKNOWN"

            # Prefer CVSS v3.1
            if metrics.get("cvssMetricV31"):
                metric = metrics["cvssMetricV31"][0]
                cvss_data = metric.get("cvssData", {})

                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get(
                    "baseSeverity",
                    "UNKNOWN"
                )

            # Fall back to CVSS v3.0
            elif metrics.get("cvssMetricV30"):
                metric = metrics["cvssMetricV30"][0]
                cvss_data = metric.get("cvssData", {})

                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get(
                    "baseSeverity",
                    "UNKNOWN"
                )

            vulnerabilities.append({
                "cve_id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "severity": severity,
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified")
            })

        return {
            "available": True,
            "keyword": keyword,
            "total_results": data.get(
                "totalResults",
                len(vulnerabilities)
            ),
            "results": vulnerabilities
        }

    except requests.RequestException as exc:
        return {
            "available": False,
            "results": [],
            "reason": str(exc)
        }

    except (ValueError, KeyError, TypeError) as exc:
        return {
            "available": False,
            "results": [],
            "reason": f"Invalid NVD response: {exc}"
        }


def build_hardware_search_terms(hardware: dict) -> list[str]:
    """
    Generate conservative search terms from the hardware inventory.

    We search identifiable product information rather than arbitrary
    serial numbers.
    """

    terms = []

    # CPU
    for cpu in hardware.get("cpu", []):
        manufacturer = _normalize(
            cpu.get("manufacturer")
        )
        name = _normalize(
            cpu.get("name")
        )

        if manufacturer and name:
            terms.append(
                f"{manufacturer} {name}"
            )
        elif name:
            terms.append(name)

    # GPU
    for gpu in hardware.get("gpu", []):
        manufacturer = _normalize(
            gpu.get("manufacturer")
        )
        name = _normalize(
            gpu.get("name")
        )

        if manufacturer and name:
            terms.append(
                f"{manufacturer} {name}"
            )
        elif name:
            terms.append(name)

    # Storage
    for disk in hardware.get("storage", []):
        manufacturer = _normalize(
            disk.get("manufacturer")
        )
        model = _normalize(
            disk.get("model")
        )

        if manufacturer and model:
            terms.append(
                f"{manufacturer} {model}"
            )
        elif model:
            terms.append(model)

    # Motherboard
    for board in hardware.get("motherboard", []):
        manufacturer = _normalize(
            board.get("manufacturer")
        )
        model = _normalize(
            board.get("model")
        )

        if manufacturer and model:
            terms.append(
                f"{manufacturer} {model}"
            )
        elif model:
            terms.append(model)

    # Remove duplicates while preserving order
    return list(dict.fromkeys(terms))


def search_hardware_vulnerabilities(
    hardware: dict,
    max_results_per_component: int = 10
) -> dict:
    """
    Search NVD for vulnerabilities associated with detected hardware.
    """

    search_terms = build_hardware_search_terms(
        hardware
    )

    results = []

    for term in search_terms:

        lookup = search_nvd(
            term,
            results_per_page=max_results_per_component
        )

        results.append({
            "component": term,
            "lookup": lookup
        })

    return {
        "components_checked": len(search_terms),
        "results": results
    }


def get_highest_severity(results: dict) -> str:
    """
    Determine the highest CVSS severity found.
    """

    severity_rank = {
        "UNKNOWN": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    highest = "UNKNOWN"

    for component in results.get("results", []):

        lookup = component.get("lookup", {})

        for vulnerability in lookup.get("results", []):

            severity = vulnerability.get(
                "severity",
                "UNKNOWN"
            ).upper()

            if severity_rank.get(
                severity,
                0
            ) > severity_rank.get(
                highest,
                0
            ):
                highest = severity

    return highest