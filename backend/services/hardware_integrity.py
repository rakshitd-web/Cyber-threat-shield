import re


# Common PCI/PNP vendor identifiers.
# This is intentionally a small initial reference set.
# It can be expanded later or moved into hardware_db.py.
KNOWN_VENDOR_IDS = {
    "10DE": "NVIDIA",
    "1002": "AMD",
    "1022": "AMD",
    "8086": "Intel",
    "14E4": "Broadcom",
    "168C": "Qualcomm Atheros",
    "1969": "Atheros",
    "1AF4": "Red Hat",
    "1B21": "ASMedia",
    "144D": "Samsung",
    "1D0F": "Amazon",
    "1B4B": "Marvell",
    "10EC": "Realtek",
    "13B1": "Linksys",
}


def normalize(value):
    """
    Normalize a hardware string before comparison.
    """
    if value is None:
        return None

    value = str(value).strip().upper()

    if not value:
        return None

    return value


def extract_vendor_id(device_id):
    """
    Extract PCI vendor ID from a Windows PNP device identifier.

    Example:
        PCI\\VEN_10DE&DEV_2487...

    Returns:
        10DE
    """
    if not device_id:
        return None

    match = re.search(r"VEN_([0-9A-F]{4})", device_id.upper())

    if match:
        return match.group(1)

    return None


def extract_device_id(device_id):
    """
    Extract PCI device ID from a Windows PNP identifier.

    Example:
        PCI\\VEN_10DE&DEV_2487...

    Returns:
        2487
    """
    if not device_id:
        return None

    match = re.search(r"DEV_([0-9A-F]{4})", device_id.upper())

    if match:
        return match.group(1)

    return None


def analyze_device_identifier(device):
    """
    Analyze a device's PNP identifier.

    This does NOT prove authenticity.
    It only checks whether the identifier is structurally valid and
    whether its vendor ID is known.
    """

    device_id = normalize(device.get("device_id"))

    result = {
        "vendor_id": None,
        "device_id": None,
        "vendor_name": None,
        "identifier_status": "UNKNOWN",
        "reason": None
    }

    if not device_id:
        result["reason"] = "No device identifier available"
        return result

    vendor_id = extract_vendor_id(device_id)
    hardware_id = extract_device_id(device_id)

    result["vendor_id"] = vendor_id
    result["device_id"] = hardware_id

    if not vendor_id:
        result["identifier_status"] = "UNKNOWN"
        result["reason"] = "Vendor identifier could not be extracted"
        return result

    vendor_name = KNOWN_VENDOR_IDS.get(vendor_id)

    if vendor_name:
        result["vendor_name"] = vendor_name
        result["identifier_status"] = "VALID"
        result["reason"] = "Known hardware vendor identifier"
    else:
        result["identifier_status"] = "UNKNOWN"
        result["reason"] = "Vendor identifier is not in the local reference database"

    return result


def compare_manufacturer(device, identifier_result):
    """
    Compare the reported manufacturer with the vendor encoded in the
    hardware identifier.

    A mismatch is a useful suspicious indicator but is not by itself
    proof of counterfeit hardware.
    """

    reported = normalize(device.get("manufacturer"))
    vendor = normalize(identifier_result.get("vendor_name"))

    if not reported or not vendor:
        return {
            "status": "UNKNOWN",
            "reason": "Insufficient manufacturer information"
        }

    # Some manufacturers have multiple valid naming conventions.
    aliases = {
        "NVIDIA CORPORATION": "NVIDIA",
        "NVIDIA": "NVIDIA",
        "ADVANCED MICRO DEVICES": "AMD",
        "AMD": "AMD",
        "INTEL CORPORATION": "INTEL",
        "INTEL": "INTEL",
        "REALTEK SEMICONDUCTOR": "REALTEK",
        "REALTEK": "REALTEK",
        "BROADCOM": "BROADCOM",
        "QUALCOMM": "QUALCOMM ATHEROS",
        "QUALCOMM ATHEROS": "QUALCOMM ATHEROS",
    }

    reported_normalized = aliases.get(reported, reported)
    vendor_normalized = aliases.get(vendor, vendor)

    if (
        reported_normalized == vendor_normalized
        or reported_normalized in vendor_normalized
        or vendor_normalized in reported_normalized
    ):
        return {
            "status": "CONSISTENT",
            "reason": "Reported manufacturer matches hardware identifier"
        }

    return {
        "status": "MISMATCH",
        "reason": (
            f"Reported manufacturer '{reported}' does not match "
            f"identifier vendor '{vendor}'"
        )
    }


def calculate_integrity_score(checks):
    """
    Calculate an integrity score from available validation checks.

    100 = all available checks passed.
    0   = severe inconsistency.

    Unknown information is not automatically treated as malicious.
    """

    score = 100
    findings = []

    for check in checks:
        status = check.get("status")

        if status == "MISMATCH":
            score -= 35
            findings.append({
                "severity": "HIGH",
                "message": check.get("reason")
            })

        elif status == "INVALID":
            score -= 30
            findings.append({
                "severity": "HIGH",
                "message": check.get("reason")
            })

        elif status == "SUSPICIOUS":
            score -= 25
            findings.append({
                "severity": "MEDIUM",
                "message": check.get("reason")
            })

    score = max(0, min(100, score))

    if score >= 80:
        status = "VERIFIED"
    elif score >= 50:
        status = "SUSPICIOUS"
    else:
        status = "HIGH_RISK"

    return {
        "score": score,
        "status": status,
        "findings": findings
    }


def analyze_gpu(gpu):
    """
    Perform integrity checks on a GPU.
    """

    identifier = analyze_device_identifier(gpu)

    manufacturer_check = compare_manufacturer(
        gpu,
        identifier
    )

    checks = [
        {
            "type": "device_identifier",
            "status": (
                "VALID"
                if identifier["identifier_status"] == "VALID"
                else "UNKNOWN"
            ),
            "reason": identifier["reason"]
        },
        {
            "type": "manufacturer_consistency",
            "status": manufacturer_check["status"],
            "reason": manufacturer_check["reason"]
        }
    ]

    integrity = calculate_integrity_score(checks)

    return {
        "component": gpu.get("name"),
        "vendor_id": identifier["vendor_id"],
        "device_id": identifier["device_id"],
        "vendor_name": identifier["vendor_name"],
        "integrity": integrity
    }


def analyze_network_adapter(adapter):
    """
    Perform integrity checks on a physical network adapter.
    """

    identifier = analyze_device_identifier(adapter)

    manufacturer_check = compare_manufacturer(
        adapter,
        identifier
    )

    checks = [
        {
            "type": "device_identifier",
            "status": (
                "VALID"
                if identifier["identifier_status"] == "VALID"
                else "UNKNOWN"
            ),
            "reason": identifier["reason"]
        },
        {
            "type": "manufacturer_consistency",
            "status": manufacturer_check["status"],
            "reason": manufacturer_check["reason"]
        }
    ]

    integrity = calculate_integrity_score(checks)

    return {
        "component": adapter.get("name"),
        "vendor_id": identifier["vendor_id"],
        "device_id": identifier["device_id"],
        "vendor_name": identifier["vendor_name"],
        "integrity": integrity
    }


def analyze_usb_device(device):
    """
    Perform basic USB hardware identity analysis.
    """

    device_id = normalize(device.get("device_id"))

    checks = []

    if device_id:
        checks.append({
            "type": "device_identifier",
            "status": "VALID",
            "reason": "USB device identifier is present"
        })
    else:
        checks.append({
            "type": "device_identifier",
            "status": "UNKNOWN",
            "reason": "USB device identifier unavailable"
        })

    if normalize(device.get("status")) == "OK":
        checks.append({
            "type": "device_status",
            "status": "VALID",
            "reason": "Windows reports the device as operational"
        })

    integrity = calculate_integrity_score(checks)

    return {
        "component": device.get("name"),
        "device_id": device.get("device_id"),
        "integrity": integrity
    }


def analyze_hardware_integrity(hardware):
    """
    Analyze the hardware inventory returned by run_hardware_scan().
    """

    results = {
        "cpu": [],
        "gpu": [],
        "memory": [],
        "motherboard": [],
        "bios": [],
        "storage": [],
        "network": [],
        "usb": [],
        "summary": {
            "total_components": 0,
            "verified": 0,
            "suspicious": 0,
            "high_risk": 0,
            "unknown": 0
        }
    }

    # GPU
    for gpu in hardware.get("gpu", []):
        results["gpu"].append(
            analyze_gpu(gpu)
        )

    # Network adapters
    for adapter in hardware.get("network", []):
        results["network"].append(
            analyze_network_adapter(adapter)
        )

    # USB devices
    for device in hardware.get("usb", []):
        results["usb"].append(
            analyze_usb_device(device)
        )

    # Count results
    component_groups = [
        "gpu",
        "network",
        "usb"
    ]

    for group in component_groups:
        for component in results[group]:
            results["summary"]["total_components"] += 1

            status = component["integrity"]["status"]

            if status == "VERIFIED":
                results["summary"]["verified"] += 1

            elif status == "SUSPICIOUS":
                results["summary"]["suspicious"] += 1

            elif status == "HIGH_RISK":
                results["summary"]["high_risk"] += 1

            else:
                results["summary"]["unknown"] += 1

    return results