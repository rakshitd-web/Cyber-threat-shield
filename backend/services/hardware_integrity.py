import re

# This is a small local reference list, not a complete vendor database.
KNOWN_VENDOR_IDS = {
    "10DE": "NVIDIA", "1002": "AMD", "1022": "AMD", "8086": "Intel",
    "14E4": "Broadcom", "168C": "Qualcomm Atheros", "1969": "Atheros",
    "1AF4": "Red Hat", "1B21": "ASMedia", "144D": "Samsung",
    "1D0F": "Amazon", "1B4B": "Marvell", "10EC": "Realtek",
    "13B1": "Linksys", "15B3": "Mellanox", "1D6A": "Aquantia",
}
ALIASES = {
    "NVIDIA CORPORATION": "NVIDIA", "NVIDIA": "NVIDIA",
    "ADVANCED MICRO DEVICES": "AMD", "AMD": "AMD",
    "INTEL CORPORATION": "INTEL", "INTEL": "INTEL",
    "REALTEK SEMICONDUCTOR": "REALTEK", "REALTEK": "REALTEK",
    "BROADCOM": "BROADCOM", "QUALCOMM": "QUALCOMM ATHEROS",
    "QUALCOMM ATHEROS": "QUALCOMM ATHEROS",
}

def normalize(value):
    if value is None:
        return None
    value = str(value).strip().upper()
    return value or None

def _device_identifier(device):
    # Windows inventory functions expose PNPDeviceID as pnp_device_id.
    return device.get("pnp_device_id") or device.get("device_id") or device.get("hardware_id")

def extract_vendor_id(device_id):
    if not device_id:
        return None
    match = re.search(r"VEN_([0-9A-F]{4})", str(device_id).upper())
    if match:
        return match.group(1)
    # USB identifiers use VID_xxxx rather than VEN_xxxx.
    match = re.search(r"VID_([0-9A-F]{4})", str(device_id).upper())
    return match.group(1) if match else None

def extract_device_id(device_id):
    if not device_id:
        return None
    match = re.search(r"DEV_([0-9A-F]{4})", str(device_id).upper())
    if match:
        return match.group(1)
    match = re.search(r"PID_([0-9A-F]{4})", str(device_id).upper())
    return match.group(1) if match else None

def analyze_device_identifier(device):
    raw_id = _device_identifier(device)
    result = {
        "vendor_id": None, "device_id": None, "vendor_name": None,
        "identifier_status": "UNKNOWN", "reason": None
    }
    if not raw_id:
        result["reason"] = "No PNP/hardware identifier was provided"
        return result
    vendor_id = extract_vendor_id(raw_id)
    hardware_id = extract_device_id(raw_id)
    result["vendor_id"] = vendor_id
    result["device_id"] = hardware_id
    if not vendor_id:
        result["reason"] = "No supported VEN_/VID_ vendor identifier was found"
        return result
    vendor_name = KNOWN_VENDOR_IDS.get(vendor_id)
    if not vendor_name:
        result["reason"] = "Vendor ID is not in the limited local reference list"
        return result
    result.update({
        "vendor_name": vendor_name,
        "identifier_status": "VALID",
        "reason": "Vendor ID matches an entry in the local reference list"
    })
    return result

def compare_manufacturer(device, identifier_result):
    reported = normalize(device.get("manufacturer"))
    vendor = normalize(identifier_result.get("vendor_name"))
    if not reported or not vendor:
        return {"status": "UNKNOWN", "reason": "Manufacturer or mapped vendor is unavailable"}
    reported_normalized = ALIASES.get(reported, reported)
    vendor_normalized = ALIASES.get(vendor, vendor)
    if reported_normalized == vendor_normalized or reported_normalized in vendor_normalized or vendor_normalized in reported_normalized:
        return {"status": "CONSISTENT", "reason": "Reported manufacturer is consistent with the mapped vendor"}
    return {
        "status": "MISMATCH",
        "reason": f"Reported manufacturer '{reported}' differs from identifier vendor '{vendor}'"
    }

def _component_status(device):
    status = normalize(device.get("status"))
    if status in {"OK", "HEALTHY", "GOOD", "NORMAL"}:
        return {"status": "VALID", "reason": "Operating status is reported as healthy"}
    if status in {"ERROR", "FAILED", "DEGRADED", "NOT OK"}:
        return {"status": "SUSPICIOUS", "reason": f"Operating status reported as {status}"}
    return {"status": "UNKNOWN", "reason": "Operating status is missing or not recognized"}

def _make_integrity(component, checks):
    actionable = [c for c in checks if c["status"] not in {"UNKNOWN", "NOT_APPLICABLE"}]
    mismatches = [c for c in checks if c["status"] == "MISMATCH"]
    suspicious = [c for c in checks if c["status"] in {"INVALID", "SUSPICIOUS"}]
    findings = []
    for check in checks:
        if check["status"] == "MISMATCH":
            findings.append({"severity": "HIGH", "message": check["reason"], "check": check["type"]})
        elif check["status"] in {"INVALID", "SUSPICIOUS"}:
            findings.append({"severity": "MEDIUM", "message": check["reason"], "check": check["type"]})
    if mismatches or suspicious:
        status = "SUSPICIOUS"
        score = max(0, 100 - 35 * len(mismatches) - 25 * len(suspicious))
    elif not actionable:
        status, score = "UNKNOWN", None
    else:
        status, score = "VERIFIED", 100
    return {
        "status": status,
        "score": score,
        "checks_performed": len(actionable),
        "checks": checks,
        "findings": findings,
        "note": "This is a heuristic consistency check, not proof of physical authenticity or absence of hardware implants."
    }

def analyze_identified_device(device, component_name=None, check_identifier=True):
    identifier = analyze_device_identifier(device)
    checks = []
    if check_identifier:
        # A known vendor is supporting evidence only; unknown vendors are not suspicious.
        checks.append({
            "type": "device_identifier",
            "status": "VALID" if identifier["identifier_status"] == "VALID" else "UNKNOWN",
            "reason": identifier["reason"]
        })
        manufacturer = compare_manufacturer(device, identifier)
        checks.append({
            "type": "manufacturer_consistency",
            "status": manufacturer["status"],
            "reason": manufacturer["reason"]
        })
    checks.append({"type": "operating_status", **_component_status(device)})
    integrity = _make_integrity(component_name or device.get("name") or device.get("model") or "Hardware component", checks)
    return {
        "component": component_name or device.get("name") or device.get("model") or "Hardware component",
        "vendor_id": identifier["vendor_id"],
        "device_id": identifier["device_id"],
        "vendor_name": identifier["vendor_name"],
        "integrity": integrity
    }

def analyze_gpu(gpu):
    return analyze_identified_device(gpu, gpu.get("name") or "GPU")

def analyze_network_adapter(adapter):
    return analyze_identified_device(adapter, adapter.get("name") or "Network adapter")

def analyze_usb_device(device):
    # USB device IDs generally use VID/PID and are parsed separately from PCI VEN/DEV IDs.
    return analyze_identified_device(device, device.get("name") or "USB device")

def _generic_metadata_check(device, label):
    fields = ("name", "model", "manufacturer", "serial_number", "processor_id", "firmware", "version")
    present = [field for field in fields if normalize(device.get(field))]
    if present:
        return {"type": "identity_metadata", "status": "VALID", "reason": f"Identity metadata available: {', '.join(present)}"}
    return {"type": "identity_metadata", "status": "UNKNOWN", "reason": "No useful identity metadata was exposed"}

def analyze_generic_component(device, component_type):
    checks = [_generic_metadata_check(device, component_type), {"type": "operating_status", **_component_status(device)}]
    return {
        "component": device.get("name") or device.get("model") or device.get("manufacturer") or component_type,
        "integrity": _make_integrity(component_type, checks)
    }

def analyze_hardware_integrity(hardware):
    groups = {
        "cpu": [], "gpu": [], "memory": [], "motherboard": [], "bios": [],
        "storage": [], "network": [], "usb": [], "battery": []
    }
    specialized = {
        "gpu": analyze_gpu,
        "network": analyze_network_adapter,
        "usb": analyze_usb_device
    }
    for group in groups:
        items = hardware.get(group, [])
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            if group in specialized:
                groups[group].append(specialized[group](item))
            else:
                groups[group].append(analyze_generic_component(item, group))

    summary = {"total_components": 0, "verified": 0, "suspicious": 0, "high_risk": 0, "unknown": 0}
    for group in groups.values():
        for component in group:
            summary["total_components"] += 1
            status = component["integrity"]["status"]
            if status == "VERIFIED":
                summary["verified"] += 1
            elif status == "SUSPICIOUS":
                summary["suspicious"] += 1
            elif status == "HIGH_RISK":
                summary["high_risk"] += 1
            else:
                summary["unknown"] += 1
    groups["summary"] = summary
    return groups
