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
