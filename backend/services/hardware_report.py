            "message": check.get("reason", "Integrity check flagged this component."),
            "check": check.get("type", "unknown"),
            **guidance,
        })

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
