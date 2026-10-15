"""
Local hardware baseline comparison.

Stores a minimal baseline under the current Windows user's LocalAppData.
No inventory is uploaded to the backend by this module.
The baseline contains component labels and SHA-256 fingerprints, not raw serial numbers.
"""
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

GROUPS = (
    "cpu", "gpu", "memory", "motherboard", "bios",
    "storage", "network", "usb", "battery"
)

# Fields that can help identify a component across scans. Values are hashed
# before storage; raw serial numbers and PNP identifiers are not written.
IDENTITY_FIELDS = (
    "name", "model", "manufacturer", "part_number", "serial_number",
    "processor_id", "pnp_device_id", "device_id", "firmware",
    "bios_version", "version", "device_locator", "bank_label",
)

def _normalized(value):
    if value is None:
        return ""
    return " ".join(str(value).strip().casefold().split())

def _identity(item):
    identity = {}
    for field in IDENTITY_FIELDS:
        value = _normalized(item.get(field))
        if value:
            identity[field] = value
    # Mutable fields like status, temperature, clock speed and capacity
    # are deliberately excluded from identity fingerprints.
    return identity

def _component_label(group, item, index):
    for field in ("name", "model", "manufacturer", "device_locator", "part_number"):
        value = item.get(field)
        if value and str(value).strip():
            return str(value).strip()[:120]
    return f"{group} component {index + 1}"

def _fingerprint(identity):
    serialized = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

def _baseline_path():
    root = os.environ.get("LOCALAPPDATA")
    if root:
        directory = Path(root) / "CyberThreatShield"
    else:
        directory = Path.home() / ".cyberthreatshield"
    return directory / "hardware_baseline.json"

def _collect(hardware):
    records = {}
    for group in GROUPS:
        items = hardware.get(group, [])
        if not isinstance(items, list):
            continue
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            identity = _identity(item)
            if not identity:
                # Don't create unstable fingerprints from empty records.
                continue
            fingerprint = _fingerprint(identity)
            key = f"{group}:{fingerprint}"
            records[key] = {
                "group": group,
                "label": _component_label(group, item, index),
                "fingerprint": fingerprint,
                "identity_fields": sorted(identity.keys()),
            }
    return records

def _atomic_write(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix="hardware-baseline-", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        os.replace(temp_name, path)
    finally:
        try:
            if os.path.exists(temp_name):
                os.remove(temp_name)
        except OSError:
            pass

def compare_hardware_baseline(hardware, reset=False):
    """
    First run creates a baseline. Later runs compare current components to it.
    Set reset=True only when the user explicitly requests a new baseline.
    """
    path = _baseline_path()
    current = _collect(hardware)
    now = datetime.now(timezone.utc).isoformat()

    if reset or not path.exists():
        payload = {
            "schema_version": 1,
            "created_at": now,
            "updated_at": now,
            "components": current,
        }
        try:
            _atomic_write(path, payload)
            return {
                "status": "BASELINE_CREATED",
                "baseline_created": True,
                "baseline_path": str(path),
                "compared_at": now,
                "summary": {
                    "added": 0, "removed": 0, "changed": 0,
                    "unchanged": len(current), "unidentifiable": 0
                },
                "changes": [],
                "message": "A local baseline was created from this scan. Future scans will compare against it."
            }
        except OSError as exc:
            return {
                "status": "BASELINE_UNAVAILABLE",
                "baseline_created": False,
                "baseline_path": str(path),
                "compared_at": now,
                "summary": {"added": 0, "removed": 0, "changed": 0, "unchanged": 0, "unidentifiable": 0},
                "changes": [],
                "message": f"Could not save the local baseline: {exc}"
            }

    try:
        with path.open("r", encoding="utf-8") as handle:
            baseline = json.load(handle)
        previous = baseline.get("components", {})
        if not isinstance(previous, dict):
            raise ValueError("Baseline components field is invalid")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {
            "status": "BASELINE_INVALID",
            "baseline_created": False,
            "baseline_path": str(path),
            "compared_at": now,
            "summary": {"added": 0, "removed": 0, "changed": 0, "unchanged": 0, "unidentifiable": 0},
            "changes": [],
            "message": f"Could not read the existing baseline: {exc}. Reset the baseline after reviewing the issue."
        }

    previous_keys, current_keys = set(previous), set(current)
    added_keys = current_keys - previous_keys
    removed_keys = previous_keys - current_keys
    unchanged_keys = current_keys & previous_keys

    changes = []
    for key in sorted(added_keys):
        item = current[key]
        changes.append({"type": "ADDED", "component_type": item["group"], "component": item["label"], "details": "Component identity was not present in the saved baseline."})
    for key in sorted(removed_keys):
        item = previous[key]
        changes.append({"type": "REMOVED", "component_type": item.get("group", "unknown"), "component": item.get("label", "Unknown component"), "details": "Component identity from the saved baseline was not found in this scan."})
    for key in sorted(unchanged_keys):
        item = current[key]
        changes.append({"type": "UNCHANGED", "component_type": item["group"], "component": item["label"], "details": "Identity fingerprint matches the saved baseline."})

    # Do not silently update the baseline after changes. That would normalize
    # an unexpected change. Baseline refresh must be an explicit user action.
    return {
        "status": "CHANGES_DETECTED" if added_keys or removed_keys else "NO_IDENTITY_CHANGES",
        "baseline_created": False,
        "baseline_path": str(path),
        "baseline_created_at": baseline.get("created_at"),
        "compared_at": now,
        "summary": {
            "added": len(added_keys),
            "removed": len(removed_keys),
            "changed": 0,
            "unchanged": len(unchanged_keys),
            "unidentifiable": 0
        },
        "changes": changes,
        "message": "Identity differences are change indicators, not proof of malicious activity. The saved baseline was not modified."
    }

def reset_hardware_baseline():
    """Explicitly replace the saved baseline on the next scan."""
    return compare_hardware_baseline({}, reset=True)
