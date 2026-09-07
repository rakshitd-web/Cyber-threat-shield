import json
import platform
import subprocess
from datetime import datetime


def _run_powershell(command, timeout=20):
    """
    Execute a PowerShell command and return parsed JSON output.
    """

    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command
            ],
            capture_output=True,
            text=True,
            timeout=timeout
        )

        if result.returncode != 0:
            return None

        output = result.stdout.strip()

        if not output:
            return None

        try:
            return json.loads(output)
        except json.JSONDecodeError:
            return output

    except (subprocess.TimeoutExpired, OSError):
        return None


def _as_list(data):
    if data is None:
        return []

    if isinstance(data, list):
        return data

    return [data]


def _clean(value):
    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    return value


# ----------------------------------------------------------------------
# STORAGE
# ----------------------------------------------------------------------

def get_storage_health():
    """
    Collect basic storage health information using Windows Storage APIs.

    This provides health information where the underlying device exposes it.
    """

    command = """
    Get-PhysicalDisk |
    Select-Object FriendlyName,
                  Manufacturer,
                  SerialNumber,
                  MediaType,
                  HealthStatus,
                  OperationalStatus,
                  Size,
                  FirmwareVersion,
                  SpindleSpeed |
    ConvertTo-Json -Compress
    """

    data = _run_powershell(command)

    drives = []

    for drive in _as_list(data):

        size = drive.get("Size")

        if isinstance(size, (int, float)):
            size_gb = round(size / (1024 ** 3), 2)
        else:
            size_gb = None

        drives.append({
            "name": _clean(drive.get("FriendlyName")),
            "manufacturer": _clean(drive.get("Manufacturer")),
            "serial_number": _clean(drive.get("SerialNumber")),
            "media_type": _clean(drive.get("MediaType")),
            "health_status": _clean(drive.get("HealthStatus")),
            "operational_status": _clean(
                drive.get("OperationalStatus")
            ),
            "size_gb": size_gb,
            "firmware": _clean(
                drive.get("FirmwareVersion")
            ),
            "spindle_speed": drive.get("SpindleSpeed")
        })

    return drives


def classify_storage_health(drive):
    """
    Convert Windows storage health information into a normalized status.
    """

    health = drive.get("health_status")

    if not health:
        return {
            "status": "UNKNOWN",
            "score": None,
            "reason": "Storage health information unavailable"
        }

    health = health.upper()

    if health == "HEALTHY":
        return {
            "status": "GOOD",
            "score": 100,
            "reason": "Windows reports the storage device as healthy"
        }

    if health in {"WARNING", "DEGRADED"}:
        return {
            "status": "MODERATE",
            "score": 60,
            "reason": (
                f"Windows reports storage health as {health.lower()}"
            )
        }

    if health in {"UNHEALTHY", "FAILED"}:
        return {
            "status": "CRITICAL",
            "score": 20,
            "reason": (
                f"Windows reports storage health as {health.lower()}"
            )
        }

    return {
        "status": "UNKNOWN",
        "score": None,
        "reason": f"Unrecognized storage health state: {health}"
    }


# ----------------------------------------------------------------------
# SMART / NVMe
# ----------------------------------------------------------------------

def get_smart_information():
    """
    Attempt to retrieve SMART information using smartctl.

    smartctl must be installed separately.

    The scanner does not fail if smartctl is unavailable.
    """

    try:
        result = subprocess.run(
            [
                "smartctl",
                "--scan-open"
            ],
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode not in (0, 1):
            return []

    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    devices = []

    for line in result.stdout.splitlines():

        line = line.strip()

        if not line:
            continue

        devices.append({
            "device": line
        })

    return devices


def get_smart_device_data(device):
    """
    Retrieve SMART data for a specific device.

    This function is intentionally defensive because different storage
    controllers expose different SMART attributes.
    """

    try:
        result = subprocess.run(
            [
                "smartctl",
                "-a",
                device
            ],
            capture_output=True,
            text=True,
            timeout=20
        )

        if result.returncode not in (0, 1, 2):
            return None

        output = result.stdout

        return {
            "device": device,
            "raw_output": output
        }

    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


# ----------------------------------------------------------------------
# TEMPERATURE
# ----------------------------------------------------------------------

def get_temperature_information():
    """
    Collect temperatures exposed through Windows WMI.

    Hardware support varies significantly between systems.
    """

    command = """
    Get-CimInstance MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue |
    Select-Object CurrentTemperature,InstanceName |
    ConvertTo-Json -Compress
    """

    data = _run_powershell(command)

    temperatures = []

    for item in _as_list(data):

        temperature = item.get("CurrentTemperature")

        if isinstance(temperature, (int, float)):
            celsius = round((temperature / 10) - 273.15, 2)
        else:
            celsius = None

        temperatures.append({
            "sensor": _clean(
                item.get("InstanceName")
            ),
            "temperature_c": celsius
        })

    return temperatures


def classify_temperature(temperature):
    """
    Classify a temperature reading.

    These are broad warning thresholds, not hardware-specific limits.
    """

    value = temperature.get("temperature_c")

    if value is None:
        return {
            "status": "UNKNOWN",
            "severity": "INFO"
        }

    if value < 70:
        return {
            "status": "NORMAL",
            "severity": "LOW"
        }

    if value < 85:
        return {
            "status": "ELEVATED",
            "severity": "MEDIUM"
        }

    return {
        "status": "HIGH",
        "severity": "HIGH"
    }


# ----------------------------------------------------------------------
# BATTERY
# ----------------------------------------------------------------------

def get_battery_health():
    """
    Calculate battery health from design and current full-charge capacity.
    """

    command = """
    Get-CimInstance Win32_Battery |
    Select-Object Name,
                  Manufacturer,
                  DesignCapacity,
                  FullChargeCapacity,
                  BatteryStatus,
                  Status |
    ConvertTo-Json -Compress
    """

    data = _run_powershell(command)

    batteries = []

    for battery in _as_list(data):

        design = battery.get("DesignCapacity")
        full = battery.get("FullChargeCapacity")

        if (
            isinstance(design, (int, float))
            and isinstance(full, (int, float))
            and design > 0
        ):
            health = round((full / design) * 100, 2)
            degradation = round(100 - health, 2)
        else:
            health = None
            degradation = None

        if health is None:
            status = "UNKNOWN"
        elif health >= 80:
            status = "GOOD"
        elif health >= 60:
            status = "MODERATE"
        else:
            status = "DEGRADED"

        batteries.append({
            "name": _clean(battery.get("Name")),
            "manufacturer": _clean(
                battery.get("Manufacturer")
            ),
            "design_capacity": design,
            "full_charge_capacity": full,
            "health_percentage": health,
            "degradation_percentage": degradation,
            "status": status,
            "battery_status": battery.get(
                "BatteryStatus"
            ),
            "system_status": _clean(
                battery.get("Status")
            )
        })

    return batteries


# ----------------------------------------------------------------------
# AGE ESTIMATION
# ----------------------------------------------------------------------

def parse_wmi_date(value):
    """
    Convert WMI date format to a Python datetime.

    Example:
        20240115123000.000000+330
    """

    if not value:
        return None

    value = str(value)

    match = (
        __import__("re")
        .match(r"(\d{14})", value)
    )

    if not match:
        return None

    try:
        return datetime.strptime(
            match.group(1),
            "%Y%m%d%H%M%S"
        )
    except ValueError:
        return None


def estimate_age(date_values):
    """
    Estimate component age from available dates.

    The oldest reliable date is used as the conservative estimate.
    """

    dates = []

    for value in date_values:

        parsed = parse_wmi_date(value)

        if parsed:
            dates.append(parsed)

    if not dates:
        return {
            "estimated_age_years": None,
            "confidence": "LOW",
            "reason": "No reliable manufacturing or firmware date available"
        }

    oldest = min(dates)
    now = datetime.now()

    age_days = (now - oldest).days
    age_years = round(age_days / 365.25, 2)

    if age_years <= 2:
        confidence = "HIGH"
    elif age_years <= 5:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    return {
        "estimated_age_years": max(0, age_years),
        "reference_date": oldest.strftime("%Y-%m-%d"),
        "confidence": confidence
    }


# ----------------------------------------------------------------------
# OVERALL HEALTH
# ----------------------------------------------------------------------

def calculate_health_status(scores):
    """
    Calculate an overall health state from available component scores.

    Missing information is ignored rather than treated as a failure.
    """

    valid_scores = [
        score
        for score in scores
        if isinstance(score, (int, float))
    ]

    if not valid_scores:
        return {
            "score": None,
            "status": "UNKNOWN"
        }

    average = round(
        sum(valid_scores) / len(valid_scores),
        2
    )

    if average >= 80:
        status = "GOOD"
    elif average >= 60:
        status = "MODERATE"
    elif average >= 40:
        status = "DEGRADED"
    else:
        status = "CRITICAL"

    return {
        "score": average,
        "status": status
    }


def run_hardware_health_scan():
    """
    Run the complete hardware health analysis.
    """

    storage = get_storage_health()
    battery = get_battery_health()
    temperatures = get_temperature_information()

    storage_results = []

    for drive in storage:

        classification = classify_storage_health(
            drive
        )

        storage_results.append({
            **drive,
            "analysis": classification
        })

    temperature_results = []

    for temperature in temperatures:

        classification = classify_temperature(
            temperature
        )

        temperature_results.append({
            **temperature,
            "analysis": classification
        })

    health_scores = []

    for drive in storage_results:
        score = drive["analysis"].get("score")

        if score is not None:
            health_scores.append(score)

    for battery_item in battery:
        score = battery_item.get(
            "health_percentage"
        )

        if score is not None:
            health_scores.append(score)

    overall = calculate_health_status(
        health_scores
    )

    return {
        "storage": storage_results,
        "battery": battery,
        "temperature": temperature_results,
        "smart_devices": get_smart_information(),
        "overall": overall
    }