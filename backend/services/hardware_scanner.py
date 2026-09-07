import subprocess
import json
import re
from datetime import datetime



def _run_powershell(command):
    """
    Execute a PowerShell command locally and return parsed JSON.

    This file must run on the user's Windows machine.
    It must NOT run on Render.
    """

    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command
            ],
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode != 0:
            return []

        output = result.stdout.strip()

        if not output:
            return []

        try:
            return json.loads(output)
        except json.JSONDecodeError:
            return output

    except Exception:
        return []



def _as_list(value):
    """
    Normalize PowerShell output into a list.
    """

    if value is None:
        return []

    if isinstance(value, list):
        return value

    return [value]


def _clean(value):
    """
    Convert PowerShell values into JSON-safe values.
    """

    if value is None:
        return None

    if isinstance(value, (str, int, float, bool)):
        return value

    return str(value)



def get_system_information():

    command = r"""
    Get-CimInstance Win32_ComputerSystem |
    Select-Object `
        Manufacturer,
        Model,
        SystemType,
        TotalPhysicalMemory,
        NumberOfLogicalProcessors,
        NumberOfProcessors |
    ConvertTo-Json -Compress
    """

    data = _run_powershell(command)

    if isinstance(data, dict):
        return {
            "manufacturer": _clean(data.get("Manufacturer")),
            "model": _clean(data.get("Model")),
            "system_type": _clean(data.get("SystemType")),
            "total_memory": _clean(data.get("TotalPhysicalMemory")),
            "logical_processors": _clean(
                data.get("NumberOfLogicalProcessors")
            ),
            "processors": _clean(
                data.get("NumberOfProcessors")
            )
        }

    return {}



def get_cpu_information():

    command = r"""
    Get-CimInstance Win32_Processor |
    Select-Object `
        Name,
        Manufacturer,
        ProcessorId,
        NumberOfCores,
        NumberOfLogicalProcessors,
        MaxClockSpeed,
        Architecture,
        Revision,
        Status |
    ConvertTo-Json -Compress
    """

    data = _run_powershell(command)

    results = []

    for cpu in _as_list(data):

        if not isinstance(cpu, dict):
            continue

        results.append({
            "name": _clean(cpu.get("Name")),
            "manufacturer": _clean(cpu.get("Manufacturer")),
            "processor_id": _clean(cpu.get("ProcessorId")),
            "cores": _clean(cpu.get("NumberOfCores")),
            "logical_processors": _clean(
                cpu.get("NumberOfLogicalProcessors")
            ),
            "max_clock_mhz": _clean(
                cpu.get("MaxClockSpeed")
            ),
            "architecture": _clean(
                cpu.get("Architecture")
            ),
            "revision": _clean(cpu.get("Revision")),
            "status": _clean(cpu.get("Status"))
        })

    return results



def get_gpu_information():

    command = r"""
    Get-CimInstance Win32_VideoController |
    Select-Object `
        Name,
        AdapterCompatibility,
        PNPDeviceID,
        DriverVersion,
        DriverDate,
        VideoProcessor,
        AdapterRAM,
        Status |
    ConvertTo-Json -Compress
    """

    data = _run_powershell(command)

    results = []

    for gpu in _as_list(data):

        if not isinstance(gpu, dict):
            continue

        results.append({
            "name": _clean(gpu.get("Name")),
            "manufacturer": _clean(
                gpu.get("AdapterCompatibility")
            ),
            "pnp_device_id": _clean(
                gpu.get("PNPDeviceID")
            ),
            "driver_version": _clean(
                gpu.get("DriverVersion")
            ),
            "driver_date": _clean(
                gpu.get("DriverDate")
            ),
            "video_processor": _clean(
                gpu.get("VideoProcessor")
            ),
            "adapter_ram": _clean(
                gpu.get("AdapterRAM")
            ),
            "status": _clean(
                gpu.get("Status")
            )
        })

    return results

def get_memory_information():

    command = r"""
    Get-CimInstance Win32_PhysicalMemory |
    Select-Object `
        Manufacturer,
        PartNumber,
        SerialNumber,
        Capacity,
        Speed,
        ConfiguredClockSpeed,
        SMBIOSMemoryType,
        DeviceLocator,
        BankLabel,
        Status |
    ConvertTo-Json -Compress
    """

    data = _run_powershell(command)

    results = []

    for memory in _as_list(data):

        if not isinstance(memory, dict):
            continue

        results.append({
            "manufacturer": _clean(
                memory.get("Manufacturer")
            ),
            "part_number": _clean(
                memory.get("PartNumber")
            ),
            "serial_number": _clean(
                memory.get("SerialNumber")
            ),
            "capacity": _clean(
                memory.get("Capacity")
            ),
            "speed_mhz": _clean(
                memory.get("Speed")
            ),
            "configured_speed_mhz": _clean(
                memory.get("ConfiguredClockSpeed")
            ),
            "smbios_memory_type": _clean(
                memory.get("SMBIOSMemoryType")
            ),
            "device_locator": _clean(
                memory.get("DeviceLocator")
            ),
            "bank_label": _clean(
                memory.get("BankLabel")
            ),
            "status": _clean(
                memory.get("Status")
            )
        })

    return results


def get_motherboard_information():

    command = r"""
    Get-CimInstance Win32_BaseBoard |
    Select-Object `
        Manufacturer,
        Product,
        Version,
        SerialNumber,
        Status |
    ConvertTo-Json -Compress
    """

    data = _run_powershell(command)

    results = []

    for board in _as_list(data):

        if not isinstance(board, dict):
            continue

        results.append({
            "manufacturer": _clean(
                board.get("Manufacturer")
            ),
            "model": _clean(
                board.get("Product")
            ),
            "version": _clean(
                board.get("Version")
            ),
            "serial_number": _clean(
                board.get("SerialNumber")
            ),
            "status": _clean(
                board.get("Status")
            )
        })

    return results


def get_bios_information():

    command = r"""
    Get-CimInstance Win32_BIOS |
    Select-Object `
        Manufacturer,
        SMBIOSBIOSVersion,
        Version,
        ReleaseDate,
        SerialNumber,
        Status |
    ConvertTo-Json -Compress
    """

    data = _run_powershell(command)

    results = []

    for bios in _as_list(data):

        if not isinstance(bios, dict):
            continue

        results.append({
            "manufacturer": _clean(
                bios.get("Manufacturer")
            ),
            "version": _clean(
                bios.get("SMBIOSBIOSVersion")
            ),
            "bios_version": _clean(
                bios.get("Version")
            ),
            "release_date": _clean(
                bios.get("ReleaseDate")
            ),
            "serial_number": _clean(
                bios.get("SerialNumber")
            ),
            "status": _clean(
                bios.get("Status")
            )
        })

    return results



def get_storage_information():

    command = r"""
    Get-CimInstance Win32_DiskDrive |
    Select-Object `
        Model,
        Manufacturer,
        SerialNumber,
        PNPDeviceID,
        InterfaceType,
        MediaType,
        Size,
        FirmwareRevision,
        Status |
    ConvertTo-Json -Compress
    """

    data = _run_powershell(command)

    results = []

    for disk in _as_list(data):

        if not isinstance(disk, dict):
            continue

        results.append({
            "model": _clean(
                disk.get("Model")
            ),
            "manufacturer": _clean(
                disk.get("Manufacturer")
            ),
            "serial_number": _clean(
                disk.get("SerialNumber")
            ),
            "pnp_device_id": _clean(
                disk.get("PNPDeviceID")
            ),
            "interface": _clean(
                disk.get("InterfaceType")
            ),
            "media_type": _clean(
                disk.get("MediaType")
            ),
            "size": _clean(
                disk.get("Size")
            ),
            "firmware": _clean(
                disk.get("FirmwareRevision")
            ),
            "status": _clean(
                disk.get("Status")
            )
        })

    return results


def get_network_information():

    command = r"""
    Get-CimInstance Win32_NetworkAdapter |
    Where-Object {
        $_.PhysicalAdapter -eq $true
    } |
    Select-Object `
        Name,
        Manufacturer,
        MACAddress,
        PNPDeviceID,
        DriverVersion,
        Speed,
        NetConnectionStatus,
        Status |
    ConvertTo-Json -Compress
    """

    data = _run_powershell(command)

    results = []

    for adapter in _as_list(data):

        if not isinstance(adapter, dict):
            continue

        results.append({
            "name": _clean(
                adapter.get("Name")
            ),
            "manufacturer": _clean(
                adapter.get("Manufacturer")
            ),
            "mac_address": _clean(
                adapter.get("MACAddress")
            ),
            "pnp_device_id": _clean(
                adapter.get("PNPDeviceID")
            ),
            "driver_version": _clean(
                adapter.get("DriverVersion")
            ),
            "speed": _clean(
                adapter.get("Speed")
            ),
            "connection_status": _clean(
                adapter.get("NetConnectionStatus")
            ),
            "status": _clean(
                adapter.get("Status")
            )
        })

    return results

def get_usb_devices():

    command = r"""
    Get-CimInstance Win32_PnPEntity |
    Where-Object {
        $_.PNPDeviceID -like 'USB*'
    } |
    Select-Object `
        Name,
        Manufacturer,
        PNPDeviceID,
        DeviceID,
        Status,
        Service |
    ConvertTo-Json -Compress
    """

    data = _run_powershell(command)

    results = []

    for device in _as_list(data):

        if not isinstance(device, dict):
            continue

        results.append({
            "name": _clean(
                device.get("Name")
            ),
            "manufacturer": _clean(
                device.get("Manufacturer")
            ),
            "pnp_device_id": _clean(
                device.get("PNPDeviceID")
            ),
            "device_id": _clean(
                device.get("DeviceID")
            ),
            "status": _clean(
                device.get("Status")
            ),
            "service": _clean(
                device.get("Service")
            )
        })

    return results


def get_battery_information():

    command = r"""
    Get-CimInstance Win32_Battery |
    Select-Object `
        Name,
        DeviceID,
        Manufacturer,
        BatteryStatus,
        EstimatedChargeRemaining,
        EstimatedRunTime,
        Status |
    ConvertTo-Json -Compress
    """

    data = _run_powershell(command)

    results = []

    for battery in _as_list(data):

        if not isinstance(battery, dict):
            continue

        results.append({
            "name": _clean(
                battery.get("Name")
            ),
            "device_id": _clean(
                battery.get("DeviceID")
            ),
            "manufacturer": _clean(
                battery.get("Manufacturer")
            ),
            "battery_status": _clean(
                battery.get("BatteryStatus")
            ),
            "charge_percent": _clean(
                battery.get("EstimatedChargeRemaining")
            ),
            "estimated_runtime": _clean(
                battery.get("EstimatedRunTime")
            ),
            "status": _clean(
                battery.get("Status")
            )
        })

    return results


def run_hardware_scan():

    hardware = {
        "system": get_system_information(),
        "cpu": get_cpu_information(),
        "gpu": get_gpu_information(),
        "memory": get_memory_information(),
        "motherboard": get_motherboard_information(),
        "bios": get_bios_information(),
        "storage": get_storage_information(),
        "network": get_network_information(),
        "usb": get_usb_devices(),
        "battery": get_battery_information()
    }

    return hardware