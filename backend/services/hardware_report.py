import html
import json
from datetime import datetime


def _pretty(value):
    return html.escape(json.dumps(value, indent=2, ensure_ascii=False, default=str))


def generate_hardware_report(hardware, scan_timestamp=None, agent_version="1.1.0"):
    '''Create a self-contained HTML report from one hardware scan result.'''
    scanned_at = datetime.fromtimestamp(scan_timestamp).astimezone().isoformat(timespec="seconds") if scan_timestamp else datetime.now().astimezone().isoformat(timespec="seconds")
    groups = ["system", "cpu", "gpu", "memory", "motherboard", "bios", "storage", "network", "usb", "battery"]
    summary = hardware.get("integrity_summary", {}) if isinstance(hardware, dict) else {}
    sections = []
    for group in groups:
        value = hardware.get(group, []) if isinstance(hardware, dict) else []
        sections.append(f"<section><h2>{html.escape(group.replace('_', ' ').title())}</h2><pre>{_pretty(value)}</pre></section>")
    sections.append(f"<section><h2>Integrity Summary</h2><pre>{_pretty(summary)}</pre></section>")
    body = "\n".join(sections)
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>CyberThreat Shield Hardware Scan Report</title>
<style>
:root{{color-scheme:light dark}}body{{font:15px/1.5 Arial,sans-serif;max-width:1100px;margin:32px auto;padding:0 18px;background:#0f172a;color:#e2e8f0}}
header,section{{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:18px;margin:0 0 16px}}h1,h2{{margin-top:0}}.meta{{color:#cbd5e1}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#020617;padding:14px;border-radius:8px;font-size:13px}}
.note{{color:#cbd5e1;font-size:13px}}
</style></head><body><header><h1>CyberThreat Shield Hardware Scan Report</h1>
<p class="meta">Scan time: {html.escape(scanned_at)}<br>Agent version: {html.escape(agent_version)}</p>
<p class="note">This report contains information reported by the local operating system and heuristic integrity checks. It is not a guarantee that hardware is genuine or physically healthy. USB ports that were not individually tested are not verified by this inventory scan.</p></header>
{body}</body></html>'''
