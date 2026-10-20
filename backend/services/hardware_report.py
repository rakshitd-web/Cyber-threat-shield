
import html
import json
from datetime import datetime


def escape(value):
    return html.escape(str(value)) if value is not None else "N/A"


def format_label(key):
    return str(key).replace("_", " ").replace("-", " ").title()


def format_value(value):
    if value is None:
        return "Not available"

    if isinstance(value, bool):
        return "Yes" if value else "No"

    if isinstance(value, int) and value >= 1024**3:
        return f"{value / (1024**3):.2f} GB"

    return str(value)


def render_fields(data, exclude=None):
    exclude = set(exclude or [])
    rows = []

    if not isinstance(data, dict):
        return ""

    for key, value in data.items():
        if key in exclude:
            continue

        label = escape(format_label(key))

        if isinstance(value, (dict, list)):
            content = escape(
                json.dumps(value, indent=2, ensure_ascii=False, default=str)
            )
            rendered_value = f"""
                <details>
                    <summary>View details</summary>
                    <pre>{content}</pre>
                </details>
            """
        else:
            rendered_value = escape(format_value(value))

        rows.append(f"""
            <div class="field">
                <span class="field-label">{label}</span>
                <div class="field-value">{rendered_value}</div>
            </div>
        """)

    return "".join(rows)



def _first_present(data, keys):
    """Return the first non-empty value found for any of the supplied keys."""
    if not isinstance(data, dict):
        return None

    for key in keys:
        value = data.get(key)
        if value not in (None, "", [], {}):
            return value

    return None


def _as_explanation_text(value):
    """Convert common strings, lists, and dictionaries into readable text."""
    if value is None:
        return None

    if isinstance(value, str):
        return value.strip() or None

    if isinstance(value, (list, tuple)):
        parts = [_as_explanation_text(item) for item in value]
        parts = [part for part in parts if part]
        return "; ".join(parts) if parts else None

    if isinstance(value, dict):
        # Prefer human-readable explanation fields over dumping raw metadata.
        preferred = _first_present(
            value,
            ("description", "message", "reason", "finding", "name", "title", "detail")
        )
        if preferred is not None:
            return _as_explanation_text(preferred)

        return json.dumps(value, ensure_ascii=False, default=str)

    return str(value)


def render_issue_analysis(item):
    """
    Render cause, recommended solution, and potential risks from the scanner's
    integrity metadata. Use cautious fallbacks when the scanner did not provide
    a specific cause, remediation, or risk.
    """
    integrity = item.get("integrity", {}) if isinstance(item, dict) else {}
    if not isinstance(integrity, dict):
        integrity = {}

    status = str(integrity.get("status", item.get("status", "UNKNOWN"))).strip().upper()

    normal_statuses = {
        "VERIFIED", "OK", "PASS", "PASSED", "HEALTHY", "NORMAL", "SUCCESS"
    }

    # Don't label a normal result as an issue.
    if status in normal_statuses:
        return ""

    cause = _as_explanation_text(_first_present(
        integrity,
        ("cause", "root_cause", "reason", "explanation", "details", "message", "finding", "evidence")
    ))
    solution = _as_explanation_text(_first_present(
        integrity,
        ("solution", "recommended_solution", "recommendation", "remediation", "fix", "recommended_action", "action")
    ))
    risks = _as_explanation_text(_first_present(
        integrity,
        ("risks", "risk", "potential_risk", "impact", "consequences", "potential_impact")
    ))

    # Some analyzers may return structured checks/findings rather than top-level
    # explanation fields. Extract available human-readable details when possible.
    findings = _first_present(integrity, ("findings", "issues", "checks", "failed_checks", "warnings"))
    if isinstance(findings, list) and findings:
        finding_causes = []
        finding_solutions = []
        finding_risks = []

        for finding in findings:
            if not isinstance(finding, dict):
                text_value = _as_explanation_text(finding)
                if text_value:
                    finding_causes.append(text_value)
                continue

            finding_cause = _as_explanation_text(_first_present(
                finding, ("cause", "root_cause", "reason", "explanation", "details", "message", "finding", "evidence", "name")
            ))
            finding_solution = _as_explanation_text(_first_present(
                finding, ("solution", "recommended_solution", "recommendation", "remediation", "fix", "recommended_action", "action")
            ))
            finding_risk = _as_explanation_text(_first_present(
                finding, ("risks", "risk", "potential_risk", "impact", "consequences", "potential_impact")
            ))

            if finding_cause:
                finding_causes.append(finding_cause)
            if finding_solution:
                finding_solutions.append(finding_solution)
            if finding_risk:
                finding_risks.append(finding_risk)

        cause = cause or _as_explanation_text(finding_causes)
        solution = solution or _as_explanation_text(finding_solutions)
        risks = risks or _as_explanation_text(finding_risks)

    if not cause:
        if status in {"UNKNOWN", "UNVERIFIED", "NOT_CHECKED", "NOT CHECKED"}:
            cause = (
                "The scanner could not verify this component using the available "
                "system information. This status does not by itself prove a fault or tampering."
            )
        else:
            cause = (
                "The scanner flagged this component, but the collected metadata does not "
                "establish a specific root cause."
            )

    if not solution:
        solution = (
            "Review the evidence and verify the component's status using the operating "
            "system or the device manufacturer's diagnostic tools. Apply a fix only after "
            "the underlying issue is confirmed."
        )

    if not risks:
        risks = (
            "The potential impact cannot be determined from the available scan data alone. "
            "Treat this as an item to investigate, not proof that the component is damaged "
            "or compromised."
        )

    return f"""
        <section class="issue-analysis">
            <h4>Issue Analysis</h4>
            <div class="issue-field">
                <strong>Cause</strong>
                <p>{escape(cause)}</p>
            </div>
            <div class="issue-field">
                <strong>Recommended Solution</strong>
                <p>{escape(solution)}</p>
            </div>
            <div class="issue-field">
                <strong>Potential Risks</strong>
                <p>{escape(risks)}</p>
            </div>
        </section>
    """

def render_component(group, data):
    title = format_label(group)

    if not data:
        return f"""
            <section class="component">
                <h2>{escape(title)}</h2>
                <p class="muted">No information available.</p>
            </section>
        """

    items = data if isinstance(data, list) else [data]
    cards = []

    for index, item in enumerate(items, 1):
        if isinstance(item, dict):
            name = (
                item.get("name")
                or item.get("model")
                or item.get("manufacturer")
                or f"{title} {index}"
            )

            status = (
                item.get("integrity", {}).get("status", "UNKNOWN")
                if isinstance(item.get("integrity"), dict)
                else item.get("status", "UNKNOWN")
            )

            fields = render_fields(item, exclude={"integrity"})
            issue_analysis = render_issue_analysis(item)

            cards.append(f"""
                <article class="device">
                    <div class="device-header">
                        <h3>{escape(name)}</h3>
                        <span class="status">{escape(status)}</span>
                    </div>
                    <div class="fields">{fields}</div>
                    {issue_analysis}
                </article>
            """)
        else:
            cards.append(f"<p>{escape(format_value(item))}</p>")

    return f"""
        <section class="component">
            <div class="section-header">
                <h2>{escape(title)}</h2>
                <span class="count">{len(items)} items</span>
            </div>
            {"".join(cards)}
        </section>
    """


def generate_hardware_report(
    hardware,
    scan_timestamp=None,
    agent_version="1.1.0"
):
    if not isinstance(hardware, dict):
        hardware = {}

    try:
        timestamp = (
            datetime.fromtimestamp(float(scan_timestamp)).astimezone()
            if scan_timestamp is not None
            else datetime.now().astimezone()
        )
        scanned_at = timestamp.strftime("%d %b %Y, %I:%M:%S %p %Z")
    except (TypeError, ValueError, OSError, OverflowError):
        scanned_at = "Unavailable"

    groups = [
        "system",
        "cpu",
        "gpu",
        "memory",
        "motherboard",
        "bios",
        "storage",
        "network",
        "usb",
        "battery",
    ]

    overview_groups = [
        ("cpu", "CPU"),
        ("gpu", "GPU"),
        ("memory", "Memory"),
        ("storage", "Storage"),
        ("network", "Network"),
        ("usb", "USB"),
        ("battery", "Battery"),
    ]

    overview = []

    for key, label in overview_groups:
        value = hardware.get(key, [])

        if isinstance(value, list):
            count = len(value)
        elif isinstance(value, dict):
            count = 1 if value else 0
        else:
            count = 1 if value else 0

        overview.append(f"""
            <div class="overview-card">
                <span>{escape(label)}</span>
                <strong>{count}</strong>
                <small>Detected items</small>
            </div>
        """)

    sections = "".join(
        render_component(group, hardware.get(group, []))
        for group in groups
    )

    summary = hardware.get("integrity_summary", {})
    summary_fields = render_fields(summary)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CyberThreat Shield - Hardware Report</title>
<style>
:root {{
    color-scheme: dark;
    --background: #0b1120;
    --panel: #131e30;
    --inner: #18263a;
    --border: #2b3b52;
    --text: #e5edf7;
    --muted: #9aabc1;
    --accent: #38bdf8;
}}
* {{ box-sizing: border-box; }}
body {{
    margin: 0;
    padding: 24px;
    background: var(--background);
    color: var(--text);
    font: 15px/1.6 Arial, sans-serif;
}}
.container {{ max-width: 1100px; margin: auto; }}
header, .component {{
    padding: 22px;
    margin-bottom: 18px;
    border: 1px solid var(--border);
    border-radius: 12px;
    background: var(--panel);
}}
.brand {{
    color: var(--accent);
    font-size: 12px;
    font-weight: bold;
    letter-spacing: 1.5px;
    text-transform: uppercase;
}}
h1 {{ margin: 8px 0; font-size: 32px; }}
h2 {{ margin: 0; font-size: 20px; }}
h3 {{ margin: 0; font-size: 16px; overflow-wrap: anywhere; }}
.muted, small {{ color: var(--muted); }}
.metadata {{
    display: flex;
    flex-wrap: wrap;
    gap: 10px 24px;
    margin-top: 18px;
    color: var(--muted);
    font-size: 13px;
}}
.section-title {{ margin: 28px 0 14px; }}
.overview {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
    gap: 12px;
    margin-bottom: 28px;
}}
.overview-card {{
    padding: 16px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
}}
.overview-card span, .overview-card small {{ display: block; }}
.overview-card strong {{ display: block; font-size: 28px; margin: 5px 0; }}
.section-header, .device-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 10px;
}}
.section-header {{ margin-bottom: 16px; }}
.count, .status {{
    padding: 4px 10px;
    border: 1px solid var(--border);
    border-radius: 20px;
    color: var(--muted);
    font-size: 12px;
}}
.device {{
    padding: 16px;
    margin-top: 12px;
    background: var(--inner);
    border: 1px solid var(--border);
    border-radius: 9px;
    min-width: 0;
}}
.fields {{ margin-top: 12px; }}
.field {{
    display: grid;
    grid-template-columns: minmax(130px, 0.7fr) minmax(0, 1.3fr);
    gap: 16px;
    padding: 10px 0;
    border-bottom: 1px solid var(--border);
    min-width: 0;
}}
.field:last-child {{ border-bottom: none; }}
.field-label {{ color: var(--muted); }}
.field-value {{ min-width: 0; overflow-wrap: anywhere; word-break: break-word; }}
.issue-analysis {{
    margin-top: 16px;
    padding: 14px;
    border: 1px solid #594b2c;
    border-radius: 8px;
    background: #211f1a;
    break-inside: avoid;
}}
.issue-analysis h4 {{
    margin: 0 0 10px;
    font-size: 15px;
    color: var(--accent);
}}
.issue-field {{
    padding: 8px 0;
    border-top: 1px solid var(--border);
}}
.issue-field strong {{
    display: block;
    margin-bottom: 3px;
}}
.issue-field p {{
    margin: 0;
    overflow-wrap: anywhere;
}}

summary {{ color: var(--accent); cursor: pointer; }}
pre {{
    padding: 12px;
    background: #080e19;
    border-radius: 8px;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    font: 12px/1.6 Consolas, monospace;
}}
.notice {{
    padding: 16px;
    border: 1px solid #594b2c;
    border-radius: 10px;
    background: #292416;
    color: #e7d9b5;
    font-size: 13px;
}}
footer {{
    margin-top: 22px;
    padding: 16px 0;
    border-top: 1px solid var(--border);
    color: var(--muted);
    font-size: 12px;
    text-align: center;
}}
@media (max-width: 560px) {{
    body {{ padding: 10px; }}
    header, .component {{ padding: 15px; }}
    h1 {{ font-size: 25px; }}
    .field {{ grid-template-columns: 1fr; gap: 4px; }}
}}
@media print {{
    :root {{
        color-scheme: light;
        --background: white;
        --panel: white;
        --inner: #f8fafc;
        --border: #d1d5db;
        --text: #111827;
        --muted: #4b5563;
        --accent: #0369a1;
    }}
    body {{ background: white; color: #111827; }}
    header, .component, .overview-card, .device {{ break-inside: avoid; }}
    pre {{ color: #111827; background: #f3f4f6; }}
    .notice {{ background: white; color: #333; }}
    .issue-analysis {{ background: #fffaf0; color: #111827; border-color: #b8a57b; }}
    .issue-analysis h4 {{ color: #075985; }}

}}
</style>
</head>
<body>
<main class="container">
<header>
    <div class="brand">CyberThreat Shield</div>
    <h1>Hardware Scan Report</h1>
    <p class="muted">Hardware inventory and integrity assessment.</p>
    <div class="metadata">
        <span>Scan time: <strong>{escape(scanned_at)}</strong></span>
        <span>Agent version: <strong>{escape(agent_version)}</strong></span>
    </div>
</header>

<h2 class="section-title">Hardware Overview</h2>
<div class="overview">
    {"".join(overview)}
</div>

<h2 class="section-title">Component Details</h2>
{sections}

<section class="component">
    <h2>Integrity Summary</h2>
    <div class="fields">{summary_fields or '<p class="muted">No integrity summary available.</p>'}</div>
</section>

<div class="notice">
    <strong>Report limitations</strong>
    <p>
        The report reflects information returned by the operating system
        and heuristic checks. A VERIFIED result does not prove physical
        authenticity or guarantee that hardware is free of tampering.
        USB inventory does not confirm that every physical port was tested.
    </p>
</div>

<footer>Generated by CyberThreat Shield Hardware Agent.</footer>
</main>
</body>
</html>"""
