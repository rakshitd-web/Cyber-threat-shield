
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
