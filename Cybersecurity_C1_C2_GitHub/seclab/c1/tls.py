from __future__ import annotations

import csv
import math
from datetime import datetime, timezone
from pathlib import Path

class UnknownDateFormat(ValueError):
    pass

DATE_FORMATS = ("%b %d %H:%M:%S %Y GMT", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z")

def parse_not_after(value: str) -> datetime:
    for format_string in DATE_FORMATS:
        try:
            dt = datetime.strptime(value, format_string)
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
        except ValueError:
            continue
    raise UnknownDateFormat(f"Unsupported certificate expiry date format: {value!r}")

def check_certificates(inventory_csv: str | Path, output_csv: str | Path, now: datetime) -> list[dict[str, str]]:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    now = now.astimezone(timezone.utc)
    result: list[dict[str, str]] = []
    with Path(inventory_csv).open(newline="", encoding="utf-8") as source:
        for row in csv.DictReader(source):
            expires = parse_not_after(row["notAfter"])
            seconds = (expires - now).total_seconds()
            days = math.floor(seconds / 86400)
            if seconds <= 0:
                status = "expired"
            elif seconds < 14 * 86400:
                status = "critical"
            elif seconds < 30 * 86400:
                status = "warning"
            else:
                status = "ok"
            result.append({
                "hostname": row["hostname"],
                "notAfter": expires.isoformat(),
                "days_remaining": str(days),
                "status": status,
            })
    result.sort(key=lambda r: (int(r["days_remaining"]), r["hostname"]))
    with Path(output_csv).open("w", newline="", encoding="utf-8") as target:
        writer = csv.DictWriter(target, fieldnames=["hostname", "notAfter", "days_remaining", "status"])
        writer.writeheader()
        writer.writerows(result)
    return result
