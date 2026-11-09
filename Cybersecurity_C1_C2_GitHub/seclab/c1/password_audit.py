from __future__ import annotations

import json
import re
from pathlib import Path

REPEAT_PATTERN = re.compile(r"(.)\1{2,}")
SYMBOL_PATTERN = re.compile(r"[^A-Za-z0-9]")

def audit_passwords(passwords_file: str | Path, common_file: str | Path, output_file: str | Path | None = None) -> list[dict[str, object]]:
    common = {
        item.strip().casefold()
        for item in Path(common_file).read_text(encoding="utf-8").splitlines()
        if item.strip()
    }
    report: list[dict[str, object]] = []
    with Path(passwords_file).open("r", encoding="utf-8") as handle:
        for line_number, password_line in enumerate(handle, start=1):
            password = password_line.rstrip("\r\n")
            broken: list[str] = []
            if len(password) < 12:
                broken.append("minimum_length_12")
            if re.search(r"[A-Z]", password) is None:
                broken.append("missing_uppercase")
            if re.search(r"[a-z]", password) is None:
                broken.append("missing_lowercase")
            if re.search(r"[0-9]", password) is None:
                broken.append("missing_digit")
            if SYMBOL_PATTERN.search(password) is None:
                broken.append("missing_symbol")
            if REPEAT_PATTERN.search(password) is not None:
                broken.append("repeated_character_3plus")
            if password.casefold() in common:
                broken.append("common_password")
            report.append({"line": line_number, "broken_rules": broken})
    if output_file is not None:
        Path(output_file).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report
