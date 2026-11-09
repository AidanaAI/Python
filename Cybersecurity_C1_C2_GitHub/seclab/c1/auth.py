from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import TypedDict

log = logging.getLogger(__name__)

class AuthEvent(TypedDict):
    timestamp: str
    host: str
    result: str
    user: str
    invalid_user: bool
    ip: str
    port: int

class MalformedLogLine(ValueError):
    pass

SSH_PATTERN = re.compile(
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>[\w.-]+)\s+sshd\[\d+\]:\s+"
    r"(?P<result>Failed|Accepted)\s+"
    r"(?:password|publickey|keyboard-interactive(?:/pam)?)\s+for\s+"
    r"(?P<invalid>invalid\s+user\s+)?"
    r"(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"port\s+(?P<port>\d+)\s+ssh2"
)

class AuthLogFileError(OSError):
    pass

def parse_ssh_line(line: str) -> AuthEvent | None:
    text = line.strip()
    if not text:
        return None
    if "sshd" not in text and not text.startswith("### corrupted"):
        return None
    match = SSH_PATTERN.fullmatch(text)
    if match is None:
        raise MalformedLogLine("SSH entry does not match the expected format")
    fields = match.groupdict()

    import ipaddress

    try:
        ipaddress.IPv4Address(fields["ip"])
        port = int(fields["port"])
        if not 0 < port < 65536:
            raise ValueError("Port out of range")
    except ValueError as exc:
        raise MalformedLogLine("Invalid SSH address or port") from exc
    return {
        "timestamp": fields["timestamp"],
        "host": fields["host"],
        "result": fields["result"].lower(),
        "user": fields["user"],
        "invalid_user": fields["invalid"] is not None,
        "ip": fields["ip"],
        "port": port,
    }

class ParseSummary(TypedDict):
    events: list[AuthEvent]
    skipped: int
    malformed_lines: list[int]

def parse_auth_log_with_report(path: str | Path) -> ParseSummary:
    events: list[AuthEvent] = []
    skipped = 0
    malformed_lines: list[int] = []
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                try:
                    event = parse_ssh_line(line)
                except MalformedLogLine as exc:
                    malformed_lines.append(number)
                    log.warning("Malformed SSH log at line %s: %s", number, exc)
                    continue
                if event is None:
                    skipped += 1
                else:
                    events.append(event)
    except FileNotFoundError as exc:
        raise AuthLogFileError(f"Authentication log not found: {path}") from exc
    except PermissionError as exc:
        raise AuthLogFileError(f"Permission denied reading auth log: {path}") from exc
    return {"events": events, "skipped": skipped, "malformed_lines": malformed_lines}

def parse_auth_log(path: str | Path) -> list[AuthEvent]:
    return parse_auth_log_with_report(path)["events"]
