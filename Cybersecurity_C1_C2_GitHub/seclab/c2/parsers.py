from __future__ import annotations

import json
import logging
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any, ClassVar
from zoneinfo import ZoneInfo

from seclab.c1.auth import MalformedLogLine, parse_ssh_line
from .models import EventParseError, SecurityEvent, Severity

log = logging.getLogger(__name__)

class LogParser(ABC):
    _registry: ClassVar[dict[str, type[LogParser]]] = {}

    def __init_subclass__(cls, *, format_name: str | None = None, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if format_name is not None:
            if format_name in cls._registry:
                raise ValueError(f"Duplicate parser format: {format_name}")
            cls._registry[format_name] = cls

    def __init__(self) -> None:
        self.malformed_lines: list[int] = []
        self.skipped = 0

    @abstractmethod
    def parse_line(self, line: str) -> SecurityEvent | None:
        raise NotImplementedError

    def parse_file(self, path: str | Path) -> list[SecurityEvent]:
        self.malformed_lines = []
        self.skipped = 0
        result: list[SecurityEvent] = []
        with Path(path).open("r", encoding="utf-8") as source:
            for line_number, line in enumerate(source, 1):
                try:
                    event = self.parse_line(line.rstrip("\n"))
                except (ValueError, KeyError, TypeError) as exc:
                    self.malformed_lines.append(line_number)
                    log.warning("Malformed line %d: %s", line_number, type(exc).__name__)
                else:
                    if event is None:
                        self.skipped += 1
                    else:
                        result.append(event)
        return result

    @classmethod
    def for_format(cls, name: str, **kwargs: Any) -> LogParser:
        try:
            return cls._registry[name](**kwargs)
        except KeyError as exc:
            raise ValueError(f"Unknown parser: {name}") from exc

class SshAuthParser(LogParser, format_name="ssh"):
    def __init__(self, year: int = 2026, source_timezone: str = "UTC") -> None:
        super().__init__()
        self.year = year
        self.source_tz = ZoneInfo(source_timezone)
        self._previous: datetime | None = None

    def parse_line(self, line: str) -> SecurityEvent | None:
        event = parse_ssh_line(line)
        if event is None:
            return None
        dt = datetime.strptime(f"{self.year} {event['timestamp']}", "%Y %b %d %H:%M:%S")
        if (self._previous is not None and self._previous.month == 12 and dt.month == 1
                and (self._previous - dt).days > 300):
            self.year += 1
            dt = dt.replace(year=self.year)
        self._previous = dt
        utc_timestamp = dt.replace(tzinfo=self.source_tz).astimezone(timezone.utc)
        success = event["result"] == "accepted"
        return SecurityEvent(
            timestamp=utc_timestamp,
            source_ip=IPv4Address(event["ip"]),
            user=event["user"],
            action="login_success" if success else "login_failed",
            severity=Severity.LOW if success else Severity.MEDIUM,
        )

COMBINED_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^]]+)\] '
    r'"(?P<method>\S+) (?P<resource>.*?) HTTP/[\d.]+" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-) "(?:[^"\\]|\\.)*" "(?:[^"\\]|\\.)*"'
)

class WebAccessParser(LogParser, format_name="apache"):
    def parse_line(self, line: str) -> SecurityEvent | None:
        if not line.strip():
            return None
        match = COMBINED_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError("Bad combined Apache log line")
        parts = match.groupdict()
        ts = datetime.strptime(parts["time"], "%d/%b/%Y:%H:%M:%S %z")
        status = int(parts["status"])
        severity = (Severity.HIGH if status >= 500 else
                    Severity.MEDIUM if status >= 400 else Severity.LOW)
        return SecurityEvent(
            timestamp=ts.astimezone(timezone.utc),
            source_ip=IPv4Address(parts["ip"]),
            user=parts["user"] if parts["user"] != "-" else "anonymous",
            action=f"http_{parts['method'].lower()}_{status}",
            severity=severity,
        )

class JsonLineParser(LogParser, format_name="jsonl"):
    def parse_line(self, line: str) -> SecurityEvent | None:
        if not line.strip():
            return None
        try:
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError("JSON event must be an object")
            return SecurityEvent.from_dict(value)
        except (json.JSONDecodeError, EventParseError) as exc:
            raise ValueError("Malformed JSON event") from exc
