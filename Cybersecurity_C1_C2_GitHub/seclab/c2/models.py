from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from ipaddress import IPv4Address, ip_address
from typing import Any, Mapping

class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class EventParseError(ValueError):
    pass

@dataclass(frozen=True, order=True)
class SecurityEvent:
    timestamp: datetime
    source_ip: IPv4Address = field(compare=False)
    user: str = field(compare=False)
    action: str = field(compare=False)
    severity: Severity = field(compare=False)

    def __post_init__(self) -> None:
        offset = self.timestamp.utcoffset()
        if self.timestamp.tzinfo is None or offset is None:
            raise ValueError("timestamp must be timezone-aware")
        if offset.total_seconds() != 0:
            raise ValueError("timestamp must be in UTC")
        if not self.action.strip():
            raise ValueError("action must not be empty")
        if not isinstance(self.source_ip, IPv4Address):
            raise ValueError("source_ip must be an IPv4Address")
        if not isinstance(self.severity, Severity):
            raise ValueError("severity must be a Severity enum")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SecurityEvent:
        try:
            raw_timestamp = data["timestamp"]
            if isinstance(raw_timestamp, datetime):
                timestamp = raw_timestamp
            else:
                timestamp = datetime.fromisoformat(str(raw_timestamp).replace("Z", "+00:00"))
            if timestamp.tzinfo is None or timestamp.utcoffset() is None:
                raise ValueError("Timestamp lacks timezone")
            timestamp = timestamp.astimezone(timezone.utc)
            address = ip_address(str(data["source_ip"]))
            if not isinstance(address, IPv4Address):
                raise ValueError("IPv6 addresses are not supported")
            raw_severity = data["severity"]
            severity = (raw_severity if isinstance(raw_severity, Severity)
                        else Severity[str(raw_severity).upper()])
            return cls(timestamp, address, str(data["user"]), str(data["action"]), severity)
        except (ValueError, KeyError, TypeError) as exc:
            raise EventParseError("Invalid security event record") from exc

@dataclass(frozen=True)
class Alert:
    rule: str
    severity: Severity
    timestamp: datetime
    source_ip: IPv4Address
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "rule": self.rule,
            "severity": self.severity.value,
            "timestamp": self.timestamp.astimezone(timezone.utc).isoformat(),
            "source_ip": str(self.source_ip),
            "message": self.message,
        }
