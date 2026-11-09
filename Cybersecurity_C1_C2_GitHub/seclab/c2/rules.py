from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from datetime import datetime, time, timedelta
from ipaddress import IPv4Address
from typing import Iterable, Mapping, Sequence
from zoneinfo import ZoneInfo

from .models import Alert, SecurityEvent, Severity

logger = logging.getLogger(__name__)

class DetectionRule(ABC):
    name: str
    severity: Severity

    @abstractmethod
    def evaluate(self, events: Sequence[SecurityEvent]) -> list[Alert]:
        raise NotImplementedError

class BruteForceRule(DetectionRule):
    name = "brute_force"
    severity = Severity.HIGH

    def __init__(self, threshold: int = 5, window_seconds: int = 60) -> None:
        if threshold < 1 or window_seconds <= 0:
            raise ValueError("Invalid brute-force threshold/window")
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[Alert]:
        queues: dict[IPv4Address, deque[SecurityEvent]] = defaultdict(deque)
        active: dict[IPv4Address, bool] = defaultdict(bool)
        alerts: list[Alert] = []
        for event in sorted(events):
            if event.action != "login_failed":
                continue
            queue = queues[event.source_ip]
            while queue and event.timestamp - queue[0].timestamp > self.window:
                queue.popleft()
            if len(queue) < self.threshold:
                active[event.source_ip] = False
            queue.append(event)
            if len(queue) >= self.threshold and not active[event.source_ip]:
                names = ", ".join(sorted({item.user for item in queue}))
                alerts.append(Alert(
                    rule=self.name, severity=self.severity, timestamp=event.timestamp,
                    source_ip=event.source_ip,
                    message=f"{len(queue)} failed logins in {self.window.total_seconds():g}s; users: {names}",
                ))
                active[event.source_ip] = True
        return alerts

class OffHoursLoginRule(DetectionRule):
    name = "off_hours_login"
    severity = Severity.MEDIUM

    def __init__(self, source_timezone: str = "UTC", start_hour: int = 8, end_hour: int = 20) -> None:
        if not (0 <= start_hour < end_hour <= 24):
            raise ValueError("Hours must satisfy 0 <= start < end <= 24")
        self.timezone = ZoneInfo(source_timezone)
        self.start_hour = start_hour
        self.end_hour = end_hour

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        for event in events:
            if event.action != "login_success":
                continue
            local_hour = event.timestamp.astimezone(self.timezone).hour
            if not self.start_hour <= local_hour < self.end_hour:
                alerts.append(Alert(
                    rule=self.name, severity=self.severity,
                    timestamp=event.timestamp, source_ip=event.source_ip,
                    message=f"Off-hours login for {event.user} ({self.timezone.key})",
                ))
        return alerts

class NewSourceForUserRule(DetectionRule):
    name = "new_source_for_user"
    severity = Severity.MEDIUM

    def __init__(self, known_sources: Mapping[str, Iterable[IPv4Address]] | None = None) -> None:
        self.known_sources = {
            user: set(ips) for user, ips in (known_sources or {}).items()
        }

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[Alert]:
        known = {user: set(ips) for user, ips in self.known_sources.items()}
        alerts: list[Alert] = []
        for event in sorted(events):
            if event.action != "login_success":
                continue
            if event.user not in known:

                known[event.user] = {event.source_ip}
            elif event.source_ip not in known[event.user]:
                alerts.append(Alert(
                    rule=self.name, severity=self.severity, timestamp=event.timestamp,
                    source_ip=event.source_ip,
                    message=f"New source IP for user {event.user}",
                ))
                known[event.user].add(event.source_ip)
        return alerts

class DetectionEngine:
    def __init__(self, rules: Sequence[DetectionRule]) -> None:
        self.rules = list(rules)

    def run(self, events: Sequence[SecurityEvent]) -> list[Alert]:
        result: list[Alert] = []
        for rule in self.rules:
            try:
                result.extend(rule.evaluate(events))
            except Exception:
                logger.exception("Rule %s failed, proceeding with remaining rules", rule.name)
        return result
