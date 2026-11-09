from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from typing import Iterable, TypedDict

from .auth import AuthEvent

class BruteForceAlert(TypedDict):
    ip: str
    attempt_count: int
    first_timestamp: str
    last_timestamp: str
    targeted_usernames: list[str]

def timestamped_events(
    events: Iterable[AuthEvent], year: int, source_timezone: str = "UTC"
) -> list[tuple[AuthEvent, datetime]]:
    tz = ZoneInfo(source_timezone)
    current_year = year
    previous_local: datetime | None = None
    converted: list[tuple[AuthEvent, datetime]] = []
    for event in events:
        local_naive = datetime.strptime(
            f"{current_year} {event['timestamp']}", "%Y %b %d %H:%M:%S"
        )
        if (
            previous_local is not None
            and previous_local.month == 12
            and local_naive.month == 1
            and (previous_local - local_naive).days > 300
        ):
            current_year += 1
            local_naive = local_naive.replace(year=current_year)
        previous_local = local_naive
        converted.append((event, local_naive.replace(tzinfo=tz).astimezone(timezone.utc)))
    return converted

def detect_brute_force(
    events: Iterable[AuthEvent],
    year: int,
    source_timezone: str = "UTC",
    threshold: int = 5,
    window_seconds: int = 60,
) -> list[BruteForceAlert]:
    if threshold < 1 or window_seconds <= 0:
        raise ValueError("threshold must be positive and window_seconds > 0")
    failed = [(e, dt) for e, dt in timestamped_events(events, year, source_timezone)
              if e["result"] == "failed"]
    failed.sort(key=lambda item: item[1])
    queues: dict[str, deque[tuple[AuthEvent, datetime]]] = defaultdict(deque)
    active: dict[str, bool] = defaultdict(bool)
    alerts: list[BruteForceAlert] = []
    for event, when in failed:
        ip = event["ip"]
        queue = queues[ip]
        while queue and when - queue[0][1] > timedelta(seconds=window_seconds):
            queue.popleft()
        if len(queue) < threshold:
            active[ip] = False
        queue.append((event, when))
        if len(queue) >= threshold and not active[ip]:
            alerts.append({
                "ip": ip,
                "attempt_count": len(queue),
                "first_timestamp": queue[0][1].isoformat(),
                "last_timestamp": queue[-1][1].isoformat(),
                "targeted_usernames": sorted({ev["user"] for ev, _ in queue}),
            })
            active[ip] = True
    return alerts
