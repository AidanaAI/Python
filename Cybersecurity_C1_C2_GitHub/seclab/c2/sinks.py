from __future__ import annotations

import csv
import json
import logging
import sys
from pathlib import Path
from typing import Protocol, Sequence, TextIO

from .models import Alert

logger = logging.getLogger(__name__)

class AlertSink(Protocol):
    def send(self, alert: Alert) -> None: ...

class ConsoleSink:
    def __init__(self, stream: TextIO | None = None) -> None:
        self.stream = stream

    def send(self, alert: Alert) -> None:
        destination = self.stream if self.stream is not None else sys.stdout
        print(f"[{alert.severity.value}] {alert.timestamp.isoformat()} {alert.rule}: {alert.message}", file=destination)

class JsonLinesSink:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def send(self, alert: Alert) -> None:
        with self.path.open("a", encoding="utf-8") as destination:
            destination.write(json.dumps(alert.to_dict()) + "\n")

class CsvSink:
    columns = ("rule", "severity", "timestamp", "source_ip", "message")

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def send(self, alert: Alert) -> None:
        need_header = not self.path.exists() or self.path.stat().st_size == 0
        with self.path.open("a", newline="", encoding="utf-8") as destination:
            writer = csv.DictWriter(destination, fieldnames=self.columns)
            if need_header:
                writer.writeheader()
            writer.writerow(alert.to_dict())

class MultiSink:
    def __init__(self, sinks: Sequence[AlertSink]) -> None:
        self.sinks = list(sinks)

    def send(self, alert: Alert) -> None:
        for sink in self.sinks:
            try:
                sink.send(alert)
            except Exception:
                logger.exception("Failed to send alert to sink %s", type(sink).__name__)
