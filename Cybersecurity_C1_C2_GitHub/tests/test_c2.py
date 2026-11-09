from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from seclab.c2.models import Alert, EventParseError, SecurityEvent, Severity
from seclab.c2.parsers import LogParser, SshAuthParser, WebAccessParser, JsonLineParser
from seclab.c2.rules import (BruteForceRule, DetectionEngine, DetectionRule,
                             NewSourceForUserRule, OffHoursLoginRule)
from seclab.c2.secret import Secret
from seclab.c2.notifiers import Notifier, EmailNotifier, SmsNotifier, WebhookNotifier
from seclab.c2.sinks import AlertSink, ConsoleSink, CsvSink, JsonLinesSink, MultiSink

DATA = Path(__file__).resolve().parent.parent / "examples" / "data"
T0 = datetime(2026, 11, 8, 3, 0, 0, tzinfo=timezone.utc)

def _event(sec: int = 0, ip: str = "203.0.113.45", user: str = "aru", action: str = "login_failed") -> SecurityEvent:
    return SecurityEvent(T0 + timedelta(seconds=sec), IPv4Address(ip), user, action, Severity.LOW)

def test_c21_immutable_sorted_hashable_from_dict() -> None:
    events = [_event(20), _event(10), _event(30)]
    assert sorted(events) == [events[1], events[0], events[2]]
    assert len(set([_event(20), _event(20)])) == 1
    converted = SecurityEvent.from_dict({
        "timestamp": "2026-11-08T08:00:00+05:00", "source_ip": "198.51.100.1",
        "user": "a", "action": "login_success", "severity": "high",
    })
    assert converted.timestamp == T0
    assert converted.severity is Severity.HIGH
    with pytest.raises(ValueError):
        SecurityEvent(datetime(2026, 1, 1), IPv4Address("1.2.3.4"), "a", "ok", Severity.LOW)
    with pytest.raises(EventParseError) as exc_info:
        SecurityEvent.from_dict({"timestamp": "nonsense"})
    assert exc_info.value.__cause__ is not None

def test_c22_abc_registry_and_ssh() -> None:
    with pytest.raises(TypeError):
        LogParser()
    parser = LogParser.for_format("ssh", year=2026, source_timezone="Asia/Almaty")
    assert isinstance(parser, SshAuthParser)
    events = parser.parse_file(DATA / "auth.log")
    assert len(events) == 3
    assert parser.skipped == 1
    assert parser.malformed_lines == [5]
    assert events[0].timestamp.hour == 3

def test_c22_apache_jsonl_and_dynamic_parser(tmp_path: Path) -> None:
    apache = LogParser.for_format("apache")
    event = apache.parse_line('198.51.100.7 - frank [10/Oct/2026:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"')
    assert isinstance(event, SecurityEvent)
    assert event.action == "http_get_200"
    parser = LogParser.for_format("jsonl")
    f = tmp_path / "events.jsonl"
    f.write_text(json.dumps({"timestamp": T0.isoformat(), "source_ip": "203.0.113.45",
                            "user": "aru", "action": "login_success", "severity": "LOW"}) + "\nwrong-json\n")
    assert len(parser.parse_file(f)) == 1
    assert parser.malformed_lines == [2]

    class CustomParser(LogParser, format_name="custom_for_test"):
        def parse_line(self, line: str) -> SecurityEvent | None:
            return _event() if line == "valid" else None

    assert isinstance(LogParser.for_format("custom_for_test"), CustomParser)

def test_c23_three_rules_and_engine_exception_isolation(caplog: pytest.LogCaptureFixture) -> None:
    class BrokenRule(DetectionRule):
        name = "broken"
        severity = Severity.CRITICAL

        def evaluate(self, events: list[SecurityEvent]) -> list[Alert]:
            raise RuntimeError("test error")

    failures = [_event(i * 10) for i in range(5)]
    successes = [_event(61, ip="198.51.100.2", action="login_success"),
                 _event(62, ip="203.0.113.4", action="login_success")]
    rules = [BrokenRule(), BruteForceRule(), OffHoursLoginRule("UTC"), NewSourceForUserRule()]
    with caplog.at_level(logging.ERROR):
        alerts = DetectionEngine(rules).run(failures + successes)
    assert any(a.rule == "brute_force" for a in alerts)
    assert sum(a.rule == "off_hours_login" for a in alerts) == 2
    assert any(a.rule == "new_source_for_user" for a in alerts)
    assert "Rule broken failed" in caplog.text

def test_c23_rules_empty_early_4_and_late_5() -> None:
    assert BruteForceRule().evaluate([_event(i * 10) for i in range(4)]) == []
    assert BruteForceRule().evaluate([_event(i) for i in [0, 15, 30, 45, 61]]) == []

def test_c24_masking_collections_and_logging(caplog: pytest.LogCaptureFixture) -> None:
    raw = "SuperSecretApiKey_99!"
    sec = Secret(raw)
    assert sec.reveal() == raw
    assert str(sec) == "Secret('********')"
    assert repr(sec) == str(sec)
    assert f"{sec}" == str(sec)
    assert sec == Secret(raw)
    assert sec != Secret("not-the-same")
    assert hash(sec) == hash(Secret(raw))
    with caplog.at_level(logging.ERROR):
        logging.error("Token: %s", sec)
    for view in [str(sec), repr({sec: 1}), str([sec]), str(Exception(sec)), caplog.text]:
        assert raw not in view

@pytest.mark.parametrize("factory", [EmailNotifier, SmsNotifier, WebhookNotifier])
@pytest.mark.parametrize("message", ["hello", "x" * 350, ""])
def test_c25_contract_success(factory: type[Notifier], message: str) -> None:
    notifier = factory(reachable=True)
    result = notifier.send(message)
    assert result is True
    assert isinstance(result, bool)

@pytest.mark.parametrize("factory", [EmailNotifier, SmsNotifier, WebhookNotifier])
@pytest.mark.parametrize("message", ["hello", "x" * 350])
def test_c25_contract_failure(factory: type[Notifier], message: str) -> None:
    notifier = factory(reachable=False)
    result = notifier.send(message)
    assert result is False
    assert isinstance(result, bool)

def test_c25_sms_split_no_data_loss() -> None:
    notifier = SmsNotifier()
    message = "x" * 350
    assert notifier.send(message)
    assert [len(chunk) for chunk in notifier.sent_chunks] == [160, 160, 30]
    assert "".join(notifier.sent_chunks) == message

def test_c26_sinks_and_bad_sink_isolation(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    alert = Alert("brute_force", Severity.HIGH, T0, IPv4Address("203.0.113.45"), "Five failures")
    stream = io.StringIO()
    jsonpath = tmp_path / "alerts.jsonl"
    csvpath = tmp_path / "alerts.csv"

    class BrokenSink:
        def send(self, alert: Alert) -> None:
            raise OSError("sink unavailable")

    all_sinks: list[AlertSink] = [ConsoleSink(stream), BrokenSink(), JsonLinesSink(jsonpath), CsvSink(csvpath)]
    with caplog.at_level(logging.ERROR):
        MultiSink(all_sinks).send(alert)
    assert "Five failures" in stream.getvalue()
    assert json.loads(jsonpath.read_text().strip())["source_ip"] == "203.0.113.45"
    with csvpath.open(newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1
    assert rows[0]["rule"] == "brute_force"
    assert "Failed to send alert" in caplog.text
