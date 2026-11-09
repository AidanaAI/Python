from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address
from pathlib import Path

from seclab.c1.auth import parse_auth_log_with_report
from seclab.c1.brute_force import detect_brute_force
from seclab.c1.ioc import extract_iocs_from_file
from seclab.c1.password_audit import audit_passwords
from seclab.c1.integrity import create_baseline, check_integrity
from seclab.c1.tls import check_certificates
from seclab.c2.models import Alert, SecurityEvent, Severity
from seclab.c2.parsers import LogParser
from seclab.c2.rules import DetectionEngine, BruteForceRule, OffHoursLoginRule, NewSourceForUserRule
from seclab.c2.secret import Secret
from seclab.c2.notifiers import EmailNotifier, SmsNotifier, WebhookNotifier
from seclab.c2.sinks import ConsoleSink, CsvSink, JsonLinesSink, MultiSink

DATA = Path(__file__).resolve().parent / "data"

def run_demo() -> None:
    print("C1.1 SSH log:")
    summary = parse_auth_log_with_report(DATA / "auth.log")
    print(json.dumps(summary, indent=2))

    print("\nC1.2 Brute force with 5 synthetic events:")
    from seclab.c1.auth import AuthEvent
    failures: list[AuthEvent] = [
        {"timestamp": f"Nov 08 12:00:{i:02d}", "host": "demo", "result": "failed",
         "user": "admin", "invalid_user": True, "ip": "203.0.113.45", "port": 22}
        for i in range(5)
    ]
    print(detect_brute_force(failures, 2026, "Asia/Almaty"))

    with tempfile.TemporaryDirectory() as folder:
        out = Path(folder)
        print("\nC1.3 IOC counts:")
        iocs = extract_iocs_from_file(DATA / "threat_report.txt", out / "iocs.json")
        print({type_: len(values) for type_, values in iocs.items()})
        print("\nC1.4 Password audit (no password contents):")
        print(audit_passwords(DATA / "passwords.txt", DATA / "common_passwords.txt"))
        print("\nC1.5 File integrity:")
        example_dir = out / "files"
        example_dir.mkdir()
        sample = example_dir / "a.txt"
        sample.write_text("before")
        create_baseline(example_dir, out / "baseline.json")
        sample.write_text("after")
        (example_dir / "new.txt").write_text("new")
        print(check_integrity(example_dir, out / "baseline.json"))
        print("\nC1.6 TLS expiration:")
        print(check_certificates(DATA / "tls_inventory.csv", out / "certs.csv", datetime(2026, 11, 8, tzinfo=timezone.utc)))

        print("\nC2.1 SecurityEvent:")
        t0 = datetime(2026, 11, 8, 2, 0, tzinfo=timezone.utc)
        event = SecurityEvent(t0, IPv4Address("203.0.113.45"), "aru", "login_success", Severity.LOW)
        print(event)
        print("\nC2.2 LogParser registry:")
        parser = LogParser.for_format("ssh", year=2026, source_timezone="Asia/Almaty")
        print("events:", len(parser.parse_file(DATA / "auth.log")), "; malformed:", parser.malformed_lines)
        print("\nC2.3 Rules:")
        batch = [SecurityEvent(t0 + timedelta(seconds=i * 10), event.source_ip, "aru", "login_failed", Severity.MEDIUM) for i in range(5)]
        batch.append(event)
        print([a.to_dict() for a in DetectionEngine([BruteForceRule(), OffHoursLoginRule("UTC"), NewSourceForUserRule()]).run(batch)])
        print("\nC2.4 Secret redaction:")
        secret = Secret("hidden_api_token")
        print(secret, repr({secret: 1}))
        print("\nC2.5 Notifier LSP contract:")
        print({cls.__name__: cls().send("x" * 350) for cls in (EmailNotifier, SmsNotifier, WebhookNotifier)})
        print("\nC2.6 MultiSink (writes JSONL and CSV):")
        alert = Alert("test", Severity.HIGH, t0, event.source_ip, "Example alert")
        MultiSink([ConsoleSink(), JsonLinesSink(out / "alerts.jsonl"), CsvSink(out / "alerts.csv")]).send(alert)
        print("JSONL:", (out / "alerts.jsonl").read_text().strip())

if __name__ == "__main__":
    run_demo()
