from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from seclab.c1.auth import AuthLogFileError, parse_auth_log, parse_auth_log_with_report
from seclab.c1.brute_force import detect_brute_force, timestamped_events
from seclab.c1.ioc import extract_iocs, extract_iocs_from_file
from seclab.c1.password_audit import audit_passwords
from seclab.c1.integrity import create_baseline, check_integrity
from seclab.c1.tls import UnknownDateFormat, parse_not_after, check_certificates

DATA = Path(__file__).resolve().parent.parent / "examples" / "data"

def _failed(times: list[datetime], ip: str = "203.0.113.45") -> list[dict]:
    return [{
        "timestamp": time.strftime("%b %d %H:%M:%S"),
        "host": "srv01", "result": "failed", "user": f"u{i}",
        "invalid_user": False, "ip": ip, "port": 22,
    } for i, time in enumerate(times)]

def test_c11_sample_and_missing_file(tmp_path: Path) -> None:
    report = parse_auth_log_with_report(DATA / "auth.log")
    assert len(report["events"]) == 3
    assert report["skipped"] == 1
    assert report["malformed_lines"] == [5]
    assert report["events"][0]["invalid_user"]
    assert report["events"][1]["result"] == "failed"
    assert len(parse_auth_log(DATA / "auth.log")) == 3
    with pytest.raises(AuthLogFileError, match="not found"):
        parse_auth_log(tmp_path / "missing.log")

def test_c11_malformed_sshd(tmp_path: Path) -> None:
    f = tmp_path / "auth.log"
    f.write_text("Oct 19 sshd broken entry\n", encoding="utf-8")
    assert parse_auth_log_with_report(f)["malformed_lines"] == [1]

def test_c12_four_fails_no_alert() -> None:
    start = datetime(2026, 11, 8, 12, 0, 0)
    assert detect_brute_force(_failed([start + timedelta(seconds=i * 10) for i in range(4)]), 2026) == []

def test_c12_five_fails_in_59_seconds() -> None:
    start = datetime(2026, 11, 8, 12, 0, 0)
    events = _failed([start + timedelta(seconds=i) for i in [0, 12, 24, 48, 59]])
    alert, = detect_brute_force(events, 2026)
    assert alert["attempt_count"] == 5
    assert alert["targeted_usernames"] == ["u0", "u1", "u2", "u3", "u4"]
    assert alert["first_timestamp"].endswith("+00:00")

def test_c12_five_fails_in_61_seconds_no_alert() -> None:
    start = datetime(2026, 11, 8, 12, 0, 0)
    events = _failed([start + timedelta(seconds=i) for i in [0, 15, 30, 45, 61]])
    assert detect_brute_force(events, 2026) == []

def test_c12_year_rollover_and_source_timezone() -> None:
    times = [datetime(2026, 12, 31, 23, 59, 58) + timedelta(seconds=i)
             for i in [0, 1, 2, 4, 5]]
    events = _failed(times)
    converted = timestamped_events(events, 2026, "Asia/Almaty")
    assert converted[0][1] == datetime(2026, 12, 31, 18, 59, 58, tzinfo=timezone.utc)
    assert converted[-1][1].year == 2026
    assert len(detect_brute_force(events, 2026, "Asia/Almaty")) == 1

def test_c13_exact_twelve_and_no_decoys(tmp_path: Path) -> None:
    result = extract_iocs_from_file(DATA / "threat_report.txt", tmp_path / "iocs.json")
    assert sum(map(len, result.values())) == 12
    assert result["ipv4"] == ["198.51.100.7", "203.0.113.45"]
    assert len(result["domains"]) == 3
    assert len(result["urls"]) == 2
    assert len(result["emails"]) == 2
    assert [len(result[k]) for k in ["md5", "sha1", "sha256"]] == [1, 1, 1]
    assert json.loads((tmp_path / "iocs.json").read_text()) == result
    assert "1.1.1" not in str(result)
    assert not extract_iocs("f" * 33)["md5"]

def test_c14_no_password_leak(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "audit.json"
    result = audit_passwords(DATA / "passwords.txt", DATA / "common_passwords.txt", target)
    assert len(result) == 5
    assert result[3]["broken_rules"] == []
    assert "common_password" in result[4]["broken_rules"]
    exposed = str(result) + target.read_text() + capsys.readouterr().out
    for pw in (DATA / "passwords.txt").read_text().splitlines():
        assert pw not in exposed

def test_c15_files_added_removed_modified(tmp_path: Path) -> None:
    folder = tmp_path / "folder"
    folder.mkdir()
    (folder / "removed.txt").write_text("before")
    (folder / "changed.txt").write_text("old")
    (folder / "unchanged.txt").write_text("same")
    baseline = folder / "baseline.json"
    saved = create_baseline(folder, baseline)
    assert len(saved["files"]) == 3
    (folder / "removed.txt").unlink()
    (folder / "changed.txt").write_text("new contents")
    (folder / "added.txt").write_text("addition")
    report = check_integrity(folder, baseline)
    assert report == {"added": ["added.txt"], "removed": ["removed.txt"],
                      "modified": ["changed.txt"], "unreadable": []}

def test_c15_unreadable_is_not_removed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import seclab.c1.integrity as integrity
    directory = tmp_path / "data"
    directory.mkdir()
    path = directory / "file.txt"
    path.write_text("initial")
    base = tmp_path / "baseline.json"
    create_baseline(directory, base)
    original = integrity._metadata

    def bad_one(p: Path):
        if p == path:
            raise PermissionError("blocked")
        return original(p)

    monkeypatch.setattr(integrity, "_metadata", bad_one)
    result = check_integrity(directory, base)
    assert result["unreadable"] == ["file.txt"]
    assert result["removed"] == []

def test_c16_sorted_statuses(tmp_path: Path) -> None:
    now = datetime(2026, 11, 8, tzinfo=timezone.utc)
    result = check_certificates(DATA / "tls_inventory.csv", tmp_path / "results.csv", now)
    assert [item["status"] for item in result] == ["expired", "critical", "warning", "ok"]
    assert [item["hostname"] for item in result] == [
        "expired.example", "critical.example", "warning.example", "ok.example"
    ]
    assert (tmp_path / "results.csv").exists()
    with pytest.raises(UnknownDateFormat):
        parse_not_after("2026/13/80")
