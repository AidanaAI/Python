from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CHUNK_SIZE = 64 * 1024

def _metadata(path: Path) -> dict[str, Any]:
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            sha.update(chunk)
        stat = path.stat()
    return {
        "sha256": sha.hexdigest(),
        "size": stat.st_size,
        "mtime_utc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
    }

def _scan(directory: Path, excluded: Path | None = None) -> tuple[dict[str, dict[str, Any]], list[str]]:
    directory = directory.resolve()
    excluded = excluded.resolve() if excluded is not None else None
    files: dict[str, dict[str, Any]] = {}
    unreadable: list[str] = []
    for root, dirs, filenames in os.walk(directory):
        dirs.sort()
        for filename in sorted(filenames):
            path = Path(root) / filename
            if excluded is not None and path.resolve() == excluded:
                continue
            relative = path.relative_to(directory).as_posix()
            try:
                files[relative] = _metadata(path)
            except (PermissionError, FileNotFoundError, IsADirectoryError, OSError):
                unreadable.append(relative)
    return files, unreadable

def create_baseline(directory: str | Path, baseline_path: str | Path = "baseline.json") -> dict[str, Any]:
    root = Path(directory)
    if not root.is_dir():
        raise NotADirectoryError(f"Directory not found: {root}")
    destination = Path(baseline_path).resolve()
    files, unreadable = _scan(root, destination)
    baseline: dict[str, Any] = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "files": files,
        "unreadable": unreadable,
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=destination.parent, prefix=".baseline-", suffix=".tmp", delete=False) as file:
            temporary = Path(file.name)
            json.dump(baseline, file, indent=2, ensure_ascii=False)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        temporary.replace(destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return baseline

def check_integrity(directory: str | Path, baseline_path: str | Path = "baseline.json") -> dict[str, list[str]]:
    baseline_file = Path(baseline_path).resolve()
    baseline = json.loads(baseline_file.read_text(encoding="utf-8"))
    previous: dict[str, dict[str, Any]] = baseline["files"]
    current, unreadable = _scan(Path(directory), baseline_file)
    previous_paths = set(previous)
    current_paths = set(current)
    unknown = set(unreadable)

    return {
        "added": sorted(current_paths - previous_paths),
        "removed": sorted(previous_paths - current_paths - unknown),
        "modified": sorted(path for path in current_paths & previous_paths
                           if current[path] != previous[path]),
        "unreadable": sorted(unreadable),
    }

def main() -> None:
    parser = argparse.ArgumentParser(description="C1.5 file integrity monitor")
    parser.add_argument("command", choices=["baseline", "check"])
    parser.add_argument("directory")
    parser.add_argument("--baseline", default="baseline.json")
    args = parser.parse_args()
    if args.command == "baseline":
        result = create_baseline(args.directory, args.baseline)
    else:
        result = check_integrity(args.directory, args.baseline)
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
