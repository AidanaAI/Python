from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

HASH_PATTERN = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
URL_PATTERN = re.compile(r"\bhttps?://[A-Za-z0-9._~%!$&'()*+,;=:@/?#\[\]-]+", re.I)
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IP_PATTERN = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.])")
DOMAIN_PATTERN = re.compile(
    r"(?<![\w@.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}(?![\w.-])"
)

def refang(text: str) -> str:
    text = re.sub(r"hxxps://", "https://", text, flags=re.I)
    text = re.sub(r"hxxp://", "http://", text, flags=re.I)
    return text.replace("[.]", ".").replace("(.)", ".").replace("[@]", "@")

def _clear_spans(text: str, matches: list[re.Match[str]]) -> str:
    chars = list(text)
    for match in matches:
        chars[match.start():match.end()] = " " * (match.end() - match.start())
    return "".join(chars)

def extract_iocs(text: str) -> dict[str, list[str]]:
    cleaned = refang(text)
    hashes = HASH_PATTERN.findall(cleaned)
    no_hashes = _clear_spans(cleaned, list(HASH_PATTERN.finditer(cleaned)))
    urls = [m.group().rstrip(".,;:!?)\"'") for m in URL_PATTERN.finditer(no_hashes)]
    no_urls = _clear_spans(no_hashes, list(URL_PATTERN.finditer(no_hashes)))
    email_matches = list(EMAIL_PATTERN.finditer(no_urls))
    emails = [m.group() for m in email_matches]
    no_emails = _clear_spans(no_urls, email_matches)
    ips = []
    ip_matches = list(IP_PATTERN.finditer(no_emails))
    for match in ip_matches:
        candidate = match.group()
        try:
            ips.append(str(ipaddress.IPv4Address(candidate)))
        except ValueError:
            pass
    no_ips = _clear_spans(no_emails, ip_matches)
    domains = [m.group().lower() for m in DOMAIN_PATTERN.finditer(no_ips)]

    return {
        "ipv4": sorted(set(ips)),
        "domains": sorted(set(domains)),
        "urls": sorted(set(urls)),
        "emails": sorted(set(emails)),
        "md5": sorted({h.lower() for h in hashes if len(h) == 32}),
        "sha1": sorted({h.lower() for h in hashes if len(h) == 40}),
        "sha256": sorted({h.lower() for h in hashes if len(h) == 64}),
    }

def extract_iocs_from_file(report_path: str | Path, output_path: str | Path = "iocs.json") -> dict[str, list[str]]:
    results = extract_iocs(Path(report_path).read_text(encoding="utf-8"))
    Path(output_path).write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return results
