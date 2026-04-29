from __future__ import annotations

import sqlite3
import subprocess
from datetime import UTC, datetime, timedelta

from app.config import Settings
from app.manual_denylist import load_entries, normalize_entry, save_entries, sync_ufw
from app.nginx_logs import iter_log_lines
from app.reporting import Reporter, _LOG_RE
from app.signatures import SCANNER_UA_RE, SUSPICIOUS_PATH_RE, SUSPICIOUS_QUERY_RE, TRUSTED_UA_RE


def load_active_banned_ips() -> set[str]:
    output = subprocess.run(
        ["bash", "-lc", "fail2ban-client status nginx-vulnscan"],
        check=True,
        text=True,
        capture_output=True,
    ).stdout
    for line in output.splitlines():
        if "Banned IP list:" in line:
            return {item for item in line.split(":", 1)[1].strip().split() if item}
    return set()


def collect_recent_scanner_ips(settings: Settings) -> tuple[set[str], list[str]]:
    reporter = Reporter(settings)
    allowlist = reporter._load_allowlist(settings.allowlist_path)
    manual = reporter._load_allowlist(settings.manual_denylist_path)
    base = reporter._load_allowlist(settings.fail2ban_ignore_base_path)
    active_banned = load_active_banned_ips()
    threshold = datetime.now(UTC) - timedelta(seconds=settings.scanner_reconcile_window_sec)

    missed: set[str] = set()
    reasons: list[str] = []

    for raw_line in iter_log_lines():
        line = raw_line.rstrip("\n")
        match = _LOG_RE.match(line)
        if match is None:
            continue
        ts = datetime.strptime(match.group("ts"), "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC)
        if ts < threshold:
            continue
        ip = match.group("ip")
        method = match.group("method")
        path = match.group("path")
        ua = match.group("ua")
        if TRUSTED_UA_RE.search(ua):
            continue
        if not (
            SUSPICIOUS_PATH_RE.search(path)
            or SUSPICIOUS_QUERY_RE.search(path)
            or SCANNER_UA_RE.search(ua)
            or method == "PROPFIND"
        ):
            continue
        if reporter._is_allowlisted(ip, allowlist):
            continue
        if reporter._is_allowlisted(ip, manual):
            continue
        if reporter._is_allowlisted(ip, base) or ip in {"127.0.0.1", "::1"}:
            continue
        if ip in active_banned:
            continue
        if ip in missed:
            continue
        missed.add(ip)
        reasons.append(f"{ip} | {ts.strftime('%Y-%m-%d %H:%M:%S UTC')} | {method} {path}")

    return missed, reasons


def reconcile() -> int:
    settings = Settings.load()
    recent_ips, reasons = collect_recent_scanner_ips(settings)
    if not recent_ips:
        print("No missed scanner IPs found.")
        return 0

    existing = load_entries(settings.manual_denylist_path)
    merged = sorted(set(existing) | {normalize_entry(ip) for ip in recent_ips})
    save_entries(settings.manual_denylist_path, merged)
    added, removed = sync_ufw(merged)

    print(f"Added {len(recent_ips)} missed scanner IPs to manual denylist.")
    print(f"Manual denylist size: {len(merged)}")
    print(f"UFW rules added: {len(added)}")
    print(f"UFW rules removed: {len(removed)}")
    print("Entries:")
    for row in reasons:
        print(row)
    return 0


if __name__ == "__main__":
    raise SystemExit(reconcile())
