from __future__ import annotations

import argparse
import ipaddress
import os
import subprocess
from pathlib import Path

COMMENT = "security-report-bot-manual-deny"


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, text=True, capture_output=True)


def normalize_entry(raw: str) -> str:
    value = raw.strip()
    if not value:
        raise ValueError("empty entry")
    if "/" in value:
        return str(ipaddress.ip_network(value, strict=False))
    return str(ipaddress.ip_address(value))


def load_entries(path: Path) -> list[str]:
    if not path.exists():
        return []
    entries: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        entries.append(normalize_entry(line))
    return sorted(set(entries))


def save_entries(path: Path, entries: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Manually confirmed malicious IPs or CIDR ranges.",
        "# This file is separate from automatic fail2ban bans.",
        "",
        *entries,
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def load_managed_ufw_entries() -> list[str]:
    output = run(["ufw", "show", "added"]).stdout.splitlines()
    prefix = "ufw reject from "
    suffix = f" comment '{COMMENT}'"
    entries: list[str] = []
    for raw_line in output:
        line = raw_line.strip()
        if not line.startswith(prefix) or not line.endswith(suffix):
            continue
        entries.append(line[len(prefix) : -len(suffix)])
    return sorted(set(entries))


def sync_ufw(entries: list[str]) -> tuple[list[str], list[str]]:
    existing = set(load_managed_ufw_entries())
    desired = set(entries)
    removed = sorted(existing - desired)
    added = sorted(desired - existing)

    for entry in removed:
        run(["ufw", "--force", "delete", "reject", "from", entry, "comment", COMMENT])
    for entry in added:
        run(["ufw", "--force", "reject", "from", entry, "comment", COMMENT])
    return added, removed


def load_manual_denylist_path() -> Path:
    return Path(os.environ.get("MANUAL_DENYLIST_PATH", "/etc/security-report-bot/manual-denylist.txt"))


def cmd_sync(path: Path) -> int:
    entries = load_entries(path)
    added, removed = sync_ufw(entries)
    print(f"Synced manual denylist from {path}")
    print(f"Desired entries: {len(entries)}")
    print(f"Added rules: {len(added)}")
    print(f"Removed rules: {len(removed)}")
    return 0


def cmd_add(path: Path, raw_entries: list[str]) -> int:
    existing = load_entries(path)
    merged = sorted(set(existing) | {normalize_entry(item) for item in raw_entries})
    save_entries(path, merged)
    added, removed = sync_ufw(merged)
    print(f"Saved {len(merged)} manual deny entries to {path}")
    print(f"Added rules: {len(added)}")
    print(f"Removed rules: {len(removed)}")
    return 0


def cmd_status(path: Path) -> int:
    file_entries = load_entries(path)
    ufw_entries = load_managed_ufw_entries()
    print(f"Manual denylist file: {path}")
    print(f"Entries in file: {len(file_entries)}")
    print(f"Managed UFW rules: {len(ufw_entries)}")
    if file_entries:
        print("Entries:")
        for entry in file_entries:
            print(entry)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage persistent manual denylist rules")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("sync")
    add_parser = subparsers.add_parser("add")
    add_parser.add_argument("entries", nargs="+")
    subparsers.add_parser("status")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    path = load_manual_denylist_path()

    if args.command == "sync":
        return cmd_sync(path)
    if args.command == "add":
        return cmd_add(path, args.entries)
    if args.command == "status":
        return cmd_status(path)

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
