from __future__ import annotations

import argparse
import ipaddress
import os
import subprocess
from pathlib import Path


JAIL = "nginx-vulnscan"


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, text=True, capture_output=True)


def normalize_ip(raw: str) -> str:
    return str(ipaddress.ip_address(raw.strip()))


def load_entries(path: Path) -> list[str]:
    if not path.exists():
        return []
    entries: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        entries.append(normalize_ip(line))
    return sorted(set(entries))


def save_entries(path: Path, entries: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Persistent fail2ban web-ban snapshot.",
        "# These IPs are restored into nginx-vulnscan after reboot.",
        "",
        *entries,
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def load_allowlist(path: Path) -> tuple[set[str], list[ipaddress._BaseNetwork]]:
    if not path.exists():
        return set(), []
    exact: set[str] = set()
    networks: list[ipaddress._BaseNetwork] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "/" in line:
            networks.append(ipaddress.ip_network(line, strict=False))
        else:
            exact.add(str(ipaddress.ip_address(line)))
    return exact, networks


def is_allowlisted(ip: str, exact: set[str], networks: list[ipaddress._BaseNetwork]) -> bool:
    if ip in exact:
        return True
    parsed = ipaddress.ip_address(ip)
    return any(parsed in network for network in networks)


def load_settings() -> tuple[Path, Path, Path]:
    persistent = Path(
        os.environ.get("FAIL2BAN_PERSISTENT_PATH", "/etc/security-report-bot/fail2ban-persistent-bans.txt")
    )
    allowlist = Path(os.environ.get("ALLOWLIST_PATH", "/etc/security-report-bot/scan-whitelist.txt"))
    ignore_base = Path(os.environ.get("FAIL2BAN_IGNORE_BASE_PATH", "/etc/security-report-bot/fail2ban-ignore-base.txt"))
    return persistent, allowlist, ignore_base


def get_live_banned_ips() -> list[str]:
    output = run(["fail2ban-client", "status", JAIL]).stdout
    marker = "Banned IP list:"
    for line in output.splitlines():
        if marker not in line:
            continue
        values = line.split(marker, 1)[1].strip()
        if not values:
            return []
        return sorted({normalize_ip(item) for item in values.split() if item.strip()})
    return []


def get_effective_allowlist() -> tuple[set[str], list[ipaddress._BaseNetwork]]:
    persistent, allowlist_path, ignore_base_path = load_settings()
    del persistent
    allow_exact, allow_networks = load_allowlist(allowlist_path)
    ignore_exact, ignore_networks = load_allowlist(ignore_base_path)
    return allow_exact | ignore_exact, allow_networks + ignore_networks


def cmd_snapshot(path: Path) -> int:
    allow_exact, allow_networks = get_effective_allowlist()
    live_entries = [
        ip for ip in get_live_banned_ips() if not is_allowlisted(ip, allow_exact, allow_networks)
    ]
    save_entries(path, live_entries)
    print(f"Saved {len(live_entries)} active {JAIL} bans to {path}")
    return 0


def cmd_restore(path: Path) -> int:
    desired = load_entries(path)
    allow_exact, allow_networks = get_effective_allowlist()
    desired = [ip for ip in desired if not is_allowlisted(ip, allow_exact, allow_networks)]
    current = set(get_live_banned_ips())
    missing = [ip for ip in desired if ip not in current]

    restored = 0
    failed: list[tuple[str, str]] = []
    for ip in missing:
        try:
            run(["fail2ban-client", "set", JAIL, "banip", ip])
            restored += 1
        except subprocess.CalledProcessError as exc:
            failed.append((ip, (exc.stderr or exc.stdout or "").strip()))

    print(f"Persistent snapshot file: {path}")
    print(f"Desired restored bans: {len(desired)}")
    print(f"Already active: {len(desired) - len(missing)}")
    print(f"Restored now: {restored}")
    print(f"Failed restores: {len(failed)}")
    for ip, reason in failed:
        print(f"{ip} :: {reason}")
    return 0 if not failed else 1


def cmd_status(path: Path) -> int:
    desired = load_entries(path)
    current = set(get_live_banned_ips())
    missing = [ip for ip in desired if ip not in current]
    print(f"Persistent snapshot file: {path}")
    print(f"Snapshot entries: {len(desired)}")
    print(f"Live {JAIL} bans: {len(current)}")
    print(f"Missing from live: {len(missing)}")
    if missing:
        print("Missing entries:")
        for ip in missing:
            print(ip)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Persist and restore fail2ban web bans across reboot")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("snapshot")
    subparsers.add_parser("restore")
    subparsers.add_parser("status")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    path, _, _ = load_settings()
    if args.command == "snapshot":
        return cmd_snapshot(path)
    if args.command == "restore":
        return cmd_restore(path)
    if args.command == "status":
        return cmd_status(path)
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
