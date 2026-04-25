from __future__ import annotations

import argparse
import ipaddress
import subprocess
from pathlib import Path

from app.config import Settings
from app.reporting import Reporter

JAILS = ("nginx-vulnscan", "nginx-botsearch")


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, text=True, capture_output=True)


def load_entries(path: Path) -> list[str]:
    if not path.exists():
        return []
    entries: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "/" in line:
            entries.append(str(ipaddress.ip_network(line, strict=False)))
        else:
            entries.append(str(ipaddress.ip_address(line)))
    return sorted(set(entries))


def render_ignoreip_config(entries: list[str]) -> str:
    ignoreip = " ".join(entries)
    return "\n".join(f"[{jail}]\nignoreip = {ignoreip}\n" for jail in JAILS)


def extract_banned_ips(jail: str) -> list[str]:
    status = run(["fail2ban-client", "status", jail]).stdout
    for line in status.splitlines():
        if "Banned IP list:" in line:
            return [item for item in line.split(":", 1)[1].strip().split() if item]
    return []


def is_allowed(ip: str, allowlist: Reporter.Allowlist) -> bool:
    return Reporter._is_allowlisted(ip, allowlist)


def cmd_sync(settings: Settings) -> int:
    loopback = ["127.0.0.0/8", "::1"]
    base_entries = load_entries(settings.fail2ban_ignore_base_path)
    allow_entries = load_entries(settings.allowlist_path)
    merged_entries = sorted(set(loopback + base_entries + allow_entries))
    config_text = render_ignoreip_config(merged_entries)
    output_path = settings.fail2ban_ignore_output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(config_text, encoding="utf-8")

    reporter = Reporter(settings)
    allowlist = reporter._load_allowlist(settings.allowlist_path)
    for jail in JAILS:
        run(["fail2ban-client", "reload", jail])
        for ip in extract_banned_ips(jail):
            if is_allowed(ip, allowlist):
                run(["fail2ban-client", "set", jail, "unbanip", ip])

    print(f"Synced allowlist from {settings.allowlist_path}")
    print(f"Base ignore entries: {len(base_entries)}")
    print(f"Allowlist entries: {len(allow_entries)}")
    print(f"Generated ignoreip entries: {len(merged_entries)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sync scan allowlist into fail2ban ignoreip config")
    parser.add_argument("command", choices=["sync"])
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    settings = Settings.load()
    if args.command == "sync":
        return cmd_sync(settings)
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
