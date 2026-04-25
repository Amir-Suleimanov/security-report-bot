from __future__ import annotations

import asyncio
import html
import subprocess
from collections import defaultdict
from datetime import UTC, datetime, timedelta

from aiogram import Bot

from app.config import Settings
from app.nginx_logs import iter_log_lines
from app.reporting import _LOG_RE, Reporter
from app.signatures import (
    SCANNER_UA_RE as _SCANNER_UA_RE,
    SUSPICIOUS_PATH_RE as _SUSPICIOUS_PATH_RE,
    SUSPICIOUS_QUERY_RE as _SUSPICIOUS_QUERY_RE,
    TRUSTED_UA_RE as _TRUSTED_UA_RE,
)


def run(command: str) -> str:
    proc = subprocess.run(["bash", "-lc", command], check=True, capture_output=True, text=True)
    return proc.stdout.strip()


def parse_banned_ips() -> list[str]:
    status = run("fail2ban-client status nginx-vulnscan")
    for line in status.splitlines():
        if "Banned IP list:" in line:
            return [item for item in line.split(":", 1)[1].strip().split() if item]
    return []
def build_daily_digest(report_day: datetime.date, banned_ips: set[str]) -> tuple[int, str]:
    first_seen: dict[str, datetime] = {}
    daily_paths: dict[str, list[str]] = defaultdict(list)

    for line in iter_log_lines():
        match = _LOG_RE.match(line.rstrip("\n"))
        if match is None:
            continue
        ip = match.group("ip")
        if ip not in banned_ips:
            continue

        path = match.group("path")
        method = match.group("method")
        user_agent = match.group("ua")
        if _TRUSTED_UA_RE.search(user_agent):
            continue
        if not (
            _SUSPICIOUS_PATH_RE.search(path)
            or _SUSPICIOUS_QUERY_RE.search(path)
            or _SCANNER_UA_RE.search(user_agent)
            or method == "PROPFIND"
        ):
            continue

        ts = datetime.strptime(match.group("ts"), "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC)
        if ip not in first_seen or ts < first_seen[ip]:
            first_seen[ip] = ts
        if ts.date() == report_day:
            entry = f"{method} {path}"
            if entry not in daily_paths[ip]:
                daily_paths[ip].append(entry)

    new_ips = sorted(ip for ip, seen in first_seen.items() if seen.date() == report_day and daily_paths.get(ip))
    if not new_ips:
        return 0, (
            "<b>Новые баны за день</b>\n"
            f"Дата: <code>{report_day.isoformat()}</code>\n"
            "Новых IP за этот день нет."
        )

    rows: list[str] = []
    for ip in new_ips:
        rows.append(ip)
        for path in daily_paths[ip]:
            rows.append(f"  - {path}")
        rows.append("")

    body = html.escape("\n".join(rows).rstrip())
    return len(new_ips), (
        "<b>Новые баны за день</b>\n"
        f"Дата: <code>{report_day.isoformat()}</code>\n"
        f"• Новых IP: <b>{len(new_ips)}</b>\n"
        "<blockquote expandable>"
        f"{body}"
        "</blockquote>"
    )


async def send_summary(settings: Settings, message: str) -> None:
    bot = Bot(settings.bot_token)
    try:
        for chat_id in settings.allowed_chat_ids:
            await bot.send_message(chat_id, message)
    finally:
        await bot.session.close()


async def main() -> None:
    settings = Settings.load()
    now = datetime.now(UTC)
    report_day = (now - timedelta(days=1)).date() if now.hour < 2 else now.date()
    reporter = Reporter(settings)
    manual_denylist = reporter._load_allowlist(settings.manual_denylist_path)
    banned_ips = set(parse_banned_ips()) | set(manual_denylist.entries)
    _, message = build_daily_digest(report_day, banned_ips)
    await send_summary(settings, message)


if __name__ == "__main__":
    asyncio.run(main())
