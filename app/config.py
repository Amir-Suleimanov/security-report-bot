from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class Settings:
    bot_token: str
    allowed_chat_ids: list[int]
    default_interval_sec: int
    poll_interval_sec: int
    state_db_path: Path
    report_title: str
    monitored_service_name: str
    monitored_service_label: str
    allowlist_path: Path

    @classmethod
    def load(cls) -> "Settings":
        bot_token = os.environ["TELEGRAM_BOT_TOKEN"].strip()
        allowed_raw = os.environ.get("ALLOWED_CHAT_IDS") or os.environ.get("TELEGRAM_CHAT_ID") or ""
        allowed_chat_ids = [int(item.strip()) for item in allowed_raw.split(",") if item.strip()]
        if not allowed_chat_ids:
            raise RuntimeError("ALLOWED_CHAT_IDS or TELEGRAM_CHAT_ID must be set")

        default_interval_sec = int(os.environ.get("DEFAULT_REPORT_INTERVAL_SEC", "10800"))
        poll_interval_sec = int(os.environ.get("SCHEDULER_POLL_INTERVAL_SEC", "30"))
        state_db_path = Path(os.environ.get("STATE_DB_PATH", "/var/lib/security-report-bot/state.db"))
        report_title = os.environ.get("REPORT_TITLE", "Отчёт безопасности сервера").strip() or "Отчёт безопасности сервера"
        monitored_service_name = os.environ.get("MONITORED_SERVICE_NAME", "").strip()
        monitored_service_label = os.environ.get("MONITORED_SERVICE_LABEL", "").strip() or monitored_service_name
        allowlist_path = Path(os.environ.get("ALLOWLIST_PATH", "/etc/security-report-bot/scan-whitelist.txt"))
        return cls(
            bot_token=bot_token,
            allowed_chat_ids=allowed_chat_ids,
            default_interval_sec=default_interval_sec,
            poll_interval_sec=poll_interval_sec,
            state_db_path=state_db_path,
            report_title=report_title,
            monitored_service_name=monitored_service_name,
            monitored_service_label=monitored_service_label,
            allowlist_path=allowlist_path,
        )
