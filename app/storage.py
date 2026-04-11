from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path


@dataclass(slots=True)
class Subscription:
    chat_id: int
    enabled: bool
    interval_sec: int
    last_sent_at: datetime | None


class Storage:
    def __init__(self, path: Path) -> None:
        self.path = path

    def init(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS subscriptions (
                    chat_id INTEGER PRIMARY KEY,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    interval_sec INTEGER NOT NULL,
                    last_sent_at TEXT
                )
                """
            )
            conn.commit()

    def ensure_subscription(self, chat_id: int, interval_sec: int) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                """
                INSERT INTO subscriptions (chat_id, enabled, interval_sec, last_sent_at)
                VALUES (?, 1, ?, NULL)
                ON CONFLICT(chat_id) DO NOTHING
                """,
                (chat_id, interval_sec),
            )
            conn.commit()

    def get_subscription(self, chat_id: int) -> Subscription | None:
        with sqlite3.connect(self.path) as conn:
            row = conn.execute(
                "SELECT chat_id, enabled, interval_sec, last_sent_at FROM subscriptions WHERE chat_id = ?",
                (chat_id,),
            ).fetchone()
        if row is None:
            return None
        return Subscription(
            chat_id=int(row[0]),
            enabled=bool(row[1]),
            interval_sec=int(row[2]),
            last_sent_at=datetime.fromisoformat(row[3]).replace(tzinfo=UTC) if row[3] else None,
        )

    def set_interval(self, chat_id: int, interval_sec: int) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                """
                INSERT INTO subscriptions (chat_id, enabled, interval_sec, last_sent_at)
                VALUES (?, 1, ?, NULL)
                ON CONFLICT(chat_id) DO UPDATE SET enabled = 1, interval_sec = excluded.interval_sec
                """,
                (chat_id, interval_sec),
            )
            conn.commit()

    def disable(self, chat_id: int) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                """
                INSERT INTO subscriptions (chat_id, enabled, interval_sec, last_sent_at)
                VALUES (?, 0, 10800, NULL)
                ON CONFLICT(chat_id) DO UPDATE SET enabled = 0
                """,
                (chat_id,),
            )
            conn.commit()

    def touch_sent(self, chat_id: int, sent_at: datetime) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "UPDATE subscriptions SET last_sent_at = ? WHERE chat_id = ?",
                (sent_at.astimezone(UTC).replace(tzinfo=None).isoformat(sep=" "), chat_id),
            )
            conn.commit()

    def due_subscriptions(self, now: datetime) -> list[Subscription]:
        with sqlite3.connect(self.path) as conn:
            rows = conn.execute(
                "SELECT chat_id, enabled, interval_sec, last_sent_at FROM subscriptions WHERE enabled = 1"
            ).fetchall()

        due: list[Subscription] = []
        for row in rows:
            sub = Subscription(
                chat_id=int(row[0]),
                enabled=bool(row[1]),
                interval_sec=int(row[2]),
                last_sent_at=datetime.fromisoformat(row[3]).replace(tzinfo=UTC) if row[3] else None,
            )
            if sub.last_sent_at is None or sub.last_sent_at + timedelta(seconds=sub.interval_sec) <= now:
                due.append(sub)
        return due
