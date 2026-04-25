from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path


@dataclass(slots=True)
class BanEvent:
    jail: str
    ip: str
    timeofban: datetime
    bantime: int
    bancount: int


def load_ban_events_for_day(path: Path, jail: str, report_day: date) -> list[BanEvent]:
    if not path.exists():
        return []
    start = datetime.combine(report_day, time.min, tzinfo=UTC)
    end = start + timedelta(days=1)
    try:
        with sqlite3.connect(path) as conn:
            rows = conn.execute(
                """
                SELECT jail, ip, timeofban, bantime, bancount
                FROM bans
                WHERE jail = ? AND timeofban >= ? AND timeofban < ?
                ORDER BY timeofban ASC, ip ASC
                """,
                (jail, int(start.timestamp()), int(end.timestamp())),
            ).fetchall()
    except sqlite3.Error:
        return []
    return [
        BanEvent(
            jail=str(row[0]),
            ip=str(row[1]),
            timeofban=datetime.fromtimestamp(int(row[2]), tz=UTC),
            bantime=int(row[3]),
            bancount=int(row[4]),
        )
        for row in rows
    ]


def load_banned_ips_for_day(path: Path, jail: str, report_day: date) -> list[str]:
    return sorted({event.ip for event in load_ban_events_for_day(path, jail, report_day)})
