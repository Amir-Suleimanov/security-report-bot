from __future__ import annotations

import asyncio
import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from html import escape

from app.config import Settings
from app.nginx_logs import iter_log_lines
from app.signatures import (
    SCANNER_UA_RE as _SCANNER_UA_RE,
    SUSPICIOUS_PATH_RE as _SUSPICIOUS_PATH_RE,
    SUSPICIOUS_QUERY_RE as _SUSPICIOUS_QUERY_RE,
    TRUSTED_UA_RE as _TRUSTED_UA_RE,
)


_LOG_RE = re.compile(
    r'^(?P<ip>\S+) - \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) '
    r'(?P<bytes>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)
_INTERVAL_RE = re.compile(r"^\s*(\d+)\s*([mhd])\s*$", re.IGNORECASE)
_CLOSING_STATES = {"FIN-WAIT-1", "FIN-WAIT-2", "TIME-WAIT", "CLOSE-WAIT", "LAST-ACK", "CLOSING"}
@dataclass(slots=True)
class SuspiciousRequest:
    ip: str
    method: str
    path: str
    count: int
    last_seen: datetime
    banned: bool
    whitelisted: bool
    user_agent: str


@dataclass(slots=True)
class HttpConnection:
    state: str
    peer_ip: str
    peer_port: str


@dataclass(slots=True)
class ReportSnapshot:
    hostname: str
    now: datetime
    window_sec: int
    nginx_state: str
    fail2ban_state: str
    monitored_service_state: str
    banned_ips: list[str]
    banned_today: list[str]
    suspicious: list[SuspiciousRequest]
    connections: list[HttpConnection]


@dataclass(slots=True)
class Allowlist:
    exact_ips: set[str]
    networks: list[ipaddress._BaseNetwork]
    entries: list[str]


class Reporter:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def collect_snapshot(self, window_sec: int) -> ReportSnapshot:
        now = datetime.now(UTC)
        hostname = await self._run("hostname")
        nginx_state = await self._run("systemctl is-active nginx")
        fail2ban_state = await self._run("systemctl is-active fail2ban")
        monitored_service_state = (
            await self._run(f"systemctl is-active {self.settings.monitored_service_name}")
            if self.settings.monitored_service_name
            else "disabled"
        )
        nginx_vulnscan = await self._run("fail2ban-client status nginx-vulnscan")
        active_http = await self._run("ss -Htn '( sport = :80 or sport = :443 )'")

        fail2ban_banned_ips = self._extract_ban_list(nginx_vulnscan)
        allowlist = self._load_allowlist(self.settings.allowlist_path)
        manual_denylist = self._load_allowlist(self.settings.manual_denylist_path)
        blocked_entries = sorted(set(fail2ban_banned_ips) | set(manual_denylist.entries))
        suspicious, banned_today = self._analyze_logs(
            now=now,
            window_sec=window_sec,
            banned_ips=set(fail2ban_banned_ips),
            allowlist=allowlist,
            manual_denylist=manual_denylist,
            today=now.date(),
        )
        connections = self._parse_connections(active_http)

        return ReportSnapshot(
            hostname=hostname.strip() or "unknown",
            now=now,
            window_sec=window_sec,
            nginx_state=nginx_state.strip() or "unknown",
            fail2ban_state=fail2ban_state.strip() or "unknown",
            monitored_service_state=monitored_service_state.strip() or "unknown",
            banned_ips=blocked_entries,
            banned_today=banned_today,
            suspicious=suspicious,
            connections=connections,
        )

    async def build_report(self, window_sec: int) -> str:
        return self.format_report(await self.collect_snapshot(window_sec))

    def format_report(self, snapshot: ReportSnapshot) -> str:
        lines = [
            f"<b>{escape(self.settings.report_title)}</b>",
            f"Сервер: <code>{escape(snapshot.hostname)}</code>",
            f"Время: <code>{snapshot.now.strftime('%Y-%m-%d %H:%M:%S UTC')}</code>",
            f"Окно: последние <code>{self.format_interval(snapshot.window_sec)}</code>",
            "",
            f"• Сервисы: {self._format_services(snapshot)}",
            f"• Сейчас в бане: <b>{len(snapshot.banned_ips)}</b>",
            f"• Новых банов за сегодня: <b>{len(snapshot.banned_today)}</b>",
            f"• Подозрительных событий: <b>{len(snapshot.suspicious)}</b>",
            f"• HTTP(S)-подключения: <b>{self._format_connections_brief(snapshot.connections)}</b>",
        ]
        return "\n".join(lines)

    def format_banned_today(self, snapshot: ReportSnapshot) -> str:
        if not snapshot.banned_today:
            return "<b>Новые баны за сегодня</b>\nСегодня новых банов нет."
        body = "\n".join(snapshot.banned_today)
        return (
            f"<b>Новые баны за сегодня: {len(snapshot.banned_today)}</b>\n"
            f"<blockquote expandable><code>{escape(body)}</code></blockquote>"
        )

    def format_banned_ips(self, snapshot: ReportSnapshot) -> str:
        if not snapshot.banned_ips:
            return "<b>Блокировки</b>\nСейчас пусто."
        body = "\n".join(snapshot.banned_ips)
        return (
            f"<b>Блокировки сейчас: {len(snapshot.banned_ips)}</b>\n"
            f"<blockquote expandable><code>{escape(body)}</code></blockquote>"
        )

    def format_suspicious_ips(self, snapshot: ReportSnapshot) -> str:
        if not snapshot.suspicious:
            return "<b>Подозрительные IP</b>\nЗа текущее окно подозрительных событий нет."
        rows = [
            f"{item.ip} | {item.method} {item.path} | {item.last_seen.strftime('%H:%M:%S UTC')} | "
            f"{'в белом списке' if item.whitelisted else ('в бане' if item.banned else 'не в бане')}"
            for item in snapshot.suspicious
        ]
        body = "\n".join(rows)
        return (
            f"<b>Подозрительные IP: {len(snapshot.suspicious)}</b>\n"
            f"<blockquote expandable><code>{escape(body)}</code></blockquote>"
        )

    def format_connections(self, snapshot: ReportSnapshot) -> str:
        if not snapshot.connections:
            return "<b>HTTP(S)-подключения</b>\nСейчас активных TCP-подключений к 80/443 нет."
        rows = [
            f"{conn.state} | {conn.peer_ip}:{conn.peer_port} | {self._describe_connection(conn)}"
            for conn in snapshot.connections
        ]
        body = "\n".join(rows)
        return (
            f"<b>HTTP(S)-подключения сейчас: {len(snapshot.connections)}</b>\n"
            f"<blockquote expandable><code>{escape(body)}</code></blockquote>"
        )

    async def _run(self, command: str) -> str:
        process = await asyncio.create_subprocess_exec(
            "bash",
            "-lc",
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await process.communicate()
        return stdout.decode("utf-8", errors="replace").strip()

    def _analyze_logs(
        self,
        now: datetime,
        window_sec: int,
        banned_ips: set[str],
        allowlist: Allowlist,
        manual_denylist: Allowlist,
        today: object,
    ) -> tuple[list[SuspiciousRequest], list[str]]:
        threshold = now - timedelta(seconds=window_sec)
        items: dict[tuple[str, str, str], SuspiciousRequest] = {}
        first_seen: dict[str, datetime] = {}

        for line in iter_log_lines():
            match = _LOG_RE.match(line)
            if match is None:
                continue
            ts = datetime.strptime(match.group("ts"), "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC)
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
            ip = match.group("ip")
            is_manually_denied = self._is_allowlisted(ip, manual_denylist)
            if (ip in banned_ips or is_manually_denied) and not self._is_allowlisted(ip, allowlist):
                if ip not in first_seen or ts < first_seen[ip]:
                    first_seen[ip] = ts
            if ts < threshold:
                continue
            key = (ip, method, path)
            if key not in items:
                items[key] = SuspiciousRequest(
                    ip=ip,
                    method=method,
                    path=path,
                    count=1,
                    last_seen=ts,
                    banned=ip in banned_ips or is_manually_denied,
                    whitelisted=self._is_allowlisted(ip, allowlist),
                    user_agent=user_agent,
                )
                continue
            item = items[key]
            item.count += 1
            if ts > item.last_seen:
                item.last_seen = ts
            item.banned = item.banned or ip in banned_ips or is_manually_denied
            item.whitelisted = item.whitelisted or self._is_allowlisted(ip, allowlist)
            if not item.user_agent and user_agent:
                item.user_agent = user_agent

        suspicious = sorted(
            items.values(),
            key=lambda item: (-item.count, item.banned, item.last_seen, item.ip, item.path),
        )[:10]
        banned_today = sorted(ip for ip, ts in first_seen.items() if ts.date() == today)
        return suspicious, banned_today

    @staticmethod
    def _parse_connections(text: str) -> list[HttpConnection]:
        connections: list[HttpConnection] = []
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            state = parts[0]
            peer = parts[4]
            if ":" not in peer:
                continue
            peer_ip, peer_port = peer.rsplit(":", 1)
            connections.append(HttpConnection(state=state, peer_ip=peer_ip, peer_port=peer_port))
        return connections

    @staticmethod
    def _load_allowlist(path) -> Allowlist:
        if not path.exists():
            return Allowlist(exact_ips=set(), networks=[], entries=[])
        exact_ips: set[str] = set()
        networks: list[ipaddress._BaseNetwork] = []
        entries: list[str] = []
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "/" in line:
                try:
                    network = ipaddress.ip_network(line, strict=False)
                    networks.append(network)
                    entries.append(str(network))
                    continue
                except ValueError:
                    pass
            exact_ips.add(line)
            entries.append(line)
        return Allowlist(exact_ips=exact_ips, networks=networks, entries=entries)

    @staticmethod
    def _is_allowlisted(ip: str, allowlist: Allowlist) -> bool:
        if ip in allowlist.exact_ips:
            return True
        try:
            parsed_ip = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(parsed_ip in network for network in allowlist.networks)

    @staticmethod
    def _extract_ban_list(text: str) -> list[str]:
        for line in text.splitlines():
            if "Banned IP list:" in line:
                _, value = line.split(":", 1)
                return [item for item in value.strip().split() if item]
        return []

    def _build_details(self, snapshot: ReportSnapshot) -> str:
        lines: list[str] = []
        if snapshot.suspicious:
            top = snapshot.suspicious[0]
            lines.append("Что важно:")
            lines.append(
                f"Подозрительный запрос: {top.method} {top.path} в {top.last_seen.strftime('%H:%M:%S UTC')}."
            )
            lines.append(f"Статус: {'IP уже в бане.' if top.banned else 'IP пока не в бане.'}")
            lines.append(f"Оценка: {self._describe_suspicious(top)}")
            if len(snapshot.suspicious) > 1:
                lines.append(f"Дополнительно: ещё {len(snapshot.suspicious) - 1} событие(й), детали в кнопках ниже.")
        else:
            lines.append("Что важно:")
            lines.append("За текущее окно явных exploit-проб не было.")

        lines.append("")
        lines.append("Подключения:")
        lines.append(self._describe_connections_summary(snapshot.connections))
        return "\n".join(lines)

    def _format_services(self, snapshot: ReportSnapshot) -> str:
        states = {
            "nginx": snapshot.nginx_state,
            "fail2ban": snapshot.fail2ban_state,
        }
        if self.settings.monitored_service_label:
            states[self.settings.monitored_service_label] = snapshot.monitored_service_state
        bad = [name for name, state in states.items() if state != "active"]
        if not bad:
            if self.settings.monitored_service_label:
                return f"nginx, fail2ban и {self.settings.monitored_service_label} активны"
            return "nginx и fail2ban активны"
        return ", ".join(f"{name}: {states[name]}" for name in states)

    @staticmethod
    def _format_connections_brief(connections: list[HttpConnection]) -> str:
        if not connections:
            return "нет активных"
        estab = sum(1 for item in connections if item.state == "ESTAB")
        closing = sum(1 for item in connections if item.state in _CLOSING_STATES)
        other = len(connections) - estab - closing
        parts: list[str] = []
        if estab:
            parts.append(f"{estab} установлено")
        if closing:
            parts.append(f"{closing} закрываются")
        if other:
            parts.append(f"{other} прочих")
        return ", ".join(parts)

    def _describe_connections_summary(self, connections: list[HttpConnection]) -> str:
        if not connections:
            return "Сейчас активных TCP-подключений к 80/443 нет."

        estab = [item for item in connections if item.state == "ESTAB"]
        closing = [item for item in connections if item.state in _CLOSING_STATES]
        parts: list[str] = []
        if estab:
            parts.append(f"Есть {len(estab)} установленное соединение(я): это обычно обычный визит пользователя или загрузка статики.")
        if closing:
            parts.append(f"Есть {len(closing)} соединение(я) в стадии закрытия: это след завершившихся HTTPS-сеансов, не отдельная атака.")
        other = len(connections) - len(estab) - len(closing)
        if other:
            parts.append(f"Есть {other} соединение(я) в прочих состояниях TCP.")
        return " ".join(parts)

    @staticmethod
    def _describe_suspicious(item: SuspiciousRequest) -> str:
        if item.method == "PROPFIND":
            return "Это типичная WebDAV-проба. Для обычного сайта такой метод обычно не нужен, часто так ходят автоматические сканеры."
        if "wp-admin/setup-config.php" in item.path:
            return "Это попытка найти WordPress installer. Если WordPress не используется, это признак массового сканирования."
        if "wp-config" in item.path:
            return "Это probe на WordPress-конфиг. Если WordPress не используется, это типичный запрос автоматического сканера."
        if "xmlrpc.php" in item.path or "wp-login.php" in item.path:
            return "Это типичная проверка WordPress-эндпоинтов ботом."
        if "actuator" in item.path:
            return "Это поиск Spring Boot actuator-эндпоинтов."
        if "GponForm/diag_Form" in item.path:
            return "Это известная массовая проверка GPON-роутеров."
        return "Это похоже на автоматический probe по известному уязвимому пути."

    @staticmethod
    def _describe_connection(conn: HttpConnection) -> str:
        if conn.state == "ESTAB":
            return "соединение открыто"
        if conn.state in _CLOSING_STATES:
            return "соединение закрывается"
        return "нестандартное состояние TCP"

    @staticmethod
    def parse_interval(text: str) -> int | None:
        value = (text or "").strip().lower()
        if value in {"off", "disable", "disabled", "выкл", "выключить"}:
            return None
        match = _INTERVAL_RE.fullmatch(value)
        if match is None:
            raise ValueError("Используйте формат 30m, 3h, 1d или off")
        amount = int(match.group(1))
        if amount <= 0:
            raise ValueError("Интервал должен быть положительным")
        unit = match.group(2).lower()
        return amount * {"m": 60, "h": 3600, "d": 86400}[unit]

    @staticmethod
    def format_interval(seconds: int) -> str:
        if seconds % 86400 == 0:
            return f"{seconds // 86400}d"
        if seconds % 3600 == 0:
            return f"{seconds // 3600}h"
        if seconds % 60 == 0:
            return f"{seconds // 60}m"
        return f"{seconds}s"
