from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ChatType, ParseMode
from aiogram.filters.callback_data import CallbackData
from aiogram.filters import Command
from aiogram.types import (
    BotCommand,
    BotCommandScopeAllChatAdministrators,
    BotCommandScopeAllGroupChats,
    BotCommandScopeAllPrivateChats,
    BotCommandScopeChat,
    BotCommandScopeDefault,
    CallbackQuery,
    InlineKeyboardMarkup,
    Message,
)
from aiogram.utils.keyboard import InlineKeyboardBuilder

from app.config import Settings
from app.reporting import ReportSnapshot, Reporter
from app.storage import Storage


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
router = Router(name="security-bot")
BOT_COMMANDS = [
    BotCommand(command="report", description="отчёт сейчас"),
    BotCommand(command="status", description="текущая настройка"),
    BotCommand(command="interval", description="сменить интервал"),
    BotCommand(command="off", description="выключить периодические отчёты"),
]


class ReportAction(CallbackData, prefix="report"):
    action: str


def build_report_keyboard(snapshot: ReportSnapshot) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(
        text=f"Новые за день ({len(snapshot.banned_today)})",
        callback_data=ReportAction(action="banned_today").pack(),
    )
    builder.button(text=f"Весь список ({len(snapshot.banned_ips)})", callback_data=ReportAction(action="banned").pack())
    builder.button(
        text=f"Подозрительные IP ({len(snapshot.suspicious)})",
        callback_data=ReportAction(action="suspicious").pack(),
    )
    builder.button(text="Подключения", callback_data=ReportAction(action="connections").pack())
    builder.adjust(2, 1)
    return builder.as_markup()


class SecurityBotApp:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.storage = Storage(settings.state_db_path)
        self.reporter = Reporter(settings)
        self.bot = Bot(
            settings.bot_token,
            default=DefaultBotProperties(parse_mode=ParseMode.HTML),
        )
        self.dp = Dispatcher()
        self.dp.include_router(router)
        self.stop_event = asyncio.Event()
        self.scheduler_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        self.storage.init()
        for chat_id in self.settings.allowed_chat_ids:
            self.storage.ensure_subscription(chat_id, self.settings.default_interval_sec)

        self.dp["settings"] = self.settings
        self.dp["storage"] = self.storage
        self.dp["reporter"] = self.reporter
        self.dp.startup.register(self.on_startup)
        self.dp.shutdown.register(self.on_shutdown)
        await self.dp.start_polling(self.bot)

    async def on_startup(self, *_: object, **__: object) -> None:
        default_scope = BotCommandScopeDefault()
        private_scope = BotCommandScopeAllPrivateChats()
        group_scope = BotCommandScopeAllGroupChats()
        admins_scope = BotCommandScopeAllChatAdministrators()

        for scope in (default_scope, private_scope, group_scope, admins_scope):
            await self.bot.delete_my_commands(scope=scope)
        for chat_id in self.settings.allowed_chat_ids:
            await self.bot.set_my_commands(BOT_COMMANDS, scope=BotCommandScopeChat(chat_id=chat_id))
        await self.bot.delete_webhook(drop_pending_updates=False)
        self.scheduler_task = asyncio.create_task(self.scheduler_loop(), name="security-scheduler")

    async def on_shutdown(self, *_: object, **__: object) -> None:
        self.stop_event.set()
        if self.scheduler_task is not None:
            self.scheduler_task.cancel()
            try:
                await self.scheduler_task
            except asyncio.CancelledError:
                pass

    async def scheduler_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                now = datetime.now(UTC)
                for sub in self.storage.due_subscriptions(now):
                    snapshot = await self.reporter.collect_snapshot(sub.interval_sec)
                    await self.bot.send_message(
                        sub.chat_id,
                        self.reporter.format_report(snapshot),
                        reply_markup=build_report_keyboard(snapshot),
                    )
                    self.storage.touch_sent(sub.chat_id, now)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Scheduler tick failed")
            try:
                await asyncio.wait_for(self.stop_event.wait(), timeout=self.settings.poll_interval_sec)
            except asyncio.TimeoutError:
                continue


def is_allowed(message: Message, settings: Settings) -> bool:
    user = message.from_user
    return (
        user is not None
        and message.chat.type == ChatType.PRIVATE
        and message.chat.id == user.id
        and message.chat.id in settings.allowed_chat_ids
    )


@router.message(Command("start"))
async def cmd_start(message: Message, settings: Settings, storage: Storage) -> None:
    if not is_allowed(message, settings):
        return
    storage.ensure_subscription(message.chat.id, settings.default_interval_sec)
    await message.answer(
        "Security Report Bot\n"
        "/report - отчёт сейчас\n"
        "/status - текущая настройка\n"
        "/interval 3h - сменить интервал\n"
        "/off - выключить периодические отчёты"
    )


@router.message(Command("report"))
async def cmd_report(message: Message, settings: Settings, storage: Storage, reporter: Reporter) -> None:
    if not is_allowed(message, settings):
        return
    sub = storage.get_subscription(message.chat.id)
    interval_sec = sub.interval_sec if sub else settings.default_interval_sec
    snapshot = await reporter.collect_snapshot(interval_sec)
    await message.answer(reporter.format_report(snapshot), reply_markup=build_report_keyboard(snapshot))


@router.message(Command("status"))
async def cmd_status(message: Message, settings: Settings, storage: Storage, reporter: Reporter) -> None:
    if not is_allowed(message, settings):
        return
    sub = storage.get_subscription(message.chat.id)
    if sub is None:
        storage.ensure_subscription(message.chat.id, settings.default_interval_sec)
        sub = storage.get_subscription(message.chat.id)
    assert sub is not None
    status = "включены" if sub.enabled else "выключены"
    interval = reporter.format_interval(sub.interval_sec)
    await message.answer(
        f"Периодические отчёты {status}.\n"
        f"Интервал: {interval}\n"
        f"Последняя отправка: {sub.last_sent_at.isoformat(sep=' ') if sub.last_sent_at else 'ещё не было'}"
    )


@router.message(Command("interval"))
async def cmd_interval(message: Message, settings: Settings, storage: Storage, reporter: Reporter) -> None:
    if not is_allowed(message, settings):
        return
    parts = (message.text or "").split(maxsplit=1)
    if len(parts) < 2:
        await message.answer("Используйте: /interval 3h")
        return
    value = parts[1].strip()
    try:
        interval = reporter.parse_interval(value)
    except ValueError as exc:
        await message.answer(str(exc))
        return
    if interval is None:
        storage.disable(message.chat.id, settings.default_interval_sec)
        await message.answer("Периодические отчёты выключены.")
        return
    storage.set_interval(message.chat.id, interval, datetime.now(UTC))
    await message.answer(f"Интервал обновлён: {reporter.format_interval(interval)}")


@router.message(Command("off"))
async def cmd_off(message: Message, settings: Settings, storage: Storage) -> None:
    if not is_allowed(message, settings):
        return
    storage.disable(message.chat.id, settings.default_interval_sec)
    await message.answer("Периодические отчёты выключены.")


@router.callback_query(ReportAction.filter())
async def on_report_action(
    callback: CallbackQuery,
    callback_data: ReportAction,
    settings: Settings,
    storage: Storage,
    reporter: Reporter,
) -> None:
    message = callback.message
    if message is None:
        await callback.answer()
        return
    user = callback.from_user
    if (
        user is None
        or message.chat.type != ChatType.PRIVATE
        or message.chat.id != user.id
        or message.chat.id not in settings.allowed_chat_ids
    ):
        await callback.answer()
        return

    sub = storage.get_subscription(message.chat.id)
    interval_sec = sub.interval_sec if sub else settings.default_interval_sec
    snapshot = await reporter.collect_snapshot(interval_sec)

    if callback_data.action == "banned_today":
        text = reporter.format_banned_today(snapshot)
        notice = "Новые баны за сегодня."
    elif callback_data.action == "banned":
        text = reporter.format_banned_ips(snapshot)
        notice = "Список IP в бане."
    elif callback_data.action == "suspicious":
        text = reporter.format_suspicious_ips(snapshot)
        notice = "Подозрительные IP за текущее окно."
    else:
        text = reporter.format_connections(snapshot)
        notice = "Текущие HTTPS-подключения."

    await callback.answer(notice)
    await message.answer(text)


@router.message(F.text)
async def fallback(message: Message, settings: Settings) -> None:
    if not is_allowed(message, settings):
        return
    await message.answer("Команды: /report, /status, /interval 3h, /off")


async def main() -> None:
    settings = Settings.load()
    app = SecurityBotApp(settings)
    await app.start()


if __name__ == "__main__":
    asyncio.run(main())
