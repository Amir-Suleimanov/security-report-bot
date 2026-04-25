# security-report-bot

Отдельный aiogram 3 Telegram-бот для security-отчётов по серверу с `nginx` и `fail2ban`.

Для короткой пошаговой инструкции без лишнего контекста используйте [INSTALL.md](INSTALL.md).

Проект рассчитан на установку на сам целевой сервер. Он:
- отправляет security-отчёт по команде и по расписанию
- показывает текущие баны, новые баны за день, suspicious IP и HTTPS-подключения
- отправляет nightly digest в `23:50 UTC` со списком новых IP за день и путями, по которым они ходили
- поддерживает allowlist IP, которые не должны повторно баниться, но должны оставаться под наблюдением
- поддерживает отдельный persistent denylist для вручную подтверждённых вредоносных IP

## Возможности

- Telegram bot на `aiogram 3`
- polling mode, без webhook
- ограничение доступа по `Telegram user id`
- inline-кнопки:
  - новые баны за день
  - весь текущий бан-лист
  - suspicious IP
  - HTTPS-подключения
- чтение `nginx access.log`
- чтение статуса `fail2ban`
- daily digest через `systemd timer`

## Структура

- `app/main.py` — основной Telegram-бот
- `app/reporting.py` — генерация security-отчётов
- `app/storage.py` — SQLite state для интервала отчётов
- `app/daily_digest.py` — nightly digest “новые баны за день”
- `app/config.py` — загрузка env
- `requirements.txt` — Python-зависимости проекта
- `deploy/` — готовые шаблоны для другого сервера

## Python environment

Проект рассчитан на запуск в отдельном virtual environment.

Что должен сделать агент:
- создать `venv` в корне проекта: `.venv`
- установить зависимости из `requirements.txt`
- запускать bot и nightly digest через бинарник Python из `.venv`

Базовые команды:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Для `systemd`-шаблонов в `deploy/systemd/` уже ожидается именно такой путь:
- `/opt/security-report-bot/.venv/bin/python`

## Требования для такого же поведения на другом сервере

Нужен Linux-сервер, где:
- `nginx` пишет access log
- установлен и работает `fail2ban`
- есть `fail2ban-client`
- есть `ss` из `iproute2`
- bot запускается с правами, достаточными для чтения логов и вызова `fail2ban-client`

Для “точно как здесь” рекомендован host deployment через `systemd`.

## Что должно существовать до первого запуска

Перед первым стартом агент должен подготовить на сервере следующее.

Пакеты и бинарники:
- `python3`
- `python3-venv`
- `pip`
- `nginx`
- `fail2ban`
- `iproute2` с командой `ss`
- `systemd`

Сервисы:
- `nginx.service` должен быть `active`
- `fail2ban.service` должен быть `active`
- сервис самого сайта или приложения должен существовать, если вы хотите видеть его статус в отчёте через `MONITORED_SERVICE_NAME`

Каталоги:
- `/opt/security-report-bot`
- `/etc/default`
- `/etc/security-report-bot`
- `/var/lib/security-report-bot`
- `/etc/fail2ban/filter.d`
- `/etc/fail2ban/jail.d`
- `/etc/systemd/system`

Файлы, которые нужно создать или скопировать до запуска:
- `/etc/default/security-report-bot`
- `/etc/security-report-bot/scan-whitelist.txt`
- `/etc/security-report-bot/manual-denylist.txt`
- `/etc/fail2ban/filter.d/nginx-vulnscan.conf`
- `/etc/fail2ban/jail.d/nginx-vulnscan.local`
- `/etc/fail2ban/jail.d/nginx-botsearch.local`
- `/etc/fail2ban/jail.d/nginx-allowlist.local`
- `/etc/fail2ban/jail.d/sshd.local`
- `/etc/systemd/system/security-report-bot.service`
- `/etc/systemd/system/security-daily-ban-digest.service`
- `/etc/systemd/system/security-daily-ban-digest.timer`
- `/etc/systemd/system/security-manual-denylist-sync.service`
- `/etc/systemd/system/security-manual-denylist-sync.path`

Файлы, которые должны быть доступны на чтение боту:
- `/var/log/nginx/access.log`
- при необходимости rotated logs `/var/log/nginx/access.log.*`

Права доступа:
- пользователь, под которым запускается бот, должен читать nginx access log
- этот пользователь должен иметь доступ к `fail2ban-client`
- путь из `STATE_DB_PATH` должен быть доступен на запись

Минимально обязательные значения в `/etc/default/security-report-bot`:
- `TELEGRAM_BOT_TOKEN`
- `ALLOWED_CHAT_IDS` или `TELEGRAM_CHAT_ID`
- `MONITORED_SERVICE_NAME`, если в отчёте нужен статус основного сайта или приложения

Если используется reverse proxy:
- для Cloudflare нужно положить real IP config, иначе в банах и отчётах будут edge IP вместо реальных клиентов
- для другого reverse proxy агент должен настроить эквивалентный real IP механизм вручную

## Переменные окружения

Смотрите [.env.example](.env.example).

Обязательные:
- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID` или `ALLOWED_CHAT_IDS`

Необязательные:
- `DEFAULT_REPORT_INTERVAL_SEC`
- `SCHEDULER_POLL_INTERVAL_SEC`
- `STATE_DB_PATH`
- `REPORT_TITLE`
- `MONITORED_SERVICE_NAME`
- `MONITORED_SERVICE_LABEL`
- `ALLOWLIST_PATH`
- `MANUAL_DENYLIST_PATH`

## Установка на новый сервер

Ниже порядок действий, который должен выполнить агент на новом сервере.

### 1. Скопировать проект

```bash
git clone <your-repo-url> /opt/security-report-bot
cd /opt/security-report-bot
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

### 2. Подготовить env

```bash
sudo mkdir -p /etc/default /etc/security-report-bot /var/lib/security-report-bot
cp .env.example /etc/default/security-report-bot
chmod 600 /etc/default/security-report-bot
```

Заполните:
- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`
- `ALLOWED_CHAT_IDS`
- `MONITORED_SERVICE_NAME`
- `MONITORED_SERVICE_LABEL`

### 3. Подготовить Nginx real IP

Если сайт за Cloudflare, скопируйте:
- [deploy/nginx/cloudflare-realip.conf.template](deploy/nginx/cloudflare-realip.conf.template)

в:
- `/etc/nginx/conf.d/cloudflare-realip.conf`

Для раннего дропа scanner-проб с последующим баном добавьте в публичные server block ещё и:
- [deploy/nginx/scanner-drop-locations.conf.template](deploy/nginx/scanner-drop-locations.conf.template)

Этот snippet не выключает логирование, а пишет такие запросы в `/var/log/nginx/scanner-drop.log`, чтобы их видел `fail2ban`.

После этого:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

### 4. Подготовить fail2ban

Скопируйте шаблоны:
- [deploy/fail2ban/filter.d/nginx-vulnscan.conf](deploy/fail2ban/filter.d/nginx-vulnscan.conf)
- [deploy/fail2ban/jail.d/nginx-vulnscan.local](deploy/fail2ban/jail.d/nginx-vulnscan.local)
- [deploy/fail2ban/jail.d/nginx-botsearch.local](deploy/fail2ban/jail.d/nginx-botsearch.local)
- [deploy/fail2ban/jail.d/nginx-allowlist.local.example](deploy/fail2ban/jail.d/nginx-allowlist.local.example)
- [deploy/fail2ban/jail.d/sshd.local](deploy/fail2ban/jail.d/sshd.local)

в соответствующие каталоги на сервере:
- `/etc/fail2ban/filter.d/`
- `/etc/fail2ban/jail.d/`

`nginx-vulnscan.local` уже ожидает два источника логов:
- `/var/log/nginx/access.log`
- `/var/log/nginx/scanner-drop.log`

Если нужен allowlist, создайте:
- `/etc/security-report-bot/scan-whitelist.txt`

по шаблону:
- [deploy/server/scan-whitelist.txt](deploy/server/scan-whitelist.txt)

Если нужен persistent denylist для вручную подтверждённых вредоносных IP, создайте:
- `/etc/security-report-bot/manual-denylist.txt`

по шаблону:
- [deploy/server/manual-denylist.txt](deploy/server/manual-denylist.txt)

Для `nginx-allowlist.local`:
- создайте файл на основе `deploy/fail2ban/jail.d/nginx-allowlist.local.example`
- внесите туда только те IP или подсети, которые вы сознательно хотите исключить из банов
- не оставляйте в шаблоне чужие IP

После этого:

```bash
sudo systemctl restart fail2ban
sudo fail2ban-client status nginx-vulnscan
```

### 5. Поднять Telegram-бота

Скопируйте systemd template:
- [deploy/systemd/security-report-bot.service](deploy/systemd/security-report-bot.service)

в:
- `/etc/systemd/system/security-report-bot.service`

Затем:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now security-report-bot.service
sudo systemctl status security-report-bot.service
```

### 6. Включить sync для persistent denylist

Скопируйте:
- [deploy/systemd/security-manual-denylist-sync.service](deploy/systemd/security-manual-denylist-sync.service)
- [deploy/systemd/security-manual-denylist-sync.path](deploy/systemd/security-manual-denylist-sync.path)

в:
- `/etc/systemd/system/`

Затем:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now security-manual-denylist-sync.path
sudo systemctl start security-manual-denylist-sync.service
sudo systemctl status security-manual-denylist-sync.path
```

### 7. Включить nightly digest

Скопируйте:
- [deploy/systemd/security-daily-ban-digest.service](deploy/systemd/security-daily-ban-digest.service)
- [deploy/systemd/security-daily-ban-digest.timer](deploy/systemd/security-daily-ban-digest.timer)

в:
- `/etc/systemd/system/`

Затем:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now security-daily-ban-digest.timer
sudo systemctl status security-daily-ban-digest.timer
```

Nightly digest будет приходить в `23:50 UTC`.

## Команды бота

- `/report` — отчёт сейчас
- `/status` — текущая настройка
- `/interval 3h` — сменить интервал
- `/off` — выключить периодические отчёты

## Allowlist

Allowlist нужен для IP, которые:
- не должны повторно баниться
- но должны оставаться под наблюдением в suspicious-отчётах

Текущая схема:
- список хранится в `/etc/security-report-bot/scan-whitelist.txt`
- поддерживаются и отдельные IP, и CIDR-сети
- `fail2ban` получает эти IP через `ignoreip`
- бот продолжает показывать такие адреса как `в белом списке`
- в шаблоне уже есть полный Cloudflare CIDR-набор, чтобы edge IP не банились по умолчанию

## Persistent denylist

Persistent denylist нужен для IP, которые:
- вы вручную подтвердили как вредоносные
- должны оставаться заблокированными независимо от live-состояния `fail2ban`

Текущая схема:
- список хранится в `/etc/security-report-bot/manual-denylist.txt`
- поддерживаются и отдельные IP, и CIDR-сети
- `ufw` получает эти записи через `python -m app.manual_denylist sync`
- бот считает такие IP заблокированными даже если они уже не видны в текущем `fail2ban-client status`
- для быстрого добавления можно использовать `python -m app.manual_denylist add 203.0.113.10`

## Docker

В репозитории есть [Dockerfile](Dockerfile), но это скорее packaging-артефакт, чем основной способ установки.

Важно:
- для полного поведения боту нужен доступ к host log files и `fail2ban-client`
- внутри обычного контейнера без bind mounts и host integration бот не сможет “точно так же” читать состояние сервера

Поэтому:
- для продакшена на реальном сервере предпочтителен `systemd`
- Docker уместен для разработки, упаковки и ограниченных сценариев

Пример:

```bash
docker build -t security-report-bot .
docker run --rm --env-file .env security-report-bot
```

Но для server-inspection такого контейнера недостаточно без дополнительных host mounts.

## Проверка после установки

```bash
sudo systemctl status security-report-bot.service
sudo systemctl status security-manual-denylist-sync.path
sudo systemctl status security-daily-ban-digest.timer
sudo fail2ban-client status nginx-vulnscan
sudo tail -n 50 /var/log/nginx/access.log
```

В Telegram проверьте:
- `/report`
- inline-кнопки
- ночной digest

## Чеклист для агента при переносе на другой сервер

Агент должен сделать это в таком порядке:

1. Проверить, что на сервере есть `nginx`, `fail2ban`, `fail2ban-client`, `ss`, `systemd`, `python3`, `python3-venv`.
2. Убедиться, что `nginx.service` и `fail2ban.service` уже активны.
3. Создать каталоги `/opt/security-report-bot`, `/etc/security-report-bot`, `/var/lib/security-report-bot`.
4. Развернуть код проекта в `/opt/security-report-bot`.
5. Создать виртуальное окружение и установить `requirements.txt`.
6. Создать `/etc/default/security-report-bot` по `.env.example` и заполнить переменные.
7. Настроить real IP для reverse proxy, если сайт стоит за CDN или балансировщиком.
8. Положить fail2ban filter и jail-файлы в `/etc/fail2ban/...`.
9. Создать `/etc/security-report-bot/scan-whitelist.txt`.
10. Создать `/etc/security-report-bot/manual-denylist.txt`.
11. Создать `/etc/fail2ban/jail.d/nginx-allowlist.local` из example-шаблона, если нужен allowlist.
12. Перезапустить `fail2ban` и проверить, что jail `nginx-vulnscan` появился.
13. Положить `systemd` unit-файлы бота, nightly digest и denylist sync.
14. Выполнить `systemctl daemon-reload`.
15. Включить и запустить `security-report-bot.service`.
16. Включить `security-manual-denylist-sync.path` и один раз запустить `security-manual-denylist-sync.service`.
17. Включить и запустить `security-daily-ban-digest.timer`.
18. Проверить, что бот отвечает на `/report`, а timer запланирован на `23:50 UTC`.

## Что адаптировать под другой сайт

Обязательно проверить:
- путь к `nginx access.log`
- используется ли Cloudflare или другой reverse proxy
- нужны ли свои allowlist IP
- нужны ли дополнительные fail2ban regex под стек сайта
- какой `Telegram user id` должен иметь доступ

## GitHub checklist

Перед публикацией:
- не коммитить `.env`
- не коммитить `.venv`
- не коммитить реальные server-specific secrets
- не коммитить реальный allowlist из продакшена, если он чувствительный
