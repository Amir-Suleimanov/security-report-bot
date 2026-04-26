# INSTALL

Краткая инструкция по установке `security-report-bot` на новый Linux-сервер.

## 1. Что должно быть на сервере заранее

Установлены пакеты и доступны команды:
- `python3`
- `python3-venv`
- `pip`
- `nginx`
- `fail2ban`
- `fail2ban-client`
- `ss` из `iproute2`
- `systemctl`

Сервисы уже существуют и работают:
- `nginx.service`
- `fail2ban.service`

Если в отчёте нужен статус основного сайта или приложения, на сервере должен существовать и его `systemd` service name.

## 2. Создать каталоги

```bash
sudo mkdir -p /opt/security-report-bot
sudo mkdir -p /etc/security-report-bot
sudo mkdir -p /var/lib/security-report-bot
sudo mkdir -p /etc/default
```

## 3. Развернуть код проекта

```bash
git clone <your-repo-url> /opt/security-report-bot
cd /opt/security-report-bot
```

## 4. Создать virtual environment и установить зависимости

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Проект и `systemd`-шаблоны ожидают Python по пути:

```bash
/opt/security-report-bot/.venv/bin/python
```

## 5. Подготовить env

```bash
sudo cp .env.example /etc/default/security-report-bot
sudo chmod 600 /etc/default/security-report-bot
sudo editor /etc/default/security-report-bot
```

Обязательно заполнить:
- `TELEGRAM_BOT_TOKEN`
- `ALLOWED_CHAT_IDS` или `TELEGRAM_CHAT_ID`

Заполнить при необходимости:
- `REPORT_TITLE`
- `MONITORED_SERVICE_NAME`
- `MONITORED_SERVICE_LABEL`
- `ALLOWLIST_PATH`
- `MANUAL_DENYLIST_PATH`
- `FAIL2BAN_DB_PATH`
- `FAIL2BAN_IGNORE_BASE_PATH`
- `STATE_DB_PATH`

## 6. Настроить real IP для reverse proxy

Если сайт стоит за Cloudflare:

```bash
sudo cp deploy/nginx/cloudflare-realip.conf.template /etc/nginx/conf.d/cloudflare-realip.conf
sudo nginx -t
sudo systemctl reload nginx
```

Если используется другой reverse proxy или CDN, настройте эквивалентный real IP механизм вручную.

Для раннего дропа scanner-проб с последующим баном встроите snippet:

```bash
deploy/nginx/scanner-drop-locations.conf.template
```

в каждый публичный `server` block сайта. Он пишет такие запросы в `/var/log/nginx/scanner-drop.log`, чтобы их видел `fail2ban`.

## 7. Настроить fail2ban filter и jails

```bash
sudo cp deploy/fail2ban/filter.d/nginx-vulnscan.conf /etc/fail2ban/filter.d/nginx-vulnscan.conf
sudo cp deploy/fail2ban/jail.d/nginx-vulnscan.local /etc/fail2ban/jail.d/nginx-vulnscan.local
sudo cp deploy/fail2ban/jail.d/nginx-botsearch.local /etc/fail2ban/jail.d/nginx-botsearch.local
sudo cp deploy/fail2ban/jail.d/sshd.local /etc/fail2ban/jail.d/sshd.local
```

`nginx-vulnscan.local` должен читать не только текущие логи, но и свежеротированные `.1`:

- `/var/log/nginx/access.log`
- `/var/log/nginx/access.log.1`
- `/var/log/nginx/scanner-drop.log`
- `/var/log/nginx/scanner-drop.log.1`

Если нужен allowlist:

```bash
sudo cp deploy/server/scan-whitelist.txt /etc/security-report-bot/scan-whitelist.txt
sudo cp deploy/server/fail2ban-ignore-base.txt /etc/security-report-bot/fail2ban-ignore-base.txt
sudo editor /etc/security-report-bot/scan-whitelist.txt
sudo editor /etc/security-report-bot/fail2ban-ignore-base.txt
```

Если allowlist не нужен:

```bash
sudo touch /etc/security-report-bot/scan-whitelist.txt
sudo touch /etc/security-report-bot/fail2ban-ignore-base.txt
```

Если нужен persistent denylist для вручную подтверждённых вредоносных IP:

```bash
sudo cp deploy/server/manual-denylist.txt /etc/security-report-bot/manual-denylist.txt
sudo editor /etc/security-report-bot/manual-denylist.txt
```

Если пока не нужен:

```bash
sudo touch /etc/security-report-bot/manual-denylist.txt
```

Шаблоны уже включают Cloudflare CIDR по умолчанию:
- `scan-whitelist.txt` для Telegram-бота
- `manual-denylist.txt` для постоянных ручных блокировок в `ufw`

Бот понимает не только отдельные IP, но и CIDR-сети.
`fail2ban` ignoreip теперь синхронизируется автоматически из:
- `scan-whitelist.txt`
- `fail2ban-ignore-base.txt`

Перезапустить `fail2ban`:

```bash
sudo systemctl restart fail2ban
sudo fail2ban-client status nginx-vulnscan
```

## 8. Установить systemd units

```bash
sudo cp deploy/systemd/security-report-bot.service /etc/systemd/system/security-report-bot.service
sudo cp deploy/systemd/security-daily-ban-digest.service /etc/systemd/system/security-daily-ban-digest.service
sudo cp deploy/systemd/security-daily-ban-digest.timer /etc/systemd/system/security-daily-ban-digest.timer
sudo cp deploy/systemd/security-allowlist-sync.service /etc/systemd/system/security-allowlist-sync.service
sudo cp deploy/systemd/security-allowlist-sync.path /etc/systemd/system/security-allowlist-sync.path
sudo cp deploy/systemd/security-manual-denylist-sync.service /etc/systemd/system/security-manual-denylist-sync.service
sudo cp deploy/systemd/security-manual-denylist-sync.path /etc/systemd/system/security-manual-denylist-sync.path
sudo systemctl daemon-reload
```

## 9. Запустить бот

```bash
sudo systemctl enable --now security-report-bot.service
sudo systemctl status security-report-bot.service
```

## 10. Включить sync для allowlist

```bash
sudo systemctl enable --now security-allowlist-sync.path
sudo systemctl start security-allowlist-sync.service
sudo systemctl status security-allowlist-sync.path
```

## 11. Включить sync для persistent denylist

```bash
sudo systemctl enable --now security-manual-denylist-sync.path
sudo systemctl start security-manual-denylist-sync.service
sudo systemctl status security-manual-denylist-sync.path
```

## 12. Включить nightly digest

```bash
sudo systemctl enable --now security-daily-ban-digest.timer
sudo systemctl status security-daily-ban-digest.timer
```

Digest отправляется в `23:50 UTC`.

## 13. Что проверить после запуска

Проверить сервисы:

```bash
sudo systemctl status nginx
sudo systemctl status fail2ban
sudo systemctl status security-report-bot.service
sudo systemctl status security-allowlist-sync.path
sudo systemctl status security-manual-denylist-sync.path
sudo systemctl status security-daily-ban-digest.timer
```

Проверить логи и jail:

```bash
sudo fail2ban-client status nginx-vulnscan
sudo /opt/security-report-bot/.venv/bin/python -m app.manual_denylist status
sudo tail -n 50 /var/log/nginx/access.log
```

Проверить в Telegram:
- `/report`
- `/status`
- inline-кнопки
- отсутствие ответа для неразрешённых пользователей

## 14. Что агент не должен забыть

- Бот должен читать `/var/log/nginx/access.log` и при необходимости `access.log.*`
- Путь из `STATE_DB_PATH` должен быть доступен на запись
- Не смешивайте scanner allowlist и инфраструктурные исключения: первое храните в `scan-whitelist.txt`, второе в `fail2ban-ignore-base.txt`
- Не складывайте автоматические `fail2ban`-срабатывания в `manual-denylist.txt` без ручной проверки
- Не коммитьте реальный `.env`
- Не используйте Docker как основной способ продакшен-развёртывания, если нужен доступ к host logs и `fail2ban-client`
