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
- `STATE_DB_PATH`

## 6. Настроить real IP для reverse proxy

Если сайт стоит за Cloudflare:

```bash
sudo cp deploy/nginx/cloudflare-realip.conf.template /etc/nginx/conf.d/cloudflare-realip.conf
sudo nginx -t
sudo systemctl reload nginx
```

Если используется другой reverse proxy или CDN, настройте эквивалентный real IP механизм вручную.

## 7. Настроить fail2ban filter и jails

```bash
sudo cp deploy/fail2ban/filter.d/nginx-vulnscan.conf /etc/fail2ban/filter.d/nginx-vulnscan.conf
sudo cp deploy/fail2ban/jail.d/nginx-vulnscan.local /etc/fail2ban/jail.d/nginx-vulnscan.local
sudo cp deploy/fail2ban/jail.d/nginx-botsearch.local /etc/fail2ban/jail.d/nginx-botsearch.local
sudo cp deploy/fail2ban/jail.d/sshd.local /etc/fail2ban/jail.d/sshd.local
```

Если нужен allowlist:

```bash
sudo cp deploy/fail2ban/jail.d/nginx-allowlist.local.example /etc/fail2ban/jail.d/nginx-allowlist.local
sudo cp deploy/server/scan-whitelist.txt /etc/security-report-bot/scan-whitelist.txt
sudo editor /etc/fail2ban/jail.d/nginx-allowlist.local
sudo editor /etc/security-report-bot/scan-whitelist.txt
```

Если allowlist не нужен:

```bash
sudo touch /etc/security-report-bot/scan-whitelist.txt
```

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
sudo systemctl daemon-reload
```

## 9. Запустить бот

```bash
sudo systemctl enable --now security-report-bot.service
sudo systemctl status security-report-bot.service
```

## 10. Включить nightly digest

```bash
sudo systemctl enable --now security-daily-ban-digest.timer
sudo systemctl status security-daily-ban-digest.timer
```

Digest отправляется в `23:50 UTC`.

## 11. Что проверить после запуска

Проверить сервисы:

```bash
sudo systemctl status nginx
sudo systemctl status fail2ban
sudo systemctl status security-report-bot.service
sudo systemctl status security-daily-ban-digest.timer
```

Проверить логи и jail:

```bash
sudo fail2ban-client status nginx-vulnscan
sudo tail -n 50 /var/log/nginx/access.log
```

Проверить в Telegram:
- `/report`
- `/status`
- inline-кнопки
- отсутствие ответа для неразрешённых пользователей

## 12. Что агент не должен забыть

- Бот должен читать `/var/log/nginx/access.log` и при необходимости `access.log.*`
- Путь из `STATE_DB_PATH` должен быть доступен на запись
- Не оставляйте в `nginx-allowlist.local` и `scan-whitelist.txt` чужие IP из другого сервера
- Не коммитьте реальный `.env`
- Не используйте Docker как основной способ продакшен-развёртывания, если нужен доступ к host logs и `fail2ban-client`
