# AGENTS

## Purpose
Этот репозиторий содержит отдельного Telegram security-бота для хоста, где:
- `nginx` пишет access log
- `fail2ban` банит web scanner IP
- оператор хочет получать отчёты и nightly digest в Telegram

## Critical rules
- Для “точно такого же” поведения на другом сервере предпочитать host deployment через `systemd`, а не Docker-only режим.
- Все авторазбаны отключены. Nightly job только отправляет digest.
- IP из allowlist не должны баниться повторно, но их suspicious requests должны быть видны в отчётах.
- Вручную подтверждённые вредоносные IP должны идти в отдельный persistent denylist, а не смешиваться с обычными временными банами `fail2ban`.
- Если `fail2ban` пропускает scanner hit, его должна добрать отдельная reconcile-джоба по логам, а не оператор вручную.

## Deploy order
1. Скопировать репозиторий на новый сервер.
2. Заполнить `.env` по `.env.example`.
3. Положить server-side шаблоны из `deploy/`:
   - `deploy/nginx/cloudflare-realip.conf.template`
   - `deploy/fail2ban/filter.d/nginx-vulnscan.conf`
   - `deploy/fail2ban/jail.d/*.local`
4. Убедиться, что `nginx` и `fail2ban` читают нужные логи.
5. Поднять `security-report-bot.service`.
6. Включить `security-manual-denylist-sync.path` и `security-allowlist-sync.path`.
7. Включить `security-scanner-reconcile.timer`.
8. Включить `security-daily-ban-digest.timer` только если нужен nightly digest.

## Preflight for another agent
- Установить `python3`, `python3-venv`, `nginx`, `fail2ban`, `iproute2`.
- Проверить, что `nginx.service` и `fail2ban.service` уже запущены.
- Создать каталоги:
  - `/opt/security-report-bot`
  - `/etc/security-report-bot`
  - `/var/lib/security-report-bot`
- Создать файлы:
  - `/etc/default/security-report-bot`
  - `/etc/security-report-bot/scan-whitelist.txt`
  - `/etc/security-report-bot/fail2ban-ignore-base.txt`
  - `/etc/security-report-bot/manual-denylist.txt`
  - `/etc/fail2ban/filter.d/nginx-vulnscan.conf`
  - `/etc/fail2ban/jail.d/nginx-vulnscan.local`
  - `/etc/fail2ban/jail.d/nginx-botsearch.local`
  - `/etc/fail2ban/jail.d/sshd.local`
  - `/etc/logrotate.d/nginx`
  - `/etc/systemd/system/security-report-bot.service`
  - `/etc/systemd/system/security-daily-ban-digest.service`
  - `/etc/systemd/system/security-daily-ban-digest.timer`
  - `/etc/systemd/system/security-allowlist-sync.service`
  - `/etc/systemd/system/security-allowlist-sync.path`
  - `/etc/systemd/system/security-manual-denylist-sync.service`
  - `/etc/systemd/system/security-manual-denylist-sync.path`
  - `/etc/systemd/system/security-scanner-reconcile.service`
  - `/etc/systemd/system/security-scanner-reconcile.timer`
- Не запускать бот до тех пор, пока не заполнены `TELEGRAM_BOT_TOKEN` и `ALLOWED_CHAT_IDS`.

## Runtime assumptions
- Бот должен иметь доступ к:
  - `/var/log/nginx/access.log*`
  - `/var/log/nginx/scanner-drop.log*`
  - `fail2ban-client`
  - `ss`
- `STATE_DB_PATH` должен быть доступен на запись.
- Для Cloudflare-проксируемых сайтов нужен real IP config, иначе в логах будут edge IP вместо клиентов.
- После ротации `nginx` логов должен выполняться reload `nginx-vulnscan`, но финальной страховкой всё равно служит `security-scanner-reconcile.timer`.

## Files operators edit most often
- `.env`
- `deploy/server/scan-whitelist.txt`
- `deploy/server/fail2ban-ignore-base.txt`
- `deploy/server/manual-denylist.txt`
- `deploy/fail2ban/filter.d/nginx-vulnscan.conf`
