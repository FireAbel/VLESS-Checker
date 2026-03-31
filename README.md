# VLESS Checker + Telegram Bot (Go)

Утилита проверяет доступность `vless://` конфигурации и показывает, на каком этапе возникает сбой:

1. Парсинг URL-конфига
2. DNS-резолв домена
3. TCP-подключение к `host:port`
4. TLS handshake (если `security=tls` или `security=reality`)
5. WebSocket Upgrade probe (если `type=ws`, либо при `--prefer-ws`)
6. Embedded Xray probe (`security=none|tls|reality`, `type=tcp|ws|xhttp`): реальная проверка через встроенный `xray-core`

Также поддерживается режим Telegram-бота:

- принимает динамический VPN-конфиг (текстом или файлом)
- извлекает из него статические `vless://` конфигурации
- проверяет каждую конфигурацию
- возвращает результат по каждой: `WORKS/FAIL`
- для `FAIL` указывает этап сбоя и краткую причину

## Запуск

```bash
go run . --config "vless://UUID@example.com:443?security=tls&type=ws&path=%2Fws&sni=example.com&host=example.com"
```

## Запуск бота без лишних действий (run.bat)

1. Скопируйте `run.bat.example` в `run.bat`
2. Откройте `run.bat` и вставьте токен в строку `set TELEGRAM_BOT_TOKEN=...`
3. Запускайте бота двойным кликом по `run.bat`

Важно: `run.bat` добавлен в `.gitignore`, чтобы токен не попал в Git.

Бот понимает:
- текст с `vless://...` ссылками (по одной или много)
- http/https ссылку на конфиг/подписку (бот скачает содержимое и извлечет `vless://`)
- base64 подписку (внутри должны быть `vless://...`)
- текстовый файл, отправленный в чат

Полезные флаги:

- `--timeout 8` - таймаут этапа (сек)
- `--skip-tls-verify true` - не проверять TLS сертификат (по умолчанию `true`)
- `--ws-probe true` - проверять WS upgrade (по умолчанию `true`)
- `--sni example.com` - принудительно задать SNI
- `--config-url https://...` - скачать конфиг/подписку по ссылке и проверить все `vless://` внутри
- `--max-from-url 25` - максимум конфигов при `--config-url`
- `--db-dir db` - пакетная проверка файлов в папке (поиск всех `vless://` в каждом файле)
- `--db-logs-dir logs` - куда писать логи для `--db-dir` (по умолчанию `<db-dir>/check_logs`)
- `--db-workers 3` - параллельная обработка файлов в `--db-dir`
- `--db-max-per-file 0` - ограничить число конфигов из одного файла (`0` = без лимита)
- `--db-file-delay-sec 30` - задержка между файлами в `--db-dir` (`0` = без задержки)
- `--probe-url http://connectivitycheck.gstatic.com/generate_204` - URL для embedded xray-probe
- `--xray-timeout 30` - общий таймаут embedded xray-probe (сек)
- `--bot true` - запустить Telegram-бота
- `--telegram-token <TOKEN>` - токен бота (или `TELEGRAM_BOT_TOKEN`)
- `--max-configs 25` - максимум конфигов из одного сообщения
- `--workers 8` - параллельные воркеры проверки (рекомендуется 5–10)
- `--bot-timeout 30` - общий таймаут на один динамический конфиг (сек)
- `--user-rpm 60` - rate limit на пользователя (проверок/мин)
- `--global-rpm 300` - общий rate limit (проверок/мин)
- `--log-file run.log` - сохранить вывод CLI в файл (дублирует stdout/stderr)
- `--log-dir logs` - сохранить вывод CLI в `logs/run_YYYYMMDD_HHMMSS.log`

## Как читать результат

- Если все этапы `OK`, базовая доступность есть.
- Если есть `FAIL`, строка `Итог: проблема возникает на этапе ...` показывает точку сбоя.
- При `security=reality` выводится предупреждение: утилита проверяет сетевую доступность и VLESS-обмен, но это не 100% гарантия совместимости с конкретным клиентом/провайдером.
- В режиме `--db-dir` дополнительно формируются:
  - `<logs>/_summary.txt` (сводка по файлам и общим счётчикам),
  - `<logs>/_configs_ok.txt` (список успешных `vless://`),
  - `<logs>/_configs_error.txt` (список `vless://` с ошибками).
- Код возврата процесса:
  - `0` - все этапы успешны
  - `1` - есть сбой на одном из этапов
  - `2` - ошибка аргументов запуска