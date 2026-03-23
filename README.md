# VLESS Checker (Go)

Утилита проверяет доступность `vless://` конфигурации и показывает, на каком этапе возникает сбой:

1. Парсинг URL-конфига
2. DNS-резолв домена
3. TCP-подключение к `host:port`
4. TLS handshake (если `security=tls` или `security=reality`)
5. WebSocket Upgrade probe (если `type=ws`, либо при `--prefer-ws`)
6. Реальный VLESS handshake + пробный проксированный HTTP запрос
7. Поведение сервера после handshake (классификация причины)

## Запуск

```bash
go run . --config "vless://UUID@example.com:443?security=tls&type=ws&path=%2Fws&sni=example.com&host=example.com"
```

Полезные флаги:

- `--timeout 8` - таймаут этапа (сек)
- `--skip-tls-verify true` - не проверять TLS сертификат (по умолчанию `true`)
- `--ws-probe true` - проверять WS upgrade (по умолчанию `true`)
- `--sni example.com` - принудительно задать SNI
- `--vless-handshake true` - выполнить реальный VLESS handshake (по умолчанию `true`)
- `--probe-dest connectivitycheck.gstatic.com:80,example.org:80` - один или несколько целевых адресов (через запятую), используется fallback
- `--probe-host connectivitycheck.gstatic.com` - Host header для тестового HTTP запроса через VLESS

## Как читать результат

- Если все этапы `OK`, базовая доступность есть.
- Если есть `FAIL`, строка `Итог: проблема возникает на этапе ...` показывает точку сбоя.
- Для этапа `post_handshake_behavior`:
  - `connection_reset -> auth fail`
  - `hang_timeout -> возможно OK`
  - `immediate_close -> reject`
- При `security=reality` выводится явное предупреждение: нужна отдельная валидация параметров Reality (`shortId/publicKey/fingerprint`), которые не всегда полностью покрываются базовой проверкой.
- Код возврата процесса:
  - `0` - все этапы успешны
  - `1` - есть сбой на одном из этапов
  - `2` - ошибка аргументов запуска