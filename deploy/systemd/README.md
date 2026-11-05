# deploy/systemd

Установка на хост, где Caddy уже слушает 80/443 в контейнере, а relay и MTProxy
работают как systemd-сервисы. Нужны Debian или Ubuntu, x86_64, root и Docker.

```
клиент :443 → Caddy (Docker) → <шлюз Docker>:8082 → socat → 127.0.0.1:8080 tproxy
                                                            → 127.0.0.1:2398 MTProxy → Telegram
```

Relay принимает только loopback-пиров и сам ходит только на loopback, поэтому
Caddy из bridge-сети соединяется с ним через `socat` на адресе шлюза Docker.

## Требования

- A-запись выбранного hostname уже указывает на этот хост. Caddy выпускает
  сертификат по HTTP-01 при первом запросе, поэтому 80 и 443 должны быть
  доступны снаружи до запуска установщика.
- Caddyfile смонтирован в контейнер. По умолчанию скрипт ждёт контейнер `caddy`
  и файл `/opt/remnawave/caddy/Caddyfile`; путь и имя контейнера задаются через
  `--caddyfile` и `--caddy-container`. Подойдёт и другой край: тогда скрипт
  предупредит, что блок из `Caddyfile.tproxy` нужно вставить самому.
- Сборка MTProxy идёт на хосте: скрипт ставит `build-essential`, `libssl-dev`,
  `zlib1g-dev`, качает исходники с `core.telegram.org` и компилирует. Нужно
  около 300 МБ диска и несколько минут.
- Снаружи открыты только 80 и 443. Порты 8080, 8081, 2398 и 8888 остаются
  локальными.

## Сборка

Бинарь собирается на Linux (glibc достаточно, musl не нужен):

```sh
cargo build --release
cp target/release/tproxy-server ./tproxy-server
```

Готовый статический бинарь можно не собирать: пуш тега `v*` запускает
`.github/workflows/release.yml`, который кладёт в релиз
`tproxy-server-x86_64-unknown-linux-musl.tar.gz` и `.sha256`.

## Установка

```sh
sudo ./deploy/systemd/install.sh --hostname notes.example.com --binary ./tproxy-server
```

Флаги: `--secret 32-hex` (иначе генерируется или переиспользуется прежний),
`--site-dir DIR` (по умолчанию `deploy/systemd/site`), `--gateway IP`,
`--network NAME` (сеть Docker с Caddy), `--caddyfile PATH` и
`--caddy-container NAME` (по умолчанию `/opt/remnawave/caddy/Caddyfile` и
`caddy`). Если файла по указанному пути нет, скрипт предупредит и оставит
блок сайта на ручную вставку.

Скрипт ставит официальный MTProxy из закреплённого коммита, создаёт
пользователей `tproxy` и `mtproxy`, каталоги `/opt/tproxy`, `/etc/mtproxy`,
`/opt/MTProxy`, конфиги, ключ токена и сайт, затем запускает сервисы. Перед
запуском он выполняет `-check`.

Повторный запуск безопасен: бинарь обновляется, сервисы перезапускаются,
существующие `token.key` и содержимое `/opt/tproxy/public` сохраняются. А вот
`config.json` и `profiles.json` каждый раз перезаписываются шаблоном из
скрипта, поэтому правки лимитов и профилей нужно вносить в сам скрипт, иначе
они потеряются при обновлении.

## Что меняется на хосте

- Юниты: `mtproxy`, `tproxy-firewall`, `tproxy-bridge`, `tproxy`,
  `refresh-mtproxy-config.timer`.
- `/opt/remnawave/caddy/Caddyfile`: добавляется блок сайта, рядом остаётся
  копия `Caddyfile.before-tproxy.*`. Перед reload выполняется `caddy validate`,
  при ошибке файл откатывается.
- UFW: правило `8082/tcp` только из подсети Docker.
- Root crontab: удаляется мёртвая строка про `MTProxy.service`, копия
  сохраняется в `/root/crontab.before-tproxy.*`.

Если локальный адрес хоста не совпадает с публичным, скрипт сам добавляет
`--nat-info <local>:<public>` в запуск MTProxy. На хосте с прямым публичным
IPv4 этот флаг пустой.

Порты 8080, 8081, 2398 и 8888 наружу не открываются: `tproxy-firewall` режет
всё, кроме loopback, а UFW по умолчанию закрывает входящие.

## После установки

Скрипт печатает `Proxy server`, `Proxy secret` и ссылку `t.me/webproxy`.
Секрет один и тот же для клиента и для MTProxy, `base_path` не используется.

- Сайт-приманка лежит в `/opt/tproxy/public`. Замените его своим и выполните
  `systemctl restart tproxy.service`. Каталог читается в память при старте.
- Ротация секрета: перезапуск с `--secret <32 hex>`, затем новые ссылки
  клиентам.
- Журналы: `journalctl -u tproxy -u mtproxy -u tproxy-bridge`.
- Обновление бинаря: `install.sh --hostname <тот же> --binary ./tproxy-server`.
  Скрипт перезапишет конфиги шаблоном и перезапустит все сервисы.
- Клиент вводит только hostname и секрет. Подходит Telegram Desktop и
  Android-клиент с WebView; нативный MTProto-прокси клиент не настраивает,
  весь обмен идёт через HTTPS-мост.

## Удаление

```sh
systemctl disable --now tproxy tproxy-bridge mtproxy refresh-mtproxy-config.timer tproxy-firewall
rm -f /etc/systemd/system/{tproxy,tproxy-bridge,mtproxy,tproxy-firewall,refresh-mtproxy-config}.service
rm -f /etc/systemd/system/refresh-mtproxy-config.timer
rm -rf /opt/tproxy /etc/mtproxy /opt/MTProxy
rm -f /usr/local/bin/tproxy-server /usr/local/sbin/refresh-mtproxy-config
systemctl daemon-reload
```

После этого уберите блок `https://<hostname> { ... }` из Caddyfile и
перезагрузите Caddy, затем `ufw delete allow from <подсеть Docker> to any port 8082 proto tcp`
и удалите пользователей `tproxy` и `mtproxy`.

## Ограничения

- `MemoryMax=96M` у relay и один воркер tokio. Для 16 сессий этого хватает,
  для большего числа поднимите лимит и `TOKIO_WORKER_THREADS`.
- Один хост обслуживает один публичный hostname. Домен `duckdns.org` годится
  для теста, но это известная динамическая зона: часть блоклистов её режет.
- Сайт в `site/` минимальный. Для боевого хоста нужен собственный контент,
  иначе приманка выглядит пустой.
