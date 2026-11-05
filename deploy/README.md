# deploy

Docker-деплой tproxy-server для VPS с ограниченной памятью (512 МБ).

Вариант с systemd-сервисами вместо Docker Compose: `systemd/README.md`.

## Файлы

- `Dockerfile` — multi-stage, статический musl-бинарь, runtime alpine.
- `docker-compose.yml` — `network_mode: host` обязателен: сервер принимает только
  loopback-peers (nginx на хосте ходит через 127.0.0.1).
- `config.json` — лимиты ужаты под 512 МБ RAM (худший случай ~64 МБ + база).
- `profiles.json` — шаблон профиля.
- `token.key` — создаётся на VPS, см. ниже.

## Подготовка

```sh
cp -r deploy /opt/tproxy && cd /opt/tproxy
openssl rand -hex 16          # вставить в profiles.json вместо REPLACE_WITH_...
openssl rand 32 > token.key
chmod 600 token.key profiles.json
mkdir -p public && cp index.html public/   # свой сайт-приманка
```

В `config.json` заменить `public_hostname` на свой домен.
`backend` в profiles.json — куда туннель отдаёт трафик (например SSH на 127.0.0.1:22).

## Запуск

```sh
docker compose run --rm tproxy /tproxy-server -config /config.json -check
docker compose up -d --build
```

Перед `up` убедиться, что 8080 и 8081 на хосте свободны.
nginx-блок: TLS 443 → `proxy_pass http://127.0.0.1:8080` с
`proxy_set_header Host $host; proxy_set_header X-Forwarded-For $remote_addr;`
`proxy_read_timeout 75s; client_max_body_size 4m;` и Upgrade-заголовками для WS-режимов.
