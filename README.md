# tproxy-server-rs

Rust rewrite of [telegramdesktop/tproxy-server](https://github.com/telegramdesktop/tproxy-server) (Go, proof-of-concept) with the goal of a production-ready relay for the Telegram WEB proxy type. The reference Go clone lives in `tproxy-server/` and is the behavioral specification; `PROTOCOL.md` in it is the normative wire contract.

## Module map

| Rust module | Go source |
|---|---|
| `src/frame.rs` | `internal/frame/frame.go` |
| `src/token.rs` | `internal/session/token.go`, `internal/config/token_key.go` |
| `src/config.rs` | `internal/config/config.go` |
| `src/session.rs` | `internal/session/session.go` |
| `src/session/manager.rs` | `internal/session/manager.go` |
| `src/server.rs` | `internal/server/server.go` |
| `src/server/secrets.rs` | `internal/server/secrets.go` |
| `src/server/site.rs` | `internal/server/site.go` |
| `src/bridge.rs` | `internal/bridge/page.go` (template moves to `assets/bridge.html`) |

Stack: tokio, axum (HTTP + WebSocket), serde, hmac/sha2/aes/subtle, metrics + Prometheus exporter, tracing.

## Port order

1. `frame` + capability derivation with golden vectors from `PROTOCOL.md`.
2. `token` (bootstrap/session tokens, AES filter tag).
3. `config` (serde, `deny_unknown_fields`, validation).
4. `session` core: budgets, flow control, lanes, tombstones — port the Go tests alongside.
5. `session/manager`: bootstraps, rate limits, capacity accounting.
6. `server`: HTTP endpoints, secret scanning, static site, reverse proxy, WebSocket carriers.
7. `bridge` page template byte-identical to the Go output.
8. Production work: CI (done), fuzzing the frame parser, metrics/logs, deploy scripts, soak test.

## Build

```bash
cargo test
cargo build --release
```
