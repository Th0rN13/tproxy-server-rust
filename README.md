# tproxy-server-rs

Rust rewrite of [telegramdesktop/tproxy-server](https://github.com/telegramdesktop/tproxy-server) (Go, proof-of-concept) with the goal of a production-ready relay for the Telegram WEB proxy type. The protocol and the overall design come from that project; `PROTOCOL.md` upstream stays the normative wire contract.

## Module map

| Rust module              | Go source                                                          |
| ------------------------ | ------------------------------------------------------------------ |
| `src/frame.rs`           | `internal/frame/frame.go`                                          |
| `src/token.rs`           | `internal/session/token.go`, `internal/config/token_key.go`        |
| `src/config.rs`          | `internal/config/config.go`                                        |
| `src/session.rs`         | `internal/session/session.go`                                      |
| `src/session/manager.rs` | `internal/session/manager.go`                                      |
| `src/server.rs`          | `internal/server/server.go`                                        |
| `src/server/secrets.rs`  | `internal/server/secrets.go`                                       |
| `src/server/site.rs`     | `internal/server/site.go`                                          |
| `src/bridge.rs`          | `internal/bridge/page.go` (template moves to `assets/bridge.html`) |

Stack: tokio, axum (HTTP + WebSocket), serde, hmac/sha2/aes/subtle, metrics + Prometheus exporter, tracing.

## Port status

All eight port steps are complete: frame, token, config, session core, manager, server, bridge page, and main with the admin surface. 77 tests pass (`cargo test`), covering the Go test matrices including probing parity, secret scanning at every base64 offset, carrier round trips for all four modes, and lane isolation. `assets/bridge.html` matches the Go template except one comment block reformatted to satisfy `goh comments`; the executable page content is unchanged.

Remaining production work: fuzzing the frame parser, a 24-72h soak test, and Linux CI verification of the unix-gated permission tests.

## Build

```bash
cargo test
cargo build --release
```

## Deployment

- `deploy/` - Docker Compose on a dedicated host with nginx in front.
- `deploy/systemd/` - systemd services next to an existing Caddy container.
