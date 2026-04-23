# leaf

[![Docker Repository on Quay](https://quay.io/repository/cloudflavor/leaf/status "Docker Repository on Quay")](https://quay.io/repository/cloudflavor/leaf)  

`leaf` is an authoritative DNS server for nip.io-style hostnames, implemented in Rust and hardened for internet-facing deployment.

It serves deterministic `A` records from encoded IPv4 names inside a configured zone, for example:

- `1-2-3-4.dev.example.com` -> `1.2.3.4`
- `api.10-11-12-13.dev.example.com` -> `10.11.12.13`
- `1.2.3.4.dev.example.com` -> `1.2.3.4`

## Current Deployment

`leaf` is currently serving `xip.kali.st` in production, including names such as:

- `172-16-15-103.xip.kali.st` -> `172.16.15.103`

Official public webpage: `https://kali.st`

## Features

- Authoritative-only DNS behavior for one or more configured zones.
- UDP and TCP listeners.
- Correct negative responses with SOA authority section for `NXDOMAIN` and `NODATA`.
- Apex authoritative `SOA` and `NS` records.
- No recursion (`RA=0`).
- Global and per-IP query rate limiting.
- Per-IP + qname invalid-query throttling for repeated bad lookups.
- Global and per-IP TCP connection caps.
- TCP idle/read/write timeouts.
- UDP and TCP request size bounds.
- Structured operational logs for startup and dropped requests.
- Optional per-query success logs for UDP/TCP.

## DNS Behavior

`leaf` currently supports authoritative answers for `A` records derived from hostname-encoded IPv4 values.

Response policy:

- `OPCODE != QUERY` -> `NOTIMP`
- `QDCOUNT != 1` -> `FORMERR`
- Out-of-zone names -> `REFUSED` and non-authoritative (`AA=0`)
- In-zone `ANY` -> `REFUSED`
- In-zone existing encoded name + `A` -> `NOERROR` with one `A` answer, `AA=1`
- In-zone existing encoded name + non-`A` -> `NOERROR` with empty answer and SOA in authority (`NODATA`)
- In-zone non-existing encoded name -> `NXDOMAIN` with SOA in authority
- Apex `SOA` -> `NOERROR` with SOA answer
- Apex `NS` -> `NOERROR` with NS answer

## Project Layout

- `src/main.rs`: runtime orchestration, UDP/TCP loops, timeouts, logging, limit enforcement.
- `src/config.rs`: CLI/env/TOML parsing, precedence merge, and validation.
- `src/dns.rs`: authoritative DNS response logic.
- `src/limits.rs`: query and TCP connection limiter implementations.
- `tests/e2e.rs`: black-box end-to-end tests over real UDP/TCP sockets.
- `.gitlab-ci.yml`: CI pipeline for lint, checks, tests, extended tests, release artifact build.
- `Containerfile`: multi-stage image build for Podman.
- `.containerignore`: trimmed container build context.
- `PRODUCTION_READINESS.md`: go-live checklist and operational guidance.

## Requirements

- Rust toolchain (stable for local dev).
- Linux/macOS shell environment for examples below.
- For CI parity with this repo pipeline, nightly rust is used in GitLab jobs.
- Podman (optional, for containerized deployment).

## Build

```bash
cargo build
```

Release build:

```bash
cargo build --release
```

## Run

Minimum required configuration:

```bash
LEAF_ZONES=dev.example.com cargo run
```

This starts the server on `0.0.0.0:5300` by default.
`LEAF_ZONE` remains supported as a single-zone shorthand.

Example with explicit bind and TTL:

```bash
LEAF_ZONES=dev.example.com,prod.example.com \
LEAF_LISTEN=127.0.0.1:5300 \
LEAF_TTL=60 \
cargo run
```

### TOML Config

`leaf` supports file-based config from:

- `--config /path/to/leaf.toml`, or
- `LEAF_CONFIG=/path/to/leaf.toml`, or
- auto-load `./leaf.toml` if present

Precedence is:

- CLI flags
- Environment variables
- TOML file

Use [`leaf.example.toml`](leaf.example.toml) as the template.

For zone selection:

- `--zone` can be provided multiple times or as a comma-separated list.
- `LEAF_ZONES` accepts comma-separated zones.
- `LEAF_ZONE` is still supported for a single zone.
- In TOML, `zones = ["dev.example.com", "prod.example.com"]` is preferred; legacy `zone = "..."` remains supported.

Recommended `leaf.toml` layout:

```toml
zones = ["dev.example.com", "prod.example.com"]
listen = "0.0.0.0:5300"

[dns]
ttl = 60
# zone_ns = "ns1.dev.example.com"
# zone_hostmaster = "hostmaster.dev.example.com"

[soa]
serial = 1
refresh = 300
retry = 60
expire = 86400
minimum = 60

[limits]
global_qps_limit = 5000
per_ip_qps_limit = 200
per_ip_invalid_qname_qps_limit = 20
limiter_max_tracked_ips = 10000
invalid_qname_limiter_max_tracked_keys = 50000
tcp_max_connections = 1024
tcp_max_connections_per_ip = 64
tcp_idle_timeout_ms = 10000
tcp_read_timeout_ms = 3000
tcp_write_timeout_ms = 3000
max_tcp_frame_bytes = 4096
max_udp_request_bytes = 1232

[logging]
query_log_enabled = false
drop_log_include_client_ip = false
```

Notes:

- Top-level flat keys are still accepted for backward compatibility.
- If `dns.zone_ns`/`dns.zone_hostmaster` are omitted, defaults are derived per zone (`ns1.<zone>`, `hostmaster.<zone>`).
- Set `[logging].query_log_enabled = true` (or `LEAF_LOG_QUERIES=true`) to enable per-query log events.
- Set `[logging].drop_log_include_client_ip = true` (or `LEAF_LOG_DROP_CLIENT_IP=true`) to include `src_ip`/`src_port` on drop events only.
- Per-query events are emitted at `info` level.

## Podman (Hetzner) Quickstart

Build image:

```bash
podman build -t leaf:latest -f Containerfile .
```

Run on high port (works well for rootless local validation):

```bash
podman run --rm --name leaf \
  -e LEAF_ZONES=dev.example.com,prod.example.com \
  -p 5300:5300/udp \
  -p 5300:5300/tcp \
  leaf:latest
```

Run on public DNS port `53` (rootful Podman recommended):

```bash
sudo podman run -d --name leaf --restart=always \
  --read-only \
  --cap-drop=all \
  --cap-add=NET_BIND_SERVICE \
  -e LEAF_ZONES=dev.example.com,prod.example.com \
  -e LEAF_LISTEN=0.0.0.0:53 \
  -e LEAF_CONFIG=/etc/leaf/leaf.toml \
  -v ./leaf.toml:/etc/leaf/leaf.toml:ro \
  -p 53:53/udp \
  -p 53:53/tcp \
  leaf:latest
```

Notes:

- Rootless Podman usually cannot bind low ports like `53` without host tuning.
- On Hetzner, allow inbound `53/udp` and `53/tcp` in host and cloud firewall policy.

## Configuration Reference

All options are available via CLI flags and environment variables.
For TOML, you can use either flat top-level keys (legacy) or the structured layout shown above.

| Variable | Default | Description |
|---|---:|---|
| `LEAF_CONFIG` | none | Path to TOML config file (same as `--config`) |
| `LEAF_ZONES` | required unless `LEAF_ZONE` is set | Comma-separated authoritative zones (for example `dev.example.com,prod.example.com`) |
| `LEAF_ZONE` | optional | Backward-compatible single-zone shortcut |
| `LEAF_LISTEN` | `0.0.0.0:5300` | Bind address and port for UDP+TCP |
| `LEAF_TTL` | `60` | TTL for positive answers |
| `LEAF_ZONE_NS` | `ns1.<zone>` | Zone apex NS target |
| `LEAF_ZONE_HOSTMASTER` | `hostmaster.<zone>` | SOA RNAME-like mailbox domain |
| `LEAF_SOA_SERIAL` | `1` | SOA serial |
| `LEAF_SOA_REFRESH` | `300` | SOA refresh |
| `LEAF_SOA_RETRY` | `60` | SOA retry |
| `LEAF_SOA_EXPIRE` | `86400` | SOA expire |
| `LEAF_SOA_MINIMUM` | `60` | SOA minimum TTL, used in negative authority responses |
| `LEAF_GLOBAL_QPS_LIMIT` | `5000` | Global fixed-window query cap (1s window) |
| `LEAF_PER_IP_QPS_LIMIT` | `200` | Per-IP fixed-window query cap (1s window) |
| `LEAF_PER_IP_INVALID_QNAME_QPS_LIMIT` | `20` | Per-IP + qname fixed-window cap for invalid responses (`NXDOMAIN`/`REFUSED`/`FORMERR`) |
| `LEAF_LIMITER_MAX_TRACKED_IPS` | `10000` | Max distinct IPs tracked per limiter window |
| `LEAF_INVALID_QNAME_LIMITER_MAX_TRACKED_KEYS` | `50000` | Max distinct `ip+qname` keys tracked in invalid-query limiter window |
| `LEAF_TCP_MAX_CONNECTIONS` | `1024` | Global concurrent TCP connection cap |
| `LEAF_TCP_MAX_CONNECTIONS_PER_IP` | `64` | Per-IP concurrent TCP connection cap |
| `LEAF_TCP_IDLE_TIMEOUT_MS` | `10000` | Timeout waiting for next frame prefix |
| `LEAF_TCP_READ_TIMEOUT_MS` | `3000` | Timeout while reading frame payload |
| `LEAF_TCP_WRITE_TIMEOUT_MS` | `3000` | Timeout writing framed response |
| `LEAF_MAX_TCP_FRAME_BYTES` | `4096` | Max accepted incoming TCP DNS frame length |
| `LEAF_MAX_UDP_REQUEST_BYTES` | `1232` | Max accepted incoming UDP DNS payload |
| `LEAF_LOG_QUERIES` | `false` | Emit per-query success logs (`event=udp_query`/`event=tcp_query`) without client IP or qname |
| `LEAF_LOG_DROP_CLIENT_IP` | `false` | Include `src_ip`/`src_port` fields on drop events (`event=udp_drop`/`event=tcp_drop`) |

TOML key mapping in structured layout:

- `LEAF_ZONES` -> `zones = ["..."]`
- `LEAF_LISTEN` -> `listen = "ip:port"`
- `LEAF_TTL` -> `[dns] ttl = ...`
- `LEAF_ZONE_NS` -> `[dns] zone_ns = "..."`
- `LEAF_ZONE_HOSTMASTER` -> `[dns] zone_hostmaster = "..."`
- `LEAF_SOA_*` -> `[soa] ...`
- `LEAF_GLOBAL_QPS_LIMIT`, `LEAF_PER_IP_QPS_LIMIT`, `LEAF_PER_IP_INVALID_QNAME_QPS_LIMIT` -> `[limits] ...`
- `LEAF_LIMITER_MAX_TRACKED_IPS`, `LEAF_INVALID_QNAME_LIMITER_MAX_TRACKED_KEYS` -> `[limits] ...`
- `LEAF_TCP_*`, `LEAF_MAX_TCP_FRAME_BYTES`, `LEAF_MAX_UDP_REQUEST_BYTES` -> `[limits] ...`
- `LEAF_LOG_QUERIES` -> `[logging] query_log_enabled = ...` (legacy top-level `log_queries = ...` is also accepted)
- `LEAF_LOG_DROP_CLIENT_IP` -> `[logging] drop_log_include_client_ip = ...` (legacy top-level `log_drop_client_ip = ...` is also accepted)

## Query Examples

```bash
# Positive A lookup
dig @127.0.0.1 -p 5300 1-2-3-4.dev.example.com A +norecurse

# Apex SOA
dig @127.0.0.1 -p 5300 dev.example.com SOA +norecurse

# Apex NS
dig @127.0.0.1 -p 5300 dev.example.com NS +norecurse

# NXDOMAIN with SOA authority
dig @127.0.0.1 -p 5300 nope.dev.example.com A +norecurse
```

## Logging

`leaf` logs to stderr as structured key/value lines.

Always logged:

- startup events (`event=startup`)
- dropped/blocked traffic (`event=udp_drop`, `event=tcp_drop`)
- TCP handler failures (`event=tcp_connection_error`)

Optional per-query success logging:

- Set `LEAF_LOG_QUERIES=true` or `[logging] query_log_enabled = true`.
- Emits one structured event per answered UDP request with `event=udp_query`.
- Emits one structured event per answered TCP request with `event=tcp_query`.
- Query logs intentionally omit client IP and full qname for data minimization.
- Drop events can include `src_ip` and `src_port` when `LEAF_LOG_DROP_CLIENT_IP=true` (or `[logging] drop_log_include_client_ip = true`).
- Startup events are `info`, dropped/invalid traffic is `warn`, and handler failures are `error`.

For Podman:

```bash
sudo podman logs -f leaf
```

## Fail2ban Integration

`leaf` does not integrate with fail2ban in-process. Integration is log-based.

1. Enable source fields on drop events:

```toml
[logging]
query_log_enabled = false
drop_log_include_client_ip = true
```

2. Create a fail2ban filter at `/etc/fail2ban/filter.d/leaf-dns-drop.conf`:

```ini
[Definition]
failregex = ^.*event="(?:udp_drop|tcp_drop)".*reason="(?:request_too_large|parse_error|invalid_query_rate_limited|rate_limited|connection_limit_reached)".*src_ip=<HOST>(?:\s|$).*
ignoreregex =
```

3. Create a jail at `/etc/fail2ban/jail.d/leaf-dns.local`:

```ini
[leaf-dns-drop]
enabled = true
filter = leaf-dns-drop
port = 53,53/udp
findtime = 60
maxretry = 20
bantime = 15m
backend = systemd
journalmatch = _SYSTEMD_UNIT=leaf.service
```

4. If running as a Podman systemd unit, change `journalmatch` to the container unit, for example:

```ini
journalmatch = _SYSTEMD_UNIT=podman-leaf.service
```

5. Reload fail2ban:

```bash
sudo systemctl restart fail2ban
sudo fail2ban-client status leaf-dns-drop
```

Operational notes:

- Use higher `maxretry` for UDP-heavy patterns (`udp_drop parse_error`) because UDP source IP can be spoofed.
- Keep `query_log_enabled=false` for privacy and volume control; fail2ban only needs drop events.
- Fail2ban is useful for repeat source suppression, not a substitute for upstream DDoS controls.

## Testing

Run all checks locally:

```bash
cargo fmt --all -- --check
cargo check --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked
cargo test --all-targets --all-features --release --locked
```

Test coverage currently includes:

- Unit tests for parser/config/limiter and DNS logic.
- End-to-end integration tests that spawn the real `leaf` binary and query it over UDP and TCP.
- E2E protocol matrix coverage for apex records, positive A synthesis, NXDOMAIN/NODATA, `ANY` refusal, out-of-zone refusal, non-`QUERY` opcode handling, and multi-question `FORMERR`.
- E2E coverage for structured TOML startup and invalid-query throttling behavior.

## CI/CD

The GitLab pipeline (`.gitlab-ci.yml`) contains:

- `cargo_fmt`
- `cargo_check`
- `cargo_clippy`
- `cargo_test`
- `cargo_test_extended`
- `release` job (tag-only) that builds Linux `amd64` + `arm64` binaries and publishes versioned tarballs:
- `dist/leaf-amd64-linux-${TAG}.tar.gz`
- `dist/leaf-arm64-linux-${TAG}.tar.gz`
- `dist/SHA256SUMS`
- `container_release` job (tag-only) that builds and publishes multi-arch (`amd64`, `arm64`) images to Quay

Quay publish job requires these CI/CD variables:

- `QUAY_USERNAME`
- `QUAY_PASSWORD`

Image destination defaults to:

- `quay.io/cloudflavor/leaf:${GIT_COMMIT_TAG}` (fallback to `${CI_COMMIT_TAG}` in GitLab)
- `quay.io/cloudflavor/leaf:latest`

Both tags are published as a multi-arch manifest list.

Local pipeline emulation with `opal`:

```bash
opal run --no-tui
```

## Internet Exposure

Use `PRODUCTION_READINESS.md` as the deployment checklist before public cutover.

Minimum production expectations:

- Run as non-root.
- Bind port 53 via `CAP_NET_BIND_SERVICE` instead of root.
- Expose only `53/udp` and `53/tcp`.
- Validate behavior from external networks using `dig`.
- Verify limiter and timeout behavior under load before full delegation.

## Current Scope and Limitations

- Shared TTL/SOA/limit settings across all configured zones.
- IPv4 `A` synthesis only.
- No recursive resolution.
- No DNSSEC implementation.
- No built-in metrics endpoint yet.

## License

Apache-2.0. See [LICENSE](LICENSE).
