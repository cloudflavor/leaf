# leaf

[![Docker Repository on Quay](https://quay.io/repository/cloudflavor/leaf/status "Docker Repository on Quay")](https://quay.io/repository/cloudflavor/leaf)  

`leaf` is an authoritative DNS server for nip.io-style hostnames, implemented in Rust and hardened for internet-facing deployment.

It serves deterministic `A` records from encoded IPv4 names inside a configured zone, for example:

- `1-2-3-4.dev.example.com` -> `1.2.3.4`
- `api.10-11-12-13.dev.example.com` -> `10.11.12.13`
- `1.2.3.4.dev.example.com` -> `1.2.3.4`

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
```

Notes:

- Top-level flat keys are still accepted for backward compatibility.
- If `dns.zone_ns`/`dns.zone_hostmaster` are omitted, defaults are derived per zone (`ns1.<zone>`, `hostmaster.<zone>`).

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

## CI/CD

The GitLab pipeline (`.gitlab-ci.yml`) contains:

- `cargo_fmt`
- `cargo_check`
- `cargo_clippy`
- `cargo_test`
- `cargo_test_extended`
- `release` job (tag-only) that builds release binary and publishes `dist/leaf` artifact
- `container_release` job (tag-only) that builds from `Containerfile` and pushes to Quay

Quay publish job requires these CI/CD variables:

- `QUAY_USERNAME`
- `QUAY_PASSWORD`

Image destination defaults to:

- `quay.io/cloudflavor/leaf:${GIT_COMMIT_TAG}` (fallback to `${CI_COMMIT_TAG}` in GitLab)
- `quay.io/cloudflavor/leaf:latest`

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
