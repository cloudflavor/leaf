# Internet Exposure Guide: leaf Authoritative DNS

This document describes the current public-exposure posture of `leaf` and the exact deployment checklist to run it on the Internet safely.

## Implemented in Code

The server now includes the following protections and protocol behavior:

- Authoritative-only behavior for configured zone(s) (`AA` set only for in-zone answers).
- Strict DNS query validation:
  - non-`QUERY` opcodes return `NOTIMP`
  - multi-question requests return `FORMERR`
  - out-of-zone names return `REFUSED`
- Explicit `ANY` query policy: in-zone `ANY` queries return `REFUSED`.
- Apex authoritative records:
  - `SOA` responses at zone apex
  - `NS` responses at zone apex
- Negative caching behavior:
  - `NXDOMAIN` responses include zone `SOA` in authority section
  - `NODATA` responses include zone `SOA` in authority section
- UDP/TCP abuse controls:
  - global QPS limiter
  - per-IP QPS limiter
  - per-IP + qname invalid-query limiter (`NXDOMAIN`/`REFUSED`/`FORMERR`)
  - bounded tracked-IP table for rate limiting
  - bounded tracked key table for invalid-query throttling
  - global TCP connection cap
  - per-IP TCP connection cap
- TCP hardening:
  - idle/read/write timeouts
  - max framed request size bound
- UDP hardening:
  - max datagram request size bound
- Structured operational logs for startup and drop reasons (`rate_limited`, `invalid_query_rate_limited`, `request_too_large`, `parse_error`, `connection_limit_reached`).
- Optional per-query success logs (`udp_query`, `tcp_query`) controlled by config and minimized to avoid client identifiers.

## Runtime Configuration

All values are configurable via CLI flags or environment variables.
You can also load values from a TOML file via `--config` or `LEAF_CONFIG` (or `./leaf.toml` if present).

Core DNS:

- `LEAF_ZONES` (required unless `LEAF_ZONE` is set): comma-separated served zones, e.g. `dev.example.com,prod.example.com`
- `LEAF_ZONE` (optional): backward-compatible single-zone shortcut
- `LEAF_CONFIG` (optional): path to TOML config file
- `LEAF_LISTEN` (default `0.0.0.0:5300`)
- `LEAF_TTL` (default `60`)
- `LEAF_ZONE_NS` (default `ns1.<zone>`)
- `LEAF_ZONE_HOSTMASTER` (default `hostmaster.<zone>`)

SOA:

- `LEAF_SOA_SERIAL` (default `1`)
- `LEAF_SOA_REFRESH` (default `300`)
- `LEAF_SOA_RETRY` (default `60`)
- `LEAF_SOA_EXPIRE` (default `86400`)
- `LEAF_SOA_MINIMUM` (default `60`)

Traffic and connection controls:

- `LEAF_GLOBAL_QPS_LIMIT` (default `5000`)
- `LEAF_PER_IP_QPS_LIMIT` (default `200`)
- `LEAF_PER_IP_INVALID_QNAME_QPS_LIMIT` (default `20`)
- `LEAF_LIMITER_MAX_TRACKED_IPS` (default `10000`)
- `LEAF_INVALID_QNAME_LIMITER_MAX_TRACKED_KEYS` (default `50000`)
- `LEAF_TCP_MAX_CONNECTIONS` (default `1024`)
- `LEAF_TCP_MAX_CONNECTIONS_PER_IP` (default `64`)
- `LEAF_TCP_IDLE_TIMEOUT_MS` (default `10000`)
- `LEAF_TCP_READ_TIMEOUT_MS` (default `3000`)
- `LEAF_TCP_WRITE_TIMEOUT_MS` (default `3000`)
- `LEAF_MAX_TCP_FRAME_BYTES` (default `4096`)
- `LEAF_MAX_UDP_REQUEST_BYTES` (default `1232`)
- `LEAF_LOG_QUERIES` (default `false`)

## Go-Live Deployment Checklist

### 1. Run as Non-Root and Bind Port 53 Safely

Build binary:

```bash
cargo build --release
```

Allow binding low ports without root:

```bash
sudo setcap 'cap_net_bind_service=+ep' ./target/release/leaf
```

Run as dedicated user (example):

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin leaf
sudo -u leaf \
  LEAF_ZONES=dev.example.com,prod.example.com \
  LEAF_LISTEN=0.0.0.0:53 \
  ./target/release/leaf
```

### 1a. Podman Deployment Profile (Hetzner)

Build container image:

```bash
podman build -t leaf:latest -f Containerfile .
```

Run in container with minimum capabilities:

```bash
PUBLIC_IP=<your-public-ip>

sudo podman run -d --name leaf --restart=always \
  --read-only \
  --cap-drop=all \
  --cap-add=NET_BIND_SERVICE \
  -e LEAF_ZONES=dev.example.com,prod.example.com \
  -e LEAF_LISTEN=0.0.0.0:53 \
  -e LEAF_CONFIG=/etc/leaf/leaf.toml \
  -v ./leaf.toml:/etc/leaf/leaf.toml:ro \
  -p ${PUBLIC_IP}:53:53/udp \
  -p ${PUBLIC_IP}:53:53/tcp \
  leaf:latest
```

Notes:

- Rootful Podman is recommended for direct binding on host port `53`.
- Prefer binding published ports to the server public IP (not wildcard) to avoid host resolver/listener conflicts.
- Keep filesystem read-only except explicit mounted config/log paths.
- Validate startup logs after restart to confirm bind and config load.

### 2. Lock Down Firewall

Expose only DNS:

- allow `53/udp`
- allow `53/tcp`
- deny other inbound ports to this host

### 3. Delegate a Test Subzone First

Delegate a limited subzone (for example `canary.dev.example.com`) to this service before full-zone cutover.

### 4. Validate Authoritative Behavior

From an external network, verify:

```bash
dig @<server-ip> 1-2-3-4.dev.example.com A +norecurse
dig @<server-ip> dev.example.com SOA +norecurse
dig @<server-ip> dev.example.com NS +norecurse
dig @<server-ip> nope.dev.example.com A +norecurse
```

Expected outcomes:

- `A` query for encoded name returns `NOERROR` with one `A` answer.
- Apex `SOA` and `NS` return `NOERROR` with authoritative answers.
- Unknown in-zone name returns `NXDOMAIN` with `SOA` in authority section.

### 5. Validate Abuse Controls in Staging

- Burst per-IP traffic above configured limit and confirm throttling in logs.
- Open many TCP connections from one source and confirm cap enforcement.
- Send oversized TCP frames and confirm immediate drop.
- Confirm process remains stable under sustained mixed load.

### 6. Monitor and Alert

At minimum, alert on:

- process restarts
- sustained `rate_limited` events above baseline
- sustained `invalid_query_rate_limited` events above baseline
- sustained parse-error spikes
- socket bind/startup failures

## Residual Risks (Operational)

The binary-level controls are now in place, but public DNS operation still requires external safeguards:

- upstream anti-DDoS capacity (provider or edge filtering)
- multi-instance deployment for redundancy
- centralized log shipping and retention
- documented incident response playbooks for abuse spikes

Do not perform full-zone public cutover until the deployment checklist is complete and validated in staging.
