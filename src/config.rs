use std::env;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use hickory_proto::rr::Name;
use serde::Deserialize;
use structopt::StructOpt;

const DEFAULT_LISTEN: &str = "0.0.0.0:5300";
const DEFAULT_TTL: u32 = 60;
const DEFAULT_SOA_SERIAL: u32 = 1;
const DEFAULT_SOA_REFRESH: u32 = 300;
const DEFAULT_SOA_RETRY: u32 = 60;
const DEFAULT_SOA_EXPIRE: u32 = 86400;
const DEFAULT_SOA_MINIMUM: u32 = 60;
const DEFAULT_GLOBAL_QPS_LIMIT: u32 = 5000;
const DEFAULT_PER_IP_QPS_LIMIT: u32 = 200;
const DEFAULT_PER_IP_INVALID_QNAME_QPS_LIMIT: u32 = 20;
const DEFAULT_LIMITER_MAX_TRACKED_IPS: usize = 10000;
const DEFAULT_INVALID_QNAME_LIMITER_MAX_TRACKED_KEYS: usize = 50000;
const DEFAULT_TCP_MAX_CONNECTIONS: usize = 1024;
const DEFAULT_TCP_MAX_CONNECTIONS_PER_IP: usize = 64;
const DEFAULT_TCP_IDLE_TIMEOUT_MS: u64 = 10000;
const DEFAULT_TCP_READ_TIMEOUT_MS: u64 = 3000;
const DEFAULT_TCP_WRITE_TIMEOUT_MS: u64 = 3000;
const DEFAULT_MAX_TCP_FRAME_BYTES: u32 = 4096;
const DEFAULT_MAX_UDP_REQUEST_BYTES: u32 = 1232;

#[derive(Debug, StructOpt, Clone, Default)]
#[structopt(name = "leaf", about = "Authoritative DNS for nip.io-style hostnames")]
pub struct Cli {
    #[structopt(long)]
    config: Option<PathBuf>,

    #[structopt(long = "zone", use_delimiter = true)]
    zones: Vec<String>,

    #[structopt(long)]
    listen: Option<SocketAddr>,

    #[structopt(long)]
    ttl: Option<u32>,

    #[structopt(long = "zone-ns")]
    zone_ns: Option<String>,

    #[structopt(long = "zone-hostmaster")]
    zone_hostmaster: Option<String>,

    #[structopt(long = "soa-serial")]
    soa_serial: Option<u32>,

    #[structopt(long = "soa-refresh")]
    soa_refresh: Option<u32>,

    #[structopt(long = "soa-retry")]
    soa_retry: Option<u32>,

    #[structopt(long = "soa-expire")]
    soa_expire: Option<u32>,

    #[structopt(long = "soa-minimum")]
    soa_minimum: Option<u32>,

    #[structopt(long = "global-qps-limit")]
    global_qps_limit: Option<u32>,

    #[structopt(long = "per-ip-qps-limit")]
    per_ip_qps_limit: Option<u32>,

    #[structopt(long = "per-ip-invalid-qname-qps-limit")]
    per_ip_invalid_qname_qps_limit: Option<u32>,

    #[structopt(long = "limiter-max-tracked-ips")]
    limiter_max_tracked_ips: Option<usize>,

    #[structopt(long = "invalid-qname-limiter-max-tracked-keys")]
    invalid_qname_limiter_max_tracked_keys: Option<usize>,

    #[structopt(long = "tcp-max-connections")]
    tcp_max_connections: Option<usize>,

    #[structopt(long = "tcp-max-connections-per-ip")]
    tcp_max_connections_per_ip: Option<usize>,

    #[structopt(long = "tcp-idle-timeout-ms")]
    tcp_idle_timeout_ms: Option<u64>,

    #[structopt(long = "tcp-read-timeout-ms")]
    tcp_read_timeout_ms: Option<u64>,

    #[structopt(long = "tcp-write-timeout-ms")]
    tcp_write_timeout_ms: Option<u64>,

    #[structopt(long = "max-tcp-frame-bytes")]
    max_tcp_frame_bytes: Option<u32>,

    #[structopt(long = "max-udp-request-bytes")]
    max_udp_request_bytes: Option<u32>,
}

#[derive(Debug, Clone, Default)]
struct EnvConfig {
    config: Option<PathBuf>,
    zones: Vec<String>,
    listen: Option<SocketAddr>,
    ttl: Option<u32>,
    zone_ns: Option<String>,
    zone_hostmaster: Option<String>,
    soa_serial: Option<u32>,
    soa_refresh: Option<u32>,
    soa_retry: Option<u32>,
    soa_expire: Option<u32>,
    soa_minimum: Option<u32>,
    global_qps_limit: Option<u32>,
    per_ip_qps_limit: Option<u32>,
    per_ip_invalid_qname_qps_limit: Option<u32>,
    limiter_max_tracked_ips: Option<usize>,
    invalid_qname_limiter_max_tracked_keys: Option<usize>,
    tcp_max_connections: Option<usize>,
    tcp_max_connections_per_ip: Option<usize>,
    tcp_idle_timeout_ms: Option<u64>,
    tcp_read_timeout_ms: Option<u64>,
    tcp_write_timeout_ms: Option<u64>,
    max_tcp_frame_bytes: Option<u32>,
    max_udp_request_bytes: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct FileConfig {
    zone: Option<String>,
    zones: Option<Vec<String>>,
    listen: Option<SocketAddr>,
    ttl: Option<u32>,
    zone_ns: Option<String>,
    zone_hostmaster: Option<String>,
    soa_serial: Option<u32>,
    soa_refresh: Option<u32>,
    soa_retry: Option<u32>,
    soa_expire: Option<u32>,
    soa_minimum: Option<u32>,
    global_qps_limit: Option<u32>,
    per_ip_qps_limit: Option<u32>,
    per_ip_invalid_qname_qps_limit: Option<u32>,
    limiter_max_tracked_ips: Option<usize>,
    invalid_qname_limiter_max_tracked_keys: Option<usize>,
    tcp_max_connections: Option<usize>,
    tcp_max_connections_per_ip: Option<usize>,
    tcp_idle_timeout_ms: Option<u64>,
    tcp_read_timeout_ms: Option<u64>,
    tcp_write_timeout_ms: Option<u64>,
    max_tcp_frame_bytes: Option<u32>,
    max_udp_request_bytes: Option<u32>,
    dns: Option<FileDnsConfig>,
    soa: Option<FileSoaConfig>,
    limits: Option<FileLimitsConfig>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct FileDnsConfig {
    ttl: Option<u32>,
    zone_ns: Option<String>,
    zone_hostmaster: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct FileSoaConfig {
    serial: Option<u32>,
    refresh: Option<u32>,
    retry: Option<u32>,
    expire: Option<u32>,
    minimum: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct FileLimitsConfig {
    global_qps_limit: Option<u32>,
    per_ip_qps_limit: Option<u32>,
    per_ip_invalid_qname_qps_limit: Option<u32>,
    limiter_max_tracked_ips: Option<usize>,
    invalid_qname_limiter_max_tracked_keys: Option<usize>,
    tcp_max_connections: Option<usize>,
    tcp_max_connections_per_ip: Option<usize>,
    tcp_idle_timeout_ms: Option<u64>,
    tcp_read_timeout_ms: Option<u64>,
    tcp_write_timeout_ms: Option<u64>,
    max_tcp_frame_bytes: Option<u32>,
    max_udp_request_bytes: Option<u32>,
}

#[derive(Debug, Clone, Default)]
struct RawConfigInputs {
    zones: Vec<String>,
    listen: Option<SocketAddr>,
    ttl: Option<u32>,
    zone_ns: Option<String>,
    zone_hostmaster: Option<String>,
    soa_serial: Option<u32>,
    soa_refresh: Option<u32>,
    soa_retry: Option<u32>,
    soa_expire: Option<u32>,
    soa_minimum: Option<u32>,
    global_qps_limit: Option<u32>,
    per_ip_qps_limit: Option<u32>,
    per_ip_invalid_qname_qps_limit: Option<u32>,
    limiter_max_tracked_ips: Option<usize>,
    invalid_qname_limiter_max_tracked_keys: Option<usize>,
    tcp_max_connections: Option<usize>,
    tcp_max_connections_per_ip: Option<usize>,
    tcp_idle_timeout_ms: Option<u64>,
    tcp_read_timeout_ms: Option<u64>,
    tcp_write_timeout_ms: Option<u64>,
    max_tcp_frame_bytes: Option<u32>,
    max_udp_request_bytes: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub zones: Vec<ZoneConfig>,
    pub listen: SocketAddr,
    pub limits: LimitsConfig,
}

#[derive(Debug, Clone)]
pub struct ZoneConfig {
    pub zone: Name,
    pub answer_ttl: u32,
    pub zone_ns: Name,
    pub zone_hostmaster: Name,
    pub soa: SoaConfig,
}

#[derive(Debug, Clone)]
pub struct SoaConfig {
    pub serial: u32,
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum: u32,
}

#[derive(Debug, Clone)]
pub struct LimitsConfig {
    pub global_qps_limit: u32,
    pub per_ip_qps_limit: u32,
    pub per_ip_invalid_qname_qps_limit: u32,
    pub limiter_max_tracked_ips: usize,
    pub invalid_qname_limiter_max_tracked_keys: usize,
    pub tcp_max_connections: usize,
    pub tcp_max_connections_per_ip: usize,
    pub tcp_idle_timeout: Duration,
    pub tcp_read_timeout: Duration,
    pub tcp_write_timeout: Duration,
    pub max_tcp_frame_bytes: usize,
    pub max_udp_request_bytes: usize,
}

impl Config {
    pub fn from_args() -> Result<Self, io::Error> {
        let cli = Cli::from_args();
        let env_config = EnvConfig::from_env()?;
        let file_path = resolve_config_path(&cli, &env_config);
        let file_config = load_file_config(file_path.as_deref())?;

        let merged = merge_inputs(cli, env_config, file_config);
        merged.try_into()
    }
}

impl EnvConfig {
    fn from_env() -> Result<Self, io::Error> {
        Ok(Self {
            config: env::var_os("LEAF_CONFIG").map(PathBuf::from),
            zones: parse_zones_from_env()?,
            listen: parse_env("LEAF_LISTEN")?,
            ttl: parse_env("LEAF_TTL")?,
            zone_ns: env::var("LEAF_ZONE_NS").ok(),
            zone_hostmaster: env::var("LEAF_ZONE_HOSTMASTER").ok(),
            soa_serial: parse_env("LEAF_SOA_SERIAL")?,
            soa_refresh: parse_env("LEAF_SOA_REFRESH")?,
            soa_retry: parse_env("LEAF_SOA_RETRY")?,
            soa_expire: parse_env("LEAF_SOA_EXPIRE")?,
            soa_minimum: parse_env("LEAF_SOA_MINIMUM")?,
            global_qps_limit: parse_env("LEAF_GLOBAL_QPS_LIMIT")?,
            per_ip_qps_limit: parse_env("LEAF_PER_IP_QPS_LIMIT")?,
            per_ip_invalid_qname_qps_limit: parse_env("LEAF_PER_IP_INVALID_QNAME_QPS_LIMIT")?,
            limiter_max_tracked_ips: parse_env("LEAF_LIMITER_MAX_TRACKED_IPS")?,
            invalid_qname_limiter_max_tracked_keys: parse_env(
                "LEAF_INVALID_QNAME_LIMITER_MAX_TRACKED_KEYS",
            )?,
            tcp_max_connections: parse_env("LEAF_TCP_MAX_CONNECTIONS")?,
            tcp_max_connections_per_ip: parse_env("LEAF_TCP_MAX_CONNECTIONS_PER_IP")?,
            tcp_idle_timeout_ms: parse_env("LEAF_TCP_IDLE_TIMEOUT_MS")?,
            tcp_read_timeout_ms: parse_env("LEAF_TCP_READ_TIMEOUT_MS")?,
            tcp_write_timeout_ms: parse_env("LEAF_TCP_WRITE_TIMEOUT_MS")?,
            max_tcp_frame_bytes: parse_env("LEAF_MAX_TCP_FRAME_BYTES")?,
            max_udp_request_bytes: parse_env("LEAF_MAX_UDP_REQUEST_BYTES")?,
        })
    }
}

impl TryFrom<RawConfigInputs> for Config {
    type Error = io::Error;

    fn try_from(raw: RawConfigInputs) -> Result<Self, Self::Error> {
        let listen = raw
            .listen
            .unwrap_or(parse_socket_addr(DEFAULT_LISTEN, "listen default")?);
        let ttl = raw.ttl.unwrap_or(DEFAULT_TTL);
        let soa_serial = raw.soa_serial.unwrap_or(DEFAULT_SOA_SERIAL);
        let soa_refresh = raw.soa_refresh.unwrap_or(DEFAULT_SOA_REFRESH);
        let soa_retry = raw.soa_retry.unwrap_or(DEFAULT_SOA_RETRY);
        let soa_expire = raw.soa_expire.unwrap_or(DEFAULT_SOA_EXPIRE);
        let soa_minimum = raw.soa_minimum.unwrap_or(DEFAULT_SOA_MINIMUM);
        let global_qps_limit = raw.global_qps_limit.unwrap_or(DEFAULT_GLOBAL_QPS_LIMIT);
        let per_ip_qps_limit = raw.per_ip_qps_limit.unwrap_or(DEFAULT_PER_IP_QPS_LIMIT);
        let per_ip_invalid_qname_qps_limit = raw
            .per_ip_invalid_qname_qps_limit
            .unwrap_or(DEFAULT_PER_IP_INVALID_QNAME_QPS_LIMIT);
        let limiter_max_tracked_ips = raw
            .limiter_max_tracked_ips
            .unwrap_or(DEFAULT_LIMITER_MAX_TRACKED_IPS);
        let invalid_qname_limiter_max_tracked_keys = raw
            .invalid_qname_limiter_max_tracked_keys
            .unwrap_or(DEFAULT_INVALID_QNAME_LIMITER_MAX_TRACKED_KEYS);
        let tcp_max_connections = raw
            .tcp_max_connections
            .unwrap_or(DEFAULT_TCP_MAX_CONNECTIONS);
        let tcp_max_connections_per_ip = raw
            .tcp_max_connections_per_ip
            .unwrap_or(DEFAULT_TCP_MAX_CONNECTIONS_PER_IP);
        let tcp_idle_timeout_ms = raw
            .tcp_idle_timeout_ms
            .unwrap_or(DEFAULT_TCP_IDLE_TIMEOUT_MS);
        let tcp_read_timeout_ms = raw
            .tcp_read_timeout_ms
            .unwrap_or(DEFAULT_TCP_READ_TIMEOUT_MS);
        let tcp_write_timeout_ms = raw
            .tcp_write_timeout_ms
            .unwrap_or(DEFAULT_TCP_WRITE_TIMEOUT_MS);
        let max_tcp_frame_bytes = raw
            .max_tcp_frame_bytes
            .unwrap_or(DEFAULT_MAX_TCP_FRAME_BYTES);
        let max_udp_request_bytes = raw
            .max_udp_request_bytes
            .unwrap_or(DEFAULT_MAX_UDP_REQUEST_BYTES);

        if ttl == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ttl must be > 0",
            ));
        }

        if soa_minimum == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "soa-minimum must be > 0",
            ));
        }

        if per_ip_qps_limit == 0 || global_qps_limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "rate limits must be > 0",
            ));
        }

        if per_ip_invalid_qname_qps_limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "per-ip-invalid-qname-qps-limit must be > 0",
            ));
        }

        if tcp_max_connections == 0 || tcp_max_connections_per_ip == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tcp connection limits must be > 0",
            ));
        }

        if tcp_max_connections_per_ip > tcp_max_connections {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tcp-max-connections-per-ip must be <= tcp-max-connections",
            ));
        }

        if limiter_max_tracked_ips == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "limiter-max-tracked-ips must be > 0",
            ));
        }

        if invalid_qname_limiter_max_tracked_keys == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid-qname-limiter-max-tracked-keys must be > 0",
            ));
        }

        if !(12..=u16::MAX as u32).contains(&max_tcp_frame_bytes) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "max-tcp-frame-bytes must be between 12 and 65535",
            ));
        }

        if !(12..=65535).contains(&max_udp_request_bytes) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "max-udp-request-bytes must be between 12 and 65535",
            ));
        }

        if tcp_idle_timeout_ms == 0 || tcp_read_timeout_ms == 0 || tcp_write_timeout_ms == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tcp timeouts must be > 0",
            ));
        }

        let mut zones = Vec::with_capacity(raw.zones.len());
        for zone_raw in &raw.zones {
            let zone = normalize_zone_name(zone_raw)
                .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?;
            if zones.iter().any(|existing: &Name| existing == &zone) {
                continue;
            }
            zones.push(zone);
        }

        if zones.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at least one zone is required (set --zone, LEAF_ZONE/LEAF_ZONES, or zone/zones in leaf.toml)",
            ));
        }

        let soa = SoaConfig {
            serial: soa_serial,
            refresh: as_i32("soa-refresh", soa_refresh)
                .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?,
            retry: as_i32("soa-retry", soa_retry)
                .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?,
            expire: as_i32("soa-expire", soa_expire)
                .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?,
            minimum: soa_minimum,
        };

        let zone_ns_override = raw.zone_ns.clone();
        let zone_hostmaster_override = raw.zone_hostmaster.clone();
        let mut zone_configs = Vec::with_capacity(zones.len());
        for zone in zones {
            let zone_ns_value = zone_ns_override
                .clone()
                .unwrap_or_else(|| format!("ns1.{}", zone.to_utf8()));
            let zone_ns = normalize_domain_name(&zone_ns_value, "zone-ns")
                .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?;

            let zone_hostmaster_value = zone_hostmaster_override
                .clone()
                .unwrap_or_else(|| format!("hostmaster.{}", zone.to_utf8()));
            let zone_hostmaster = normalize_domain_name(&zone_hostmaster_value, "zone-hostmaster")
                .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?;

            zone_configs.push(ZoneConfig {
                zone,
                answer_ttl: ttl,
                zone_ns,
                zone_hostmaster,
                soa: soa.clone(),
            });
        }

        Ok(Self {
            zones: zone_configs,
            listen,
            limits: LimitsConfig {
                global_qps_limit,
                per_ip_qps_limit,
                per_ip_invalid_qname_qps_limit,
                limiter_max_tracked_ips,
                invalid_qname_limiter_max_tracked_keys,
                tcp_max_connections,
                tcp_max_connections_per_ip,
                tcp_idle_timeout: Duration::from_millis(tcp_idle_timeout_ms),
                tcp_read_timeout: Duration::from_millis(tcp_read_timeout_ms),
                tcp_write_timeout: Duration::from_millis(tcp_write_timeout_ms),
                max_tcp_frame_bytes: max_tcp_frame_bytes as usize,
                max_udp_request_bytes: max_udp_request_bytes as usize,
            },
        })
    }
}

fn resolve_config_path(cli: &Cli, env_config: &EnvConfig) -> Option<PathBuf> {
    cli.config
        .clone()
        .or_else(|| env_config.config.clone())
        .or_else(|| {
            let default_path = PathBuf::from("leaf.toml");
            if default_path.exists() {
                Some(default_path)
            } else {
                None
            }
        })
}

fn load_file_config(path: Option<&Path>) -> Result<FileConfig, io::Error> {
    let Some(path) = path else {
        return Ok(FileConfig::default());
    };

    let contents = fs::read_to_string(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("failed reading config file '{}': {error}", path.display()),
        )
    })?;

    toml::from_str::<FileConfig>(&contents).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed parsing TOML config '{}': {error}", path.display()),
        )
    })
}

fn merge_inputs(cli: Cli, env_config: EnvConfig, file_config: FileConfig) -> RawConfigInputs {
    let file_dns = file_config.dns.as_ref();
    let file_soa = file_config.soa.as_ref();
    let file_limits = file_config.limits.as_ref();
    let file_zones = zones_from_file_config(&file_config);
    RawConfigInputs {
        zones: pick_zones(cli.zones, env_config.zones, file_zones),
        listen: pick(cli.listen, env_config.listen, file_config.listen),
        ttl: pick(
            cli.ttl,
            env_config.ttl,
            file_config.ttl.or_else(|| file_dns.and_then(|dns| dns.ttl)),
        ),
        zone_ns: pick(
            cli.zone_ns,
            env_config.zone_ns,
            file_config
                .zone_ns
                .clone()
                .or_else(|| file_dns.and_then(|dns| dns.zone_ns.clone())),
        ),
        zone_hostmaster: pick(
            cli.zone_hostmaster,
            env_config.zone_hostmaster,
            file_config
                .zone_hostmaster
                .clone()
                .or_else(|| file_dns.and_then(|dns| dns.zone_hostmaster.clone())),
        ),
        soa_serial: pick(
            cli.soa_serial,
            env_config.soa_serial,
            file_config
                .soa_serial
                .or_else(|| file_soa.and_then(|soa| soa.serial)),
        ),
        soa_refresh: pick(
            cli.soa_refresh,
            env_config.soa_refresh,
            file_config
                .soa_refresh
                .or_else(|| file_soa.and_then(|soa| soa.refresh)),
        ),
        soa_retry: pick(
            cli.soa_retry,
            env_config.soa_retry,
            file_config
                .soa_retry
                .or_else(|| file_soa.and_then(|soa| soa.retry)),
        ),
        soa_expire: pick(
            cli.soa_expire,
            env_config.soa_expire,
            file_config
                .soa_expire
                .or_else(|| file_soa.and_then(|soa| soa.expire)),
        ),
        soa_minimum: pick(
            cli.soa_minimum,
            env_config.soa_minimum,
            file_config
                .soa_minimum
                .or_else(|| file_soa.and_then(|soa| soa.minimum)),
        ),
        global_qps_limit: pick(
            cli.global_qps_limit,
            env_config.global_qps_limit,
            file_config
                .global_qps_limit
                .or_else(|| file_limits.and_then(|limits| limits.global_qps_limit)),
        ),
        per_ip_qps_limit: pick(
            cli.per_ip_qps_limit,
            env_config.per_ip_qps_limit,
            file_config
                .per_ip_qps_limit
                .or_else(|| file_limits.and_then(|limits| limits.per_ip_qps_limit)),
        ),
        per_ip_invalid_qname_qps_limit: pick(
            cli.per_ip_invalid_qname_qps_limit,
            env_config.per_ip_invalid_qname_qps_limit,
            file_config
                .per_ip_invalid_qname_qps_limit
                .or_else(|| file_limits.and_then(|limits| limits.per_ip_invalid_qname_qps_limit)),
        ),
        limiter_max_tracked_ips: pick(
            cli.limiter_max_tracked_ips,
            env_config.limiter_max_tracked_ips,
            file_config
                .limiter_max_tracked_ips
                .or_else(|| file_limits.and_then(|limits| limits.limiter_max_tracked_ips)),
        ),
        invalid_qname_limiter_max_tracked_keys: pick(
            cli.invalid_qname_limiter_max_tracked_keys,
            env_config.invalid_qname_limiter_max_tracked_keys,
            file_config
                .invalid_qname_limiter_max_tracked_keys
                .or_else(|| {
                    file_limits.and_then(|limits| limits.invalid_qname_limiter_max_tracked_keys)
                }),
        ),
        tcp_max_connections: pick(
            cli.tcp_max_connections,
            env_config.tcp_max_connections,
            file_config
                .tcp_max_connections
                .or_else(|| file_limits.and_then(|limits| limits.tcp_max_connections)),
        ),
        tcp_max_connections_per_ip: pick(
            cli.tcp_max_connections_per_ip,
            env_config.tcp_max_connections_per_ip,
            file_config
                .tcp_max_connections_per_ip
                .or_else(|| file_limits.and_then(|limits| limits.tcp_max_connections_per_ip)),
        ),
        tcp_idle_timeout_ms: pick(
            cli.tcp_idle_timeout_ms,
            env_config.tcp_idle_timeout_ms,
            file_config
                .tcp_idle_timeout_ms
                .or_else(|| file_limits.and_then(|limits| limits.tcp_idle_timeout_ms)),
        ),
        tcp_read_timeout_ms: pick(
            cli.tcp_read_timeout_ms,
            env_config.tcp_read_timeout_ms,
            file_config
                .tcp_read_timeout_ms
                .or_else(|| file_limits.and_then(|limits| limits.tcp_read_timeout_ms)),
        ),
        tcp_write_timeout_ms: pick(
            cli.tcp_write_timeout_ms,
            env_config.tcp_write_timeout_ms,
            file_config
                .tcp_write_timeout_ms
                .or_else(|| file_limits.and_then(|limits| limits.tcp_write_timeout_ms)),
        ),
        max_tcp_frame_bytes: pick(
            cli.max_tcp_frame_bytes,
            env_config.max_tcp_frame_bytes,
            file_config
                .max_tcp_frame_bytes
                .or_else(|| file_limits.and_then(|limits| limits.max_tcp_frame_bytes)),
        ),
        max_udp_request_bytes: pick(
            cli.max_udp_request_bytes,
            env_config.max_udp_request_bytes,
            file_config
                .max_udp_request_bytes
                .or_else(|| file_limits.and_then(|limits| limits.max_udp_request_bytes)),
        ),
    }
}

fn pick<T>(cli: Option<T>, env: Option<T>, file: Option<T>) -> Option<T> {
    cli.or(env).or(file)
}

fn pick_zones(cli: Vec<String>, env: Vec<String>, file: Vec<String>) -> Vec<String> {
    if !cli.is_empty() {
        return cli;
    }
    if !env.is_empty() {
        return env;
    }
    file
}

fn zones_from_file_config(file_config: &FileConfig) -> Vec<String> {
    if let Some(zones) = &file_config.zones
        && !zones.is_empty()
    {
        return zones.clone();
    }

    file_config
        .zone
        .as_ref()
        .map_or_else(Vec::new, |zone| vec![zone.clone()])
}

fn parse_env<T>(name: &str) -> Result<Option<T>, io::Error>
where
    T: FromStr,
    <T as FromStr>::Err: std::fmt::Display,
{
    match env::var(name) {
        Ok(value) => value.parse::<T>().map(Some).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid {name} value '{value}': {error}"),
            )
        }),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} is not valid unicode"),
        )),
    }
}

fn parse_zones_from_env() -> Result<Vec<String>, io::Error> {
    let mut zones = Vec::new();

    if let Ok(list) = env::var("LEAF_ZONES") {
        zones.extend(parse_zone_list(&list));
    }

    if let Ok(single_zone) = env::var("LEAF_ZONE")
        && !single_zone.trim().is_empty()
    {
        zones.push(single_zone.trim().to_string());
    }

    Ok(zones)
}

fn parse_zone_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

fn normalize_zone_name(zone: &str) -> Result<Name, String> {
    normalize_domain_name(zone, "zone")
}

fn normalize_domain_name(domain: &str, field_name: &str) -> Result<Name, String> {
    let trimmed = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() {
        return Err(format!("{field_name} cannot be empty"));
    }

    Name::from_ascii(format!("{trimmed}."))
        .map_err(|error| format!("invalid {field_name} '{domain}': {error}"))
}

fn parse_socket_addr(input: &str, field_name: &str) -> Result<SocketAddr, io::Error> {
    input.parse::<SocketAddr>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid {field_name} '{input}': {error}"),
        )
    })
}

fn as_i32(field_name: &str, value: u32) -> Result<i32, String> {
    i32::try_from(value).map_err(|_| format!("{field_name} exceeds i32::MAX"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_inputs() -> RawConfigInputs {
        RawConfigInputs {
            zones: vec!["dev.example.com".to_string()],
            listen: Some(
                "127.0.0.1:5300"
                    .parse()
                    .unwrap_or_else(|err| panic!("invalid socket addr: {err}")),
            ),
            ttl: Some(60),
            zone_ns: None,
            zone_hostmaster: None,
            soa_serial: Some(1),
            soa_refresh: Some(300),
            soa_retry: Some(60),
            soa_expire: Some(86400),
            soa_minimum: Some(60),
            global_qps_limit: Some(5000),
            per_ip_qps_limit: Some(200),
            per_ip_invalid_qname_qps_limit: Some(20),
            limiter_max_tracked_ips: Some(1000),
            invalid_qname_limiter_max_tracked_keys: Some(1000),
            tcp_max_connections: Some(64),
            tcp_max_connections_per_ip: Some(16),
            tcp_idle_timeout_ms: Some(5000),
            tcp_read_timeout_ms: Some(1000),
            tcp_write_timeout_ms: Some(1000),
            max_tcp_frame_bytes: Some(4096),
            max_udp_request_bytes: Some(1232),
        }
    }

    #[test]
    fn accepts_defaulted_config() {
        let config = Config::try_from(valid_inputs())
            .unwrap_or_else(|err| panic!("expected config to parse: {err}"));

        assert_eq!(config.zones.len(), 1);
        assert_eq!(config.zones[0].zone.to_utf8(), "dev.example.com.");
        assert_eq!(config.zones[0].zone_ns.to_utf8(), "ns1.dev.example.com.");
        assert_eq!(
            config.zones[0].zone_hostmaster.to_utf8(),
            "hostmaster.dev.example.com."
        );
    }

    #[test]
    fn supports_multiple_zones_with_per_zone_defaults() {
        let mut inputs = valid_inputs();
        inputs.zones = vec![
            "dev.example.com".to_string(),
            "prod.example.com".to_string(),
        ];
        let config = Config::try_from(inputs)
            .unwrap_or_else(|err| panic!("expected config to parse: {err}"));

        assert_eq!(config.zones.len(), 2);
        assert_eq!(config.zones[0].zone.to_utf8(), "dev.example.com.");
        assert_eq!(config.zones[0].zone_ns.to_utf8(), "ns1.dev.example.com.");
        assert_eq!(config.zones[1].zone.to_utf8(), "prod.example.com.");
        assert_eq!(config.zones[1].zone_ns.to_utf8(), "ns1.prod.example.com.");
    }

    #[test]
    fn rejects_invalid_tcp_frame_size() {
        let mut inputs = valid_inputs();
        inputs.max_tcp_frame_bytes = Some(8);
        let result = Config::try_from(inputs);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_per_ip_connections_above_global() {
        let mut inputs = valid_inputs();
        inputs.tcp_max_connections = Some(32);
        inputs.tcp_max_connections_per_ip = Some(64);
        let result = Config::try_from(inputs);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_invalid_qname_qps_limit_zero() {
        let mut inputs = valid_inputs();
        inputs.per_ip_invalid_qname_qps_limit = Some(0);
        let result = Config::try_from(inputs);
        assert!(result.is_err());
    }

    #[test]
    fn merge_prefers_cli_over_env_over_file() {
        let cli = Cli {
            zones: vec!["cli.example.com".to_string()],
            ttl: Some(30),
            ..Cli::default()
        };
        let env = EnvConfig {
            zones: vec!["env.example.com".to_string()],
            ttl: Some(20),
            ..EnvConfig::default()
        };
        let file = FileConfig {
            zone: Some("file.example.com".to_string()),
            ttl: Some(10),
            ..FileConfig::default()
        };

        let merged = merge_inputs(cli, env, file.clone());
        assert_eq!(merged.zones, vec!["cli.example.com".to_string()]);
        assert_eq!(merged.ttl, Some(30));
    }

    #[test]
    fn merge_falls_back_to_env_then_file() {
        let cli = Cli::default();
        let env = EnvConfig {
            zones: vec!["env.example.com".to_string()],
            ttl: Some(20),
            ..EnvConfig::default()
        };
        let file = FileConfig {
            zones: Some(vec![
                "file1.example.com".to_string(),
                "file2.example.com".to_string(),
            ]),
            ttl: Some(10),
            ..FileConfig::default()
        };

        let merged = merge_inputs(cli, env, file.clone());
        assert_eq!(merged.zones, vec!["env.example.com".to_string()]);
        assert_eq!(merged.ttl, Some(20));

        let merged_file_only = merge_inputs(Cli::default(), EnvConfig::default(), file);
        assert_eq!(
            merged_file_only.zones,
            vec![
                "file1.example.com".to_string(),
                "file2.example.com".to_string()
            ]
        );
        assert_eq!(merged_file_only.ttl, Some(10));
    }

    #[test]
    fn loads_toml_config_file() {
        let mut path = std::env::temp_dir();
        path.push("leaf-config-test.toml");

        fs::write(
            &path,
            "zones = [\"dev.example.com\", \"prod.example.com\"]\nlisten = \"127.0.0.1:5301\"\nttl = 120\n",
        )
        .unwrap_or_else(|err| panic!("failed writing test config: {err}"));

        let loaded = load_file_config(Some(&path))
            .unwrap_or_else(|err| panic!("failed loading config file: {err}"));
        assert_eq!(
            loaded.zones,
            Some(vec![
                "dev.example.com".to_string(),
                "prod.example.com".to_string()
            ])
        );
        assert_eq!(
            loaded.listen,
            Some(
                "127.0.0.1:5301"
                    .parse()
                    .unwrap_or_else(|err| panic!("invalid socket addr: {err}"))
            )
        );
        assert_eq!(loaded.ttl, Some(120));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn merges_nested_toml_layout_into_raw_inputs() {
        let mut path = std::env::temp_dir();
        path.push("leaf-config-nested-test.toml");

        fs::write(
            &path,
            "zones = [\"dev.example.com\"]\n[dns]\nttl = 120\nzone_ns = \"ns9.dev.example.com\"\n[soa]\nserial = 7\nrefresh = 400\nretry = 90\nexpire = 90000\nminimum = 45\n[limits]\nglobal_qps_limit = 321\nper_ip_qps_limit = 111\nper_ip_invalid_qname_qps_limit = 22\nlimiter_max_tracked_ips = 555\ninvalid_qname_limiter_max_tracked_keys = 777\ntcp_max_connections = 333\ntcp_max_connections_per_ip = 44\ntcp_idle_timeout_ms = 9999\ntcp_read_timeout_ms = 2222\ntcp_write_timeout_ms = 3333\nmax_tcp_frame_bytes = 4097\nmax_udp_request_bytes = 1400\n",
        )
        .unwrap_or_else(|err| panic!("failed writing nested config: {err}"));

        let file = load_file_config(Some(&path))
            .unwrap_or_else(|err| panic!("failed loading nested config file: {err}"));
        let merged = merge_inputs(Cli::default(), EnvConfig::default(), file);

        assert_eq!(merged.zones, vec!["dev.example.com".to_string()]);
        assert_eq!(merged.ttl, Some(120));
        assert_eq!(merged.zone_ns, Some("ns9.dev.example.com".to_string()));
        assert_eq!(merged.soa_serial, Some(7));
        assert_eq!(merged.global_qps_limit, Some(321));
        assert_eq!(merged.max_udp_request_bytes, Some(1400));

        let _ = fs::remove_file(&path);
    }
}
