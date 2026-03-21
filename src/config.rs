use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use hickory_proto::rr::Name;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "leaf", about = "Authoritative DNS for nip.io-style hostnames")]
pub struct Cli {
    #[structopt(long, env = "LEAF_ZONE")]
    zone: String,

    #[structopt(long, env = "LEAF_LISTEN", default_value = "0.0.0.0:5300")]
    listen: SocketAddr,

    #[structopt(long, env = "LEAF_TTL", default_value = "60")]
    ttl: u32,

    #[structopt(long, env = "LEAF_ZONE_NS")]
    zone_ns: Option<String>,

    #[structopt(long, env = "LEAF_ZONE_HOSTMASTER")]
    zone_hostmaster: Option<String>,

    #[structopt(long, env = "LEAF_SOA_SERIAL", default_value = "1")]
    soa_serial: u32,

    #[structopt(long, env = "LEAF_SOA_REFRESH", default_value = "300")]
    soa_refresh: u32,

    #[structopt(long, env = "LEAF_SOA_RETRY", default_value = "60")]
    soa_retry: u32,

    #[structopt(long, env = "LEAF_SOA_EXPIRE", default_value = "86400")]
    soa_expire: u32,

    #[structopt(long, env = "LEAF_SOA_MINIMUM", default_value = "60")]
    soa_minimum: u32,

    #[structopt(long, env = "LEAF_GLOBAL_QPS_LIMIT", default_value = "5000")]
    global_qps_limit: u32,

    #[structopt(long, env = "LEAF_PER_IP_QPS_LIMIT", default_value = "200")]
    per_ip_qps_limit: u32,

    #[structopt(long, env = "LEAF_LIMITER_MAX_TRACKED_IPS", default_value = "10000")]
    limiter_max_tracked_ips: usize,

    #[structopt(long, env = "LEAF_TCP_MAX_CONNECTIONS", default_value = "1024")]
    tcp_max_connections: usize,

    #[structopt(long, env = "LEAF_TCP_MAX_CONNECTIONS_PER_IP", default_value = "64")]
    tcp_max_connections_per_ip: usize,

    #[structopt(long, env = "LEAF_TCP_IDLE_TIMEOUT_MS", default_value = "10000")]
    tcp_idle_timeout_ms: u64,

    #[structopt(long, env = "LEAF_TCP_READ_TIMEOUT_MS", default_value = "3000")]
    tcp_read_timeout_ms: u64,

    #[structopt(long, env = "LEAF_TCP_WRITE_TIMEOUT_MS", default_value = "3000")]
    tcp_write_timeout_ms: u64,

    #[structopt(long, env = "LEAF_MAX_TCP_FRAME_BYTES", default_value = "4096")]
    max_tcp_frame_bytes: u32,

    #[structopt(long, env = "LEAF_MAX_UDP_REQUEST_BYTES", default_value = "1232")]
    max_udp_request_bytes: u32,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub zone: Name,
    pub listen: SocketAddr,
    pub answer_ttl: u32,
    pub zone_ns: Name,
    pub zone_hostmaster: Name,
    pub soa: SoaConfig,
    pub limits: LimitsConfig,
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
    pub limiter_max_tracked_ips: usize,
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
        Cli::from_args().try_into()
    }
}

impl TryFrom<Cli> for Config {
    type Error = io::Error;

    fn try_from(cli: Cli) -> Result<Self, Self::Error> {
        let zone = normalize_zone_name(&cli.zone)
            .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?;

        let zone_ns = normalize_domain_name(
            cli.zone_ns
                .unwrap_or_else(|| format!("ns1.{}", zone.to_utf8()))
                .as_str(),
            "zone-ns",
        )
        .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?;

        let zone_hostmaster = normalize_domain_name(
            cli.zone_hostmaster
                .unwrap_or_else(|| format!("hostmaster.{}", zone.to_utf8()))
                .as_str(),
            "zone-hostmaster",
        )
        .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?;

        if cli.ttl == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ttl must be > 0",
            ));
        }

        if cli.soa_minimum == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "soa-minimum must be > 0",
            ));
        }

        if cli.per_ip_qps_limit == 0 || cli.global_qps_limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "rate limits must be > 0",
            ));
        }

        if cli.tcp_max_connections == 0 || cli.tcp_max_connections_per_ip == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tcp connection limits must be > 0",
            ));
        }

        if cli.tcp_max_connections_per_ip > cli.tcp_max_connections {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tcp-max-connections-per-ip must be <= tcp-max-connections",
            ));
        }

        if cli.limiter_max_tracked_ips == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "limiter-max-tracked-ips must be > 0",
            ));
        }

        if cli.max_tcp_frame_bytes < 12 || cli.max_tcp_frame_bytes > u16::MAX as u32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "max-tcp-frame-bytes must be between 12 and 65535",
            ));
        }

        if cli.max_udp_request_bytes < 12 || cli.max_udp_request_bytes > 65535 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "max-udp-request-bytes must be between 12 and 65535",
            ));
        }

        if cli.tcp_idle_timeout_ms == 0
            || cli.tcp_read_timeout_ms == 0
            || cli.tcp_write_timeout_ms == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tcp timeouts must be > 0",
            ));
        }

        Ok(Self {
            zone,
            listen: cli.listen,
            answer_ttl: cli.ttl,
            zone_ns,
            zone_hostmaster,
            soa: SoaConfig {
                serial: cli.soa_serial,
                refresh: as_i32("soa-refresh", cli.soa_refresh)
                    .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?,
                retry: as_i32("soa-retry", cli.soa_retry)
                    .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?,
                expire: as_i32("soa-expire", cli.soa_expire)
                    .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?,
                minimum: cli.soa_minimum,
            },
            limits: LimitsConfig {
                global_qps_limit: cli.global_qps_limit,
                per_ip_qps_limit: cli.per_ip_qps_limit,
                limiter_max_tracked_ips: cli.limiter_max_tracked_ips,
                tcp_max_connections: cli.tcp_max_connections,
                tcp_max_connections_per_ip: cli.tcp_max_connections_per_ip,
                tcp_idle_timeout: Duration::from_millis(cli.tcp_idle_timeout_ms),
                tcp_read_timeout: Duration::from_millis(cli.tcp_read_timeout_ms),
                tcp_write_timeout: Duration::from_millis(cli.tcp_write_timeout_ms),
                max_tcp_frame_bytes: cli.max_tcp_frame_bytes as usize,
                max_udp_request_bytes: cli.max_udp_request_bytes as usize,
            },
        })
    }
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

fn as_i32(field_name: &str, value: u32) -> Result<i32, String> {
    i32::try_from(value).map_err(|_| format!("{field_name} exceeds i32::MAX"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_defaulted_config() {
        let config = Config::try_from(Cli {
            zone: "dev.example.com".to_string(),
            listen: "127.0.0.1:5300"
                .parse()
                .unwrap_or_else(|err| panic!("invalid socket addr: {err}")),
            ttl: 60,
            zone_ns: None,
            zone_hostmaster: None,
            soa_serial: 1,
            soa_refresh: 300,
            soa_retry: 60,
            soa_expire: 86400,
            soa_minimum: 60,
            global_qps_limit: 5000,
            per_ip_qps_limit: 200,
            limiter_max_tracked_ips: 1000,
            tcp_max_connections: 64,
            tcp_max_connections_per_ip: 16,
            tcp_idle_timeout_ms: 5000,
            tcp_read_timeout_ms: 1000,
            tcp_write_timeout_ms: 1000,
            max_tcp_frame_bytes: 4096,
            max_udp_request_bytes: 1232,
        })
        .unwrap_or_else(|err| panic!("expected config to parse: {err}"));

        assert_eq!(config.zone.to_utf8(), "dev.example.com.");
        assert_eq!(config.zone_ns.to_utf8(), "ns1.dev.example.com.");
        assert_eq!(
            config.zone_hostmaster.to_utf8(),
            "hostmaster.dev.example.com."
        );
    }

    #[test]
    fn rejects_invalid_tcp_frame_size() {
        let result = Config::try_from(Cli {
            zone: "dev.example.com".to_string(),
            listen: "127.0.0.1:5300"
                .parse()
                .unwrap_or_else(|err| panic!("invalid socket addr: {err}")),
            ttl: 60,
            zone_ns: None,
            zone_hostmaster: None,
            soa_serial: 1,
            soa_refresh: 300,
            soa_retry: 60,
            soa_expire: 86400,
            soa_minimum: 60,
            global_qps_limit: 5000,
            per_ip_qps_limit: 200,
            limiter_max_tracked_ips: 1000,
            tcp_max_connections: 64,
            tcp_max_connections_per_ip: 16,
            tcp_idle_timeout_ms: 5000,
            tcp_read_timeout_ms: 1000,
            tcp_write_timeout_ms: 1000,
            max_tcp_frame_bytes: 8,
            max_udp_request_bytes: 1232,
        });

        assert!(result.is_err());
    }

    #[test]
    fn rejects_per_ip_connections_above_global() {
        let result = Config::try_from(Cli {
            zone: "dev.example.com".to_string(),
            listen: "127.0.0.1:5300"
                .parse()
                .unwrap_or_else(|err| panic!("invalid socket addr: {err}")),
            ttl: 60,
            zone_ns: None,
            zone_hostmaster: None,
            soa_serial: 1,
            soa_refresh: 300,
            soa_retry: 60,
            soa_expire: 86400,
            soa_minimum: 60,
            global_qps_limit: 5000,
            per_ip_qps_limit: 200,
            limiter_max_tracked_ips: 1000,
            tcp_max_connections: 32,
            tcp_max_connections_per_ip: 64,
            tcp_idle_timeout_ms: 5000,
            tcp_read_timeout_ms: 1000,
            tcp_write_timeout_ms: 1000,
            max_tcp_frame_bytes: 4096,
            max_udp_request_bytes: 1232,
        });

        assert!(result.is_err());
    }
}
