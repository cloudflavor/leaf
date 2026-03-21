mod config;
mod dns;
mod limits;

use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::ResponseCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::config::{Config, LimitsConfig};
use crate::dns::{BuiltResponse, DnsAuthority};
use crate::limits::{
    InvalidQueryRateLimiter, QueryRateLimiter, TcpConnectionLimiter, TcpConnectionPermit,
};

#[derive(Debug, Clone)]
struct RuntimeState {
    authority: Arc<DnsAuthority>,
    query_rate_limiter: QueryRateLimiter,
    invalid_query_rate_limiter: InvalidQueryRateLimiter,
    limits: LimitsConfig,
    query_log_enabled: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::from_args()?;

    let runtime = RuntimeState {
        authority: Arc::new(DnsAuthority::from_config(&config)),
        query_rate_limiter: QueryRateLimiter::new(
            config.limits.global_qps_limit,
            config.limits.per_ip_qps_limit,
            config.limits.limiter_max_tracked_ips,
        ),
        invalid_query_rate_limiter: InvalidQueryRateLimiter::new(
            config.limits.per_ip_invalid_qname_qps_limit,
            config.limits.invalid_qname_limiter_max_tracked_keys,
        ),
        limits: config.limits.clone(),
        query_log_enabled: config.query_log_enabled,
    };

    let tcp_connection_limiter = TcpConnectionLimiter::new(
        config.limits.tcp_max_connections,
        config.limits.tcp_max_connections_per_ip,
    );

    let udp_socket = UdpSocket::bind(config.listen).await?;
    let tcp_listener = TcpListener::bind(config.listen).await?;

    let zones = config
        .zones
        .iter()
        .map(|zone| zone.zone.to_utf8())
        .collect::<Vec<_>>()
        .join(",");

    eprintln!(
        "event=startup message='authoritative dns online' listen={} zones={} global_qps_limit={} per_ip_qps_limit={} per_ip_invalid_qname_qps_limit={} invalid_qname_limiter_max_tracked_keys={} tcp_max_connections={} tcp_max_connections_per_ip={} max_udp_request_bytes={} max_tcp_frame_bytes={}",
        config.listen,
        zones,
        config.limits.global_qps_limit,
        config.limits.per_ip_qps_limit,
        config.limits.per_ip_invalid_qname_qps_limit,
        config.limits.invalid_qname_limiter_max_tracked_keys,
        config.limits.tcp_max_connections,
        config.limits.tcp_max_connections_per_ip,
        config.limits.max_udp_request_bytes,
        config.limits.max_tcp_frame_bytes,
    );
    eprintln!(
        "event=startup message='query logging configuration' query_log_enabled={}",
        config.query_log_enabled
    );

    tokio::try_join!(
        run_udp(udp_socket, runtime.clone()),
        run_tcp(tcp_listener, runtime, tcp_connection_limiter),
    )?;

    Ok(())
}

async fn run_udp(socket: UdpSocket, runtime: RuntimeState) -> io::Result<()> {
    let mut buffer = vec![0_u8; runtime.limits.max_udp_request_bytes.saturating_add(1)];

    loop {
        let (received, peer) = socket.recv_from(&mut buffer).await?;

        if received > runtime.limits.max_udp_request_bytes {
            eprintln!(
                "event=udp_drop reason=request_too_large received_bytes={} limit_bytes={}",
                received, runtime.limits.max_udp_request_bytes
            );
            continue;
        }

        if !runtime.query_rate_limiter.allow(peer.ip()) {
            eprintln!("event=udp_drop reason=rate_limited");
            continue;
        }

        if let Some(response) = runtime.authority.build_response(&buffer[..received]) {
            if !allow_invalid_query_response(&runtime, peer.ip(), &response) {
                eprintln!(
                    "event=udp_drop reason=invalid_query_rate_limited rcode={:?}",
                    response.response_code
                );
                continue;
            }

            log_query_if_enabled(&runtime, "udp_query", &response, received);

            // Best effort; malformed peers should not terminate the server.
            let _ = socket.send_to(&response.wire_bytes, peer).await;
        } else {
            eprintln!("event=udp_drop reason=parse_error");
        }
    }
}

async fn run_tcp(
    listener: TcpListener,
    runtime: RuntimeState,
    tcp_connection_limiter: TcpConnectionLimiter,
) -> io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;

        let Some(connection_permit) = tcp_connection_limiter.try_acquire(peer.ip()) else {
            eprintln!("event=tcp_drop reason=connection_limit_reached");
            continue;
        };

        let runtime = runtime.clone();

        tokio::spawn(async move {
            if let Err(error) =
                handle_tcp_connection(stream, peer, runtime, connection_permit).await
            {
                eprintln!("event=tcp_connection_error error={}", error);
            }
        });
    }
}

async fn handle_tcp_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    runtime: RuntimeState,
    _connection_permit: TcpConnectionPermit,
) -> io::Result<()> {
    loop {
        let mut length_prefix = [0_u8; 2];
        match read_exact_with_timeout(
            &mut stream,
            &mut length_prefix,
            runtime.limits.tcp_idle_timeout,
        )
        .await
        {
            Ok(()) => {}
            Err(error) if is_disconnect_error(&error) => return Ok(()),
            Err(error) => return Err(error),
        }

        let frame_len = u16::from_be_bytes(length_prefix) as usize;
        if frame_len == 0 {
            continue;
        }

        if frame_len > runtime.limits.max_tcp_frame_bytes {
            eprintln!(
                "event=tcp_drop reason=request_too_large received_bytes={} limit_bytes={}",
                frame_len, runtime.limits.max_tcp_frame_bytes
            );
            return Ok(());
        }

        if !runtime.query_rate_limiter.allow(peer.ip()) {
            eprintln!("event=tcp_drop reason=rate_limited");
            return Ok(());
        }

        let mut request = vec![0_u8; frame_len];
        match read_exact_with_timeout(&mut stream, &mut request, runtime.limits.tcp_read_timeout)
            .await
        {
            Ok(()) => {}
            Err(error) if is_disconnect_error(&error) => return Ok(()),
            Err(error) => return Err(error),
        }

        let Some(response) = runtime.authority.build_response(&request) else {
            eprintln!("event=tcp_drop reason=parse_error");
            return Ok(());
        };

        if !allow_invalid_query_response(&runtime, peer.ip(), &response) {
            eprintln!(
                "event=tcp_drop reason=invalid_query_rate_limited rcode={:?}",
                response.response_code
            );
            return Ok(());
        }

        log_query_if_enabled(&runtime, "tcp_query", &response, frame_len);

        let response_len = u16::try_from(response.wire_bytes.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "dns response too large for tcp framing",
            )
        })?;

        write_all_with_timeout(
            &mut stream,
            &response_len.to_be_bytes(),
            runtime.limits.tcp_write_timeout,
        )
        .await?;

        write_all_with_timeout(
            &mut stream,
            &response.wire_bytes,
            runtime.limits.tcp_write_timeout,
        )
        .await?;
    }
}

fn log_query_if_enabled(
    runtime: &RuntimeState,
    event: &str,
    response: &BuiltResponse,
    request_bytes: usize,
) {
    if !runtime.query_log_enabled {
        return;
    }

    let qtype = response
        .query_type
        .map_or_else(|| "-".to_string(), |value| value.to_string());

    eprintln!(
        "event={} qtype={} rcode={:?} authoritative={} answers={} authority={} request_bytes={} response_bytes={}",
        event,
        qtype,
        response.response_code,
        response.authoritative,
        response.answer_count,
        response.authority_count,
        request_bytes,
        response.wire_bytes.len(),
    );
}

async fn read_exact_with_timeout(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    timeout_duration: Duration,
) -> io::Result<()> {
    match timeout(timeout_duration, stream.read_exact(buffer)).await {
        Ok(result) => result.map(|_| ()),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "timeout reading from tcp connection",
        )),
    }
}

async fn write_all_with_timeout(
    stream: &mut TcpStream,
    buffer: &[u8],
    timeout_duration: Duration,
) -> io::Result<()> {
    match timeout(timeout_duration, stream.write_all(buffer)).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "timeout writing to tcp connection",
        )),
    }
}

fn is_disconnect_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::TimedOut
    )
}

fn allow_invalid_query_response(
    runtime: &RuntimeState,
    ip: std::net::IpAddr,
    response: &BuiltResponse,
) -> bool {
    if !is_invalid_query_response_code(response.response_code) {
        return true;
    }

    let Some(query_name) = response.query_name.as_deref() else {
        return true;
    };

    runtime.invalid_query_rate_limiter.allow(ip, query_name)
}

fn is_invalid_query_response_code(response_code: ResponseCode) -> bool {
    matches!(
        response_code,
        ResponseCode::NXDomain | ResponseCode::Refused | ResponseCode::FormErr
    )
}
