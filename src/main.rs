mod config;
mod dns;
mod limits;

use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::config::{Config, LimitsConfig};
use crate::dns::DnsAuthority;
use crate::limits::{QueryRateLimiter, TcpConnectionLimiter, TcpConnectionPermit};

#[derive(Debug, Clone)]
struct RuntimeState {
    authority: Arc<DnsAuthority>,
    query_rate_limiter: QueryRateLimiter,
    limits: LimitsConfig,
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
        limits: config.limits.clone(),
    };

    let tcp_connection_limiter = TcpConnectionLimiter::new(
        config.limits.tcp_max_connections,
        config.limits.tcp_max_connections_per_ip,
    );

    let udp_socket = UdpSocket::bind(config.listen).await?;
    let tcp_listener = TcpListener::bind(config.listen).await?;

    eprintln!(
        "event=startup message='authoritative dns online' listen={} zone={} zone_ns={} hostmaster={} ttl={} global_qps_limit={} per_ip_qps_limit={} tcp_max_connections={} tcp_max_connections_per_ip={} max_udp_request_bytes={} max_tcp_frame_bytes={}",
        config.listen,
        config.zone.to_utf8(),
        config.zone_ns.to_utf8(),
        config.zone_hostmaster.to_utf8(),
        config.answer_ttl,
        config.limits.global_qps_limit,
        config.limits.per_ip_qps_limit,
        config.limits.tcp_max_connections,
        config.limits.tcp_max_connections_per_ip,
        config.limits.max_udp_request_bytes,
        config.limits.max_tcp_frame_bytes,
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
                "event=udp_drop reason=request_too_large peer={} received_bytes={} limit_bytes={}",
                peer, received, runtime.limits.max_udp_request_bytes
            );
            continue;
        }

        if !runtime.query_rate_limiter.allow(peer.ip()) {
            eprintln!("event=udp_drop reason=rate_limited peer={}", peer);
            continue;
        }

        if let Some(response) = runtime.authority.build_response(&buffer[..received]) {
            // Best effort; malformed peers should not terminate the server.
            let _ = socket.send_to(&response, peer).await;
        } else {
            eprintln!("event=udp_drop reason=parse_error peer={}", peer);
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
            eprintln!(
                "event=tcp_drop reason=connection_limit_reached peer={}",
                peer
            );
            continue;
        };

        let runtime = runtime.clone();

        tokio::spawn(async move {
            if let Err(error) =
                handle_tcp_connection(stream, peer, runtime, connection_permit).await
            {
                eprintln!("event=tcp_connection_error peer={} error={}", peer, error);
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
                "event=tcp_drop reason=request_too_large peer={} received_bytes={} limit_bytes={}",
                peer, frame_len, runtime.limits.max_tcp_frame_bytes
            );
            return Ok(());
        }

        if !runtime.query_rate_limiter.allow(peer.ip()) {
            eprintln!("event=tcp_drop reason=rate_limited peer={}", peer);
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
            eprintln!("event=tcp_drop reason=parse_error peer={}", peer);
            return Ok(());
        };

        let response_len = u16::try_from(response.len()).map_err(|_| {
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

        write_all_with_timeout(&mut stream, &response, runtime.limits.tcp_write_timeout).await?;
    }
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
