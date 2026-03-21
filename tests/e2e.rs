use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const QUERY_TIMEOUT: Duration = Duration::from_millis(500);

struct ServerProcess {
    child: Child,
    listen: SocketAddr,
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn udp_end_to_end_authoritative_behavior() {
    let zone = "dev.example.com";
    let server = start_server(zone);

    let answer = query_udp(server.listen, "1-2-3-4.dev.example.com.", RecordType::A)
        .unwrap_or_else(|error| panic!("failed udp query for A record: {error}"));
    assert_eq!(answer.response_code(), ResponseCode::NoError);
    assert!(answer.authoritative());
    assert_eq!(answer.answers().len(), 1);
    assert_eq!(answer.answers()[0].record_type(), RecordType::A);

    let nxdomain = query_udp(server.listen, "nope.dev.example.com.", RecordType::A)
        .unwrap_or_else(|error| panic!("failed udp query for NXDOMAIN check: {error}"));
    assert_eq!(nxdomain.response_code(), ResponseCode::NXDomain);
    assert!(nxdomain.authoritative());
    assert_eq!(nxdomain.name_servers().len(), 1);
    assert_eq!(nxdomain.name_servers()[0].record_type(), RecordType::SOA);

    let refused = query_udp(server.listen, "1-2-3-4.prod.example.com.", RecordType::A)
        .unwrap_or_else(|error| panic!("failed udp query for REFUSED check: {error}"));
    assert_eq!(refused.response_code(), ResponseCode::Refused);
    assert!(!refused.authoritative());
}

#[test]
fn tcp_end_to_end_authoritative_behavior() {
    let zone = "dev.example.com";
    let server = start_server(zone);

    let answer = query_tcp(server.listen, "1-2-3-4.dev.example.com.", RecordType::A)
        .unwrap_or_else(|error| panic!("failed tcp query for A record: {error}"));
    assert_eq!(answer.response_code(), ResponseCode::NoError);
    assert!(answer.authoritative());
    assert_eq!(answer.answers().len(), 1);
    assert_eq!(answer.answers()[0].record_type(), RecordType::A);

    let apex_ns = query_tcp(server.listen, "dev.example.com.", RecordType::NS)
        .unwrap_or_else(|error| panic!("failed tcp query for NS apex check: {error}"));
    assert_eq!(apex_ns.response_code(), ResponseCode::NoError);
    assert!(apex_ns.authoritative());
    assert_eq!(apex_ns.answers().len(), 1);
    assert_eq!(apex_ns.answers()[0].record_type(), RecordType::NS);

    let nodata = query_tcp(server.listen, "1-2-3-4.dev.example.com.", RecordType::AAAA)
        .unwrap_or_else(|error| panic!("failed tcp query for NODATA check: {error}"));
    assert_eq!(nodata.response_code(), ResponseCode::NoError);
    assert!(nodata.authoritative());
    assert!(nodata.answers().is_empty());
    assert_eq!(nodata.name_servers().len(), 1);
    assert_eq!(nodata.name_servers()[0].record_type(), RecordType::SOA);
}

fn start_server(zone: &str) -> ServerProcess {
    let listen = reserve_listen_addr();
    let mut child = Command::new(binary_path())
        .env("LEAF_ZONE", zone)
        .env("LEAF_LISTEN", listen.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to start leaf binary: {error}"));

    wait_until_ready(&mut child, listen, zone);
    ServerProcess { child, listen }
}

fn reserve_listen_addr() -> SocketAddr {
    loop {
        let tcp_listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .unwrap_or_else(|error| panic!("failed to bind tcp probe listener: {error}"));
        let port = tcp_listener
            .local_addr()
            .unwrap_or_else(|error| panic!("failed to read tcp probe listener addr: {error}"))
            .port();

        let udp_bind = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
        if udp_bind.is_ok() {
            drop(tcp_listener);
            return SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        }
    }
}

fn wait_until_ready(child: &mut Child, listen: SocketAddr, zone: &str) {
    let ready_qname = format!("{zone}.");
    let deadline = Instant::now() + STARTUP_TIMEOUT;

    while Instant::now() < deadline {
        if let Some(status) = child
            .try_wait()
            .unwrap_or_else(|error| panic!("failed checking server process status: {error}"))
        {
            panic!("leaf server exited during startup with status: {status}");
        }

        if let Ok(response) = query_udp(listen, &ready_qname, RecordType::SOA)
            && response.response_code() == ResponseCode::NoError
        {
            return;
        }

        sleep(Duration::from_millis(50));
    }

    panic!("leaf server failed startup readiness check on {listen}");
}

fn query_udp(server: SocketAddr, qname: &str, qtype: RecordType) -> io::Result<Message> {
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
    socket.set_read_timeout(Some(QUERY_TIMEOUT))?;
    socket.set_write_timeout(Some(QUERY_TIMEOUT))?;

    let request = build_query(qname, qtype);
    socket.send_to(&request, server)?;

    let mut buffer = [0_u8; 4096];
    let (received, _) = socket.recv_from(&mut buffer)?;
    Message::from_vec(&buffer[..received])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}

fn query_tcp(server: SocketAddr, qname: &str, qtype: RecordType) -> io::Result<Message> {
    let mut stream = TcpStream::connect_timeout(&server, QUERY_TIMEOUT)?;
    stream.set_read_timeout(Some(QUERY_TIMEOUT))?;
    stream.set_write_timeout(Some(QUERY_TIMEOUT))?;

    let request = build_query(qname, qtype);
    let request_len = u16::try_from(request.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "request frame too large"))?;

    stream.write_all(&request_len.to_be_bytes())?;
    stream.write_all(&request)?;

    let mut response_prefix = [0_u8; 2];
    stream.read_exact(&mut response_prefix)?;
    let response_len = u16::from_be_bytes(response_prefix) as usize;

    let mut response = vec![0_u8; response_len];
    stream.read_exact(&mut response)?;

    Message::from_vec(&response)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}

fn build_query(qname: &str, qtype: RecordType) -> Vec<u8> {
    let name = Name::from_ascii(qname)
        .unwrap_or_else(|error| panic!("invalid query name {qname}: {error}"));
    let mut message = Message::new();
    message.set_id(0x1234);
    message.set_op_code(OpCode::Query);
    message.add_query(Query::query(name, qtype));
    message
        .to_vec()
        .unwrap_or_else(|error| panic!("failed to encode dns query: {error}"))
}

fn binary_path() -> String {
    std::env::var("CARGO_BIN_EXE_leaf").unwrap_or_else(|error| {
        panic!("CARGO_BIN_EXE_leaf is not set for integration test: {error}")
    })
}
