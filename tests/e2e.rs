use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hickory_proto::op::{Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const QUERY_TIMEOUT: Duration = Duration::from_millis(500);

struct ServerProcess {
    child: Child,
    listen: SocketAddr,
    temp_config_path: Option<PathBuf>,
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(path) = &self.temp_config_path {
            let _ = fs::remove_file(path);
        }
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

#[test]
fn multi_zone_end_to_end_authoritative_behavior() {
    let server = start_server_with_zones(&["dev.example.com", "prod.example.com"]);

    let dev_answer = query_udp(server.listen, "1-2-3-4.dev.example.com.", RecordType::A)
        .unwrap_or_else(|error| panic!("failed udp query for dev zone A record: {error}"));
    assert_eq!(dev_answer.response_code(), ResponseCode::NoError);
    assert!(dev_answer.authoritative());
    assert_eq!(dev_answer.answers().len(), 1);

    let prod_answer = query_udp(server.listen, "5-6-7-8.prod.example.com.", RecordType::A)
        .unwrap_or_else(|error| panic!("failed udp query for prod zone A record: {error}"));
    assert_eq!(prod_answer.response_code(), ResponseCode::NoError);
    assert!(prod_answer.authoritative());
    assert_eq!(prod_answer.answers().len(), 1);

    let refused = query_udp(server.listen, "1-2-3-4.other.example.com.", RecordType::A)
        .unwrap_or_else(|error| panic!("failed udp query for out-of-zone check: {error}"));
    assert_eq!(refused.response_code(), ResponseCode::Refused);
    assert!(!refused.authoritative());
}

#[test]
fn structured_toml_config_end_to_end_behavior() {
    let listen = reserve_listen_addr();
    let config = format!(
        "zones = [\"dev.example.com\", \"prod.example.com\"]\nlisten = \"{listen}\"\n[dns]\nttl = 120\n[soa]\nserial = 7\nrefresh = 400\nretry = 90\nexpire = 90000\nminimum = 45\n[limits]\nglobal_qps_limit = 5000\nper_ip_qps_limit = 200\nper_ip_invalid_qname_qps_limit = 20\nlimiter_max_tracked_ips = 10000\ninvalid_qname_limiter_max_tracked_keys = 50000\ntcp_max_connections = 1024\ntcp_max_connections_per_ip = 64\ntcp_idle_timeout_ms = 10000\ntcp_read_timeout_ms = 3000\ntcp_write_timeout_ms = 3000\nmax_tcp_frame_bytes = 4096\nmax_udp_request_bytes = 1232\n"
    );
    let server = start_server_with_toml(listen, &config, "dev.example.com");

    let dev_answer = query_udp(server.listen, "1-2-3-4.dev.example.com.", RecordType::A)
        .unwrap_or_else(|error| panic!("failed udp query for dev zone A record: {error}"));
    assert_eq!(dev_answer.response_code(), ResponseCode::NoError);
    assert!(dev_answer.authoritative());
    assert_eq!(dev_answer.answers().len(), 1);

    let prod_answer = query_tcp(server.listen, "5-6-7-8.prod.example.com.", RecordType::A)
        .unwrap_or_else(|error| panic!("failed tcp query for prod zone A record: {error}"));
    assert_eq!(prod_answer.response_code(), ResponseCode::NoError);
    assert!(prod_answer.authoritative());
    assert_eq!(prod_answer.answers().len(), 1);
}

#[test]
fn invalid_query_limiter_drops_repeated_bad_lookup() {
    let server = start_server_with_zones_and_env(
        &["dev.example.com"],
        &[
            ("LEAF_PER_IP_INVALID_QNAME_QPS_LIMIT", "1"),
            ("LEAF_GLOBAL_QPS_LIMIT", "1000"),
            ("LEAF_PER_IP_QPS_LIMIT", "1000"),
        ],
    );

    let first = query_udp(server.listen, "nope.dev.example.com.", RecordType::A)
        .unwrap_or_else(|error| panic!("first invalid query should get response: {error}"));
    assert_eq!(first.response_code(), ResponseCode::NXDomain);

    let second = query_udp(server.listen, "nope.dev.example.com.", RecordType::A);
    assert!(
        second.is_err(),
        "second invalid query should be dropped by limiter"
    );
}

#[test]
fn udp_response_policy_matrix_end_to_end() {
    let server = start_server("dev.example.com");

    let apex_soa = query_udp(server.listen, "dev.example.com.", RecordType::SOA)
        .unwrap_or_else(|error| panic!("failed udp SOA query: {error}"));
    assert_eq!(apex_soa.response_code(), ResponseCode::NoError);
    assert!(apex_soa.authoritative());
    assert_eq!(apex_soa.answers().len(), 1);
    assert_eq!(apex_soa.answers()[0].record_type(), RecordType::SOA);

    let apex_ns = query_udp(server.listen, "dev.example.com.", RecordType::NS)
        .unwrap_or_else(|error| panic!("failed udp NS query: {error}"));
    assert_eq!(apex_ns.response_code(), ResponseCode::NoError);
    assert!(apex_ns.authoritative());
    assert_eq!(apex_ns.answers().len(), 1);
    assert_eq!(apex_ns.answers()[0].record_type(), RecordType::NS);

    let nodata = query_udp(server.listen, "1-2-3-4.dev.example.com.", RecordType::AAAA)
        .unwrap_or_else(|error| panic!("failed udp NODATA query: {error}"));
    assert_eq!(nodata.response_code(), ResponseCode::NoError);
    assert!(nodata.authoritative());
    assert!(nodata.answers().is_empty());
    assert_eq!(nodata.name_servers().len(), 1);
    assert_eq!(nodata.name_servers()[0].record_type(), RecordType::SOA);

    let any_refused = query_udp(server.listen, "1-2-3-4.dev.example.com.", RecordType::ANY)
        .unwrap_or_else(|error| panic!("failed udp ANY query: {error}"));
    assert_eq!(any_refused.response_code(), ResponseCode::Refused);
    assert!(any_refused.authoritative());

    let nxdomain = query_udp(server.listen, "nope.dev.example.com.", RecordType::A)
        .unwrap_or_else(|error| panic!("failed udp NXDOMAIN query: {error}"));
    assert_eq!(nxdomain.response_code(), ResponseCode::NXDomain);
    assert!(nxdomain.authoritative());
    assert_eq!(nxdomain.name_servers().len(), 1);
    assert_eq!(nxdomain.name_servers()[0].record_type(), RecordType::SOA);

    let out_of_zone = query_udp(server.listen, "1-2-3-4.other.example.com.", RecordType::A)
        .unwrap_or_else(|error| panic!("failed udp out-of-zone query: {error}"));
    assert_eq!(out_of_zone.response_code(), ResponseCode::Refused);
    assert!(!out_of_zone.authoritative());
}

#[test]
fn opcode_and_multi_question_errors_end_to_end() {
    let server = start_server("dev.example.com");

    let notimp_udp = query_udp_raw(
        server.listen,
        &build_query_with_opcode("1-2-3-4.dev.example.com.", RecordType::A, OpCode::Status),
    )
    .unwrap_or_else(|error| panic!("failed udp non-query opcode request: {error}"));
    assert_eq!(notimp_udp.response_code(), ResponseCode::NotImp);

    let formerr_udp = query_udp_raw(
        server.listen,
        &build_multi_question_query(
            ("1-2-3-4.dev.example.com.", RecordType::A),
            ("2-3-4-5.dev.example.com.", RecordType::A),
        ),
    )
    .unwrap_or_else(|error| panic!("failed udp multi-question request: {error}"));
    assert_eq!(formerr_udp.response_code(), ResponseCode::FormErr);

    let notimp_tcp = query_tcp_raw(
        server.listen,
        &build_query_with_opcode("1-2-3-4.dev.example.com.", RecordType::A, OpCode::Status),
    )
    .unwrap_or_else(|error| panic!("failed tcp non-query opcode request: {error}"));
    assert_eq!(notimp_tcp.response_code(), ResponseCode::NotImp);

    let formerr_tcp = query_tcp_raw(
        server.listen,
        &build_multi_question_query(
            ("1-2-3-4.dev.example.com.", RecordType::A),
            ("2-3-4-5.dev.example.com.", RecordType::A),
        ),
    )
    .unwrap_or_else(|error| panic!("failed tcp multi-question request: {error}"));
    assert_eq!(formerr_tcp.response_code(), ResponseCode::FormErr);
}

fn start_server(zone: &str) -> ServerProcess {
    start_server_with_zones(&[zone])
}

fn start_server_with_zones(zones: &[&str]) -> ServerProcess {
    start_server_with_zones_and_env(zones, &[])
}

fn start_server_with_zones_and_env(zones: &[&str], extra_env: &[(&str, &str)]) -> ServerProcess {
    let listen = reserve_listen_addr();
    let zones_value = zones.join(",");
    let readiness_zone = zones
        .first()
        .unwrap_or_else(|| panic!("at least one zone is required for tests"));
    let mut command = Command::new(binary_path());
    command
        .env("LEAF_ZONES", zones_value)
        .env("LEAF_LISTEN", listen.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    for (key, value) in extra_env {
        command.env(key, value);
    }

    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("failed to start leaf binary: {error}"));

    wait_until_ready(&mut child, listen, readiness_zone);
    ServerProcess {
        child,
        listen,
        temp_config_path: None,
    }
}

fn start_server_with_toml(
    listen: SocketAddr,
    config_contents: &str,
    readiness_zone: &str,
) -> ServerProcess {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "leaf-e2e-{}-{}.toml",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|error| panic!("system time before unix epoch: {error}"))
            .as_nanos()
    ));
    fs::write(&path, config_contents)
        .unwrap_or_else(|error| panic!("failed writing temporary config: {error}"));

    let mut child = Command::new(binary_path())
        .env("LEAF_CONFIG", &path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to start leaf binary from TOML config: {error}"));

    wait_until_ready(&mut child, listen, readiness_zone);
    ServerProcess {
        child,
        listen,
        temp_config_path: Some(path),
    }
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
    query_udp_raw(server, &build_query(qname, qtype))
}

fn query_udp_raw(server: SocketAddr, request: &[u8]) -> io::Result<Message> {
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
    socket.set_read_timeout(Some(QUERY_TIMEOUT))?;
    socket.set_write_timeout(Some(QUERY_TIMEOUT))?;

    socket.send_to(request, server)?;

    let mut buffer = [0_u8; 4096];
    let (received, _) = socket.recv_from(&mut buffer)?;
    Message::from_vec(&buffer[..received])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}

fn query_tcp(server: SocketAddr, qname: &str, qtype: RecordType) -> io::Result<Message> {
    query_tcp_raw(server, &build_query(qname, qtype))
}

fn query_tcp_raw(server: SocketAddr, request: &[u8]) -> io::Result<Message> {
    let mut stream = TcpStream::connect_timeout(&server, QUERY_TIMEOUT)?;
    stream.set_read_timeout(Some(QUERY_TIMEOUT))?;
    stream.set_write_timeout(Some(QUERY_TIMEOUT))?;

    let request_len = u16::try_from(request.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "request frame too large"))?;

    stream.write_all(&request_len.to_be_bytes())?;
    stream.write_all(request)?;

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

fn build_query_with_opcode(qname: &str, qtype: RecordType, op_code: OpCode) -> Vec<u8> {
    let name = Name::from_ascii(qname)
        .unwrap_or_else(|error| panic!("invalid query name {qname}: {error}"));
    let mut message = Message::new();
    message.set_id(0x2233);
    message.set_op_code(op_code);
    message.add_query(Query::query(name, qtype));
    message
        .to_vec()
        .unwrap_or_else(|error| panic!("failed to encode dns query: {error}"))
}

fn build_multi_question_query(first: (&str, RecordType), second: (&str, RecordType)) -> Vec<u8> {
    let first_name = Name::from_ascii(first.0)
        .unwrap_or_else(|error| panic!("invalid query name {}: {error}", first.0));
    let second_name = Name::from_ascii(second.0)
        .unwrap_or_else(|error| panic!("invalid query name {}: {error}", second.0));

    let mut message = Message::new();
    message.set_id(0x3344);
    message.set_op_code(OpCode::Query);
    message.add_query(Query::query(first_name, first.1));
    message.add_query(Query::query(second_name, second.1));
    message
        .to_vec()
        .unwrap_or_else(|error| panic!("failed to encode dns query: {error}"))
}

fn binary_path() -> String {
    std::env::var("CARGO_BIN_EXE_leaf").unwrap_or_else(|error| {
        panic!("CARGO_BIN_EXE_leaf is not set for integration test: {error}")
    })
}
