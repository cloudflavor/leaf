use std::net::Ipv4Addr;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, NS, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use crate::config::{Config, SoaConfig, ZoneConfig};

#[derive(Debug, Clone)]
pub struct BuiltResponse {
    pub wire_bytes: Vec<u8>,
    pub response_code: ResponseCode,
    pub query_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DnsAuthority {
    zones: Vec<AuthorityZone>,
}

#[derive(Debug, Clone)]
struct AuthorityZone {
    zone: Name,
    answer_ttl: u32,
    zone_ns: Name,
    zone_hostmaster: Name,
    soa: SoaConfig,
}

impl DnsAuthority {
    pub fn from_config(config: &Config) -> Self {
        Self {
            zones: config
                .zones
                .iter()
                .map(AuthorityZone::from_zone_config)
                .collect(),
        }
    }

    pub fn build_response(&self, request_bytes: &[u8]) -> Option<BuiltResponse> {
        let request = Message::from_vec(request_bytes).ok()?;
        let query_name = request
            .queries()
            .first()
            .map(|query| query.name().to_utf8().to_ascii_lowercase());

        let mut response = Message::new();
        response.set_id(request.id());
        response.set_op_code(request.op_code());
        response.set_message_type(MessageType::Response);
        response.set_authoritative(false);
        response.set_recursion_desired(request.recursion_desired());
        response.set_recursion_available(false);

        for query in request.queries() {
            response.add_query(query.clone());
        }

        if request.op_code() != OpCode::Query {
            response.set_response_code(ResponseCode::NotImp);
            return finalize_response(response, query_name);
        }

        if request.queries().len() != 1 {
            response.set_response_code(ResponseCode::FormErr);
            return finalize_response(response, query_name);
        }

        let query = request.queries().first()?;
        let Some(zone) = self.find_matching_zone(query.name()) else {
            response.set_response_code(ResponseCode::Refused);
            return finalize_response(response, query_name);
        };

        response.set_authoritative(true);

        if query.query_type() == RecordType::ANY {
            response.set_response_code(ResponseCode::Refused);
            return finalize_response(response, query_name);
        }

        if query.name() == &zone.zone {
            zone.build_apex_response(&mut response, query);
            return finalize_response(response, query_name);
        }

        if let Some(ip) = resolve_nip_style_ipv4(query.name(), &zone.zone) {
            zone.build_existing_record_response(&mut response, query, ip);
            return finalize_response(response, query_name);
        }

        response.set_response_code(ResponseCode::NXDomain);
        zone.add_negative_authority(&mut response);
        finalize_response(response, query_name)
    }

    fn find_matching_zone(&self, qname: &Name) -> Option<&AuthorityZone> {
        self.zones
            .iter()
            .filter(|zone| is_name_in_zone(qname, &zone.zone))
            .max_by_key(|zone| labels(&zone.zone).len())
    }
}

impl AuthorityZone {
    fn from_zone_config(zone_config: &ZoneConfig) -> Self {
        Self {
            zone: zone_config.zone.clone(),
            answer_ttl: zone_config.answer_ttl,
            zone_ns: zone_config.zone_ns.clone(),
            zone_hostmaster: zone_config.zone_hostmaster.clone(),
            soa: zone_config.soa.clone(),
        }
    }

    fn build_apex_response(&self, response: &mut Message, query: &Query) {
        match query.query_type() {
            RecordType::SOA => {
                response.add_answer(self.soa_record(self.answer_ttl));
                response.set_response_code(ResponseCode::NoError);
            }
            RecordType::NS => {
                response.add_answer(self.ns_record(self.answer_ttl));
                response.set_response_code(ResponseCode::NoError);
            }
            _ => {
                response.set_response_code(ResponseCode::NoError);
                self.add_negative_authority(response);
            }
        }
    }

    fn build_existing_record_response(&self, response: &mut Message, query: &Query, ip: Ipv4Addr) {
        match query.query_type() {
            RecordType::A => {
                let [a, b, c, d] = ip.octets();
                response.add_answer(Record::from_rdata(
                    query.name().clone(),
                    self.answer_ttl,
                    RData::A(A::new(a, b, c, d)),
                ));
                response.set_response_code(ResponseCode::NoError);
            }
            _ => {
                response.set_response_code(ResponseCode::NoError);
                self.add_negative_authority(response);
            }
        }
    }

    fn add_negative_authority(&self, response: &mut Message) {
        response.add_name_server(self.soa_record(self.soa.minimum));
    }

    fn soa_record(&self, ttl: u32) -> Record {
        Record::from_rdata(
            self.zone.clone(),
            ttl,
            RData::SOA(SOA::new(
                self.zone_ns.clone(),
                self.zone_hostmaster.clone(),
                self.soa.serial,
                self.soa.refresh,
                self.soa.retry,
                self.soa.expire,
                self.soa.minimum,
            )),
        )
    }

    fn ns_record(&self, ttl: u32) -> Record {
        Record::from_rdata(self.zone.clone(), ttl, RData::NS(NS(self.zone_ns.clone())))
    }
}

fn finalize_response(response: Message, query_name: Option<String>) -> Option<BuiltResponse> {
    let response_code = response.response_code();
    let wire_bytes = response.to_vec().ok()?;
    Some(BuiltResponse {
        wire_bytes,
        response_code,
        query_name,
    })
}

fn is_name_in_zone(name: &Name, zone: &Name) -> bool {
    let name_labels = labels(name);
    let zone_labels = labels(zone);

    name_labels.len() >= zone_labels.len() && name_labels.ends_with(&zone_labels)
}

fn resolve_nip_style_ipv4(name: &Name, zone: &Name) -> Option<Ipv4Addr> {
    let name_labels = labels(name);
    let zone_labels = labels(zone);

    if name_labels.len() <= zone_labels.len() || !name_labels.ends_with(&zone_labels) {
        return None;
    }

    let prefix = &name_labels[..name_labels.len() - zone_labels.len()];

    // nip.io-like style: 1-2-3-4.example.com
    if let Some(last) = prefix.last()
        && let Some(ip) = parse_dashed_ipv4(last)
    {
        return Some(ip);
    }

    // nip.io-like style: 1.2.3.4.example.com
    if prefix.len() >= 4 {
        let dotted = prefix[prefix.len() - 4..].join(".");
        if let Some(ip) = parse_dotted_ipv4(&dotted) {
            return Some(ip);
        }
    }

    None
}

fn parse_dashed_ipv4(label: &str) -> Option<Ipv4Addr> {
    parse_dotted_ipv4(&label.replace('-', "."))
}

fn parse_dotted_ipv4(input: &str) -> Option<Ipv4Addr> {
    let mut octets = [0_u8; 4];
    let mut parts = input.split('.');

    for octet in &mut octets {
        let part = parts.next()?;
        *octet = part.parse::<u8>().ok()?;
    }

    if parts.next().is_some() {
        return None;
    }

    Some(Ipv4Addr::from(octets))
}

fn labels(name: &Name) -> Vec<String> {
    name.to_utf8()
        .trim_end_matches('.')
        .split('.')
        .filter(|label| !label.is_empty())
        .map(|label| label.to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;

    fn name(value: &str) -> Name {
        Name::from_ascii(value).unwrap_or_else(|err| panic!("invalid test name {value}: {err}"))
    }

    fn authority() -> DnsAuthority {
        DnsAuthority {
            zones: vec![AuthorityZone {
                zone: name("dev.example.com."),
                answer_ttl: 60,
                zone_ns: name("ns1.dev.example.com."),
                zone_hostmaster: name("hostmaster.dev.example.com."),
                soa: SoaConfig {
                    serial: 1,
                    refresh: 300,
                    retry: 60,
                    expire: 86400,
                    minimum: 60,
                },
            }],
        }
    }

    fn multi_zone_authority() -> DnsAuthority {
        DnsAuthority {
            zones: vec![
                AuthorityZone {
                    zone: name("dev.example.com."),
                    answer_ttl: 60,
                    zone_ns: name("ns1.dev.example.com."),
                    zone_hostmaster: name("hostmaster.dev.example.com."),
                    soa: SoaConfig {
                        serial: 1,
                        refresh: 300,
                        retry: 60,
                        expire: 86400,
                        minimum: 60,
                    },
                },
                AuthorityZone {
                    zone: name("example.com."),
                    answer_ttl: 120,
                    zone_ns: name("ns1.example.com."),
                    zone_hostmaster: name("hostmaster.example.com."),
                    soa: SoaConfig {
                        serial: 2,
                        refresh: 600,
                        retry: 120,
                        expire: 172800,
                        minimum: 120,
                    },
                },
            ],
        }
    }

    fn query_packet(qname: &str, qtype: RecordType) -> Vec<u8> {
        let mut request = Message::new();
        request.set_id(12);
        request.set_op_code(OpCode::Query);
        request.add_query(Query::query(name(qname), qtype));
        request
            .to_vec()
            .unwrap_or_else(|err| panic!("failed to serialize request: {err}"))
    }

    fn decode_message(bytes: &[u8]) -> Message {
        Message::from_vec(bytes).unwrap_or_else(|err| panic!("failed to decode response: {err}"))
    }

    #[test]
    fn resolves_dashed_style() {
        let zone = name("dev.example.com.");
        let query = name("1-2-3-4.dev.example.com.");
        assert_eq!(
            resolve_nip_style_ipv4(&query, &zone),
            Some(Ipv4Addr::new(1, 2, 3, 4))
        );
    }

    #[test]
    fn resolves_dotted_style() {
        let zone = name("dev.example.com.");
        let query = name("1.2.3.4.dev.example.com.");
        assert_eq!(
            resolve_nip_style_ipv4(&query, &zone),
            Some(Ipv4Addr::new(1, 2, 3, 4))
        );
    }

    #[test]
    fn resolves_with_leading_subdomain() {
        let zone = name("dev.example.com.");
        let query = name("api.10-11-12-13.dev.example.com.");
        assert_eq!(
            resolve_nip_style_ipv4(&query, &zone),
            Some(Ipv4Addr::new(10, 11, 12, 13))
        );
    }

    #[test]
    fn rejects_invalid_octet() {
        let zone = name("dev.example.com.");
        let query = name("300-2-3-4.dev.example.com.");
        assert_eq!(resolve_nip_style_ipv4(&query, &zone), None);
    }

    #[test]
    fn rejects_outside_zone() {
        let zone = name("dev.example.com.");
        let query = name("1-2-3-4.prod.example.com.");
        assert_eq!(resolve_nip_style_ipv4(&query, &zone), None);
        assert!(!is_name_in_zone(&query, &zone));
    }

    #[test]
    fn returns_formerr_for_multi_question_requests() {
        let mut request = Message::new();
        request.set_id(11);
        request.set_op_code(OpCode::Query);
        request.add_query(Query::query(
            name("1-2-3-4.dev.example.com."),
            RecordType::A,
        ));
        request.add_query(Query::query(
            name("2-3-4-5.dev.example.com."),
            RecordType::A,
        ));

        let request_bytes = request
            .to_vec()
            .unwrap_or_else(|err| panic!("failed to serialize request: {err}"));
        let response_bytes = authority()
            .build_response(&request_bytes)
            .unwrap_or_else(|| panic!("expected response"))
            .wire_bytes;
        let response = decode_message(&response_bytes);

        assert_eq!(response.response_code(), ResponseCode::FormErr);
    }

    #[test]
    fn returns_refused_for_out_of_zone_names() {
        let response_bytes = authority()
            .build_response(&query_packet("1-2-3-4.prod.example.com.", RecordType::A))
            .unwrap_or_else(|| panic!("expected response"))
            .wire_bytes;
        let response = decode_message(&response_bytes);

        assert_eq!(response.response_code(), ResponseCode::Refused);
        assert!(!response.authoritative());
    }

    #[test]
    fn returns_apex_soa_record() {
        let response_bytes = authority()
            .build_response(&query_packet("dev.example.com.", RecordType::SOA))
            .unwrap_or_else(|| panic!("expected response"))
            .wire_bytes;
        let response = decode_message(&response_bytes);

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
        assert_eq!(response.answers()[0].record_type(), RecordType::SOA);
    }

    #[test]
    fn returns_apex_ns_record() {
        let response_bytes = authority()
            .build_response(&query_packet("dev.example.com.", RecordType::NS))
            .unwrap_or_else(|| panic!("expected response"))
            .wire_bytes;
        let response = decode_message(&response_bytes);

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
        assert_eq!(response.answers()[0].record_type(), RecordType::NS);
    }

    #[test]
    fn returns_refused_for_any_queries() {
        let response_bytes = authority()
            .build_response(&query_packet("1-2-3-4.dev.example.com.", RecordType::ANY))
            .unwrap_or_else(|| panic!("expected response"))
            .wire_bytes;
        let response = decode_message(&response_bytes);

        assert_eq!(response.response_code(), ResponseCode::Refused);
        assert!(response.authoritative());
    }

    #[test]
    fn returns_nodata_with_soa_authority() {
        let response_bytes = authority()
            .build_response(&query_packet("1-2-3-4.dev.example.com.", RecordType::AAAA))
            .unwrap_or_else(|| panic!("expected response"))
            .wire_bytes;
        let response = decode_message(&response_bytes);

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert!(response.answers().is_empty());
        assert_eq!(response.name_servers().len(), 1);
        assert_eq!(response.name_servers()[0].record_type(), RecordType::SOA);
    }

    #[test]
    fn returns_nxdomain_with_soa_authority() {
        let response_bytes = authority()
            .build_response(&query_packet("nope.dev.example.com.", RecordType::A))
            .unwrap_or_else(|| panic!("expected response"))
            .wire_bytes;
        let response = decode_message(&response_bytes);

        assert_eq!(response.response_code(), ResponseCode::NXDomain);
        assert!(response.answers().is_empty());
        assert_eq!(response.name_servers().len(), 1);
        assert_eq!(response.name_servers()[0].record_type(), RecordType::SOA);
    }

    #[test]
    fn returns_a_record_for_existing_encoded_name() {
        let response_bytes = authority()
            .build_response(&query_packet("1-2-3-4.dev.example.com.", RecordType::A))
            .unwrap_or_else(|| panic!("expected response"))
            .wire_bytes;
        let response = decode_message(&response_bytes);

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
        assert_eq!(response.answers()[0].record_type(), RecordType::A);
        assert!(response.authoritative());
    }

    #[test]
    fn chooses_most_specific_zone_for_overlapping_suffixes() {
        let response_bytes = multi_zone_authority()
            .build_response(&query_packet("dev.example.com.", RecordType::SOA))
            .unwrap_or_else(|| panic!("expected response"))
            .wire_bytes;
        let response = decode_message(&response_bytes);
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);

        let apex_name = response.answers()[0].name().to_utf8().to_ascii_lowercase();
        assert_eq!(apex_name, "dev.example.com.");
    }
}
