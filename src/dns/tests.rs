// Copyright 2023 宋昊文
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use hickory_client::op::{Message, MessageType, ResponseCode};
use hickory_client::rr::rdata::{NAPTR, SRV};
use hickory_client::rr::{Name, RData, Record, RecordType};
use hickory_client::serialize::binary::{BinDecodable, BinEncodable};
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;
use tokio_stream::StreamExt;

use super::{DnsClient, DnsConfig};

fn name(name: &str) -> Name {
    Name::from_str(name).unwrap()
}

fn naptr(owner: &str, order: u16, preference: u16, service: &str, replacement: &str) -> Record {
    Record::from_rdata(
        name(owner),
        300,
        RData::NAPTR(NAPTR::new(
            order,
            preference,
            b"s".to_vec().into_boxed_slice(),
            service.as_bytes().to_vec().into_boxed_slice(),
            Vec::new().into_boxed_slice(),
            name(replacement),
        )),
    )
}

fn srv(owner: &str, priority: u16, weight: u16, port: u16, target: &str) -> Record {
    Record::from_rdata(
        name(owner),
        300,
        RData::SRV(SRV::new(priority, weight, port, name(target))),
    )
}

/// A DNS server answering from `records`, which holds the answers to each
/// name and type it knows, and counting the queries it gets
fn dns_server(rt: &Runtime, records: Vec<Record>) -> (DnsConfig, Arc<std::sync::Mutex<usize>>) {
    let mut answers: HashMap<(Name, RecordType), Vec<Record>> = HashMap::new();
    for record in records {
        answers
            .entry((record.name().clone(), record.record_type()))
            .or_default()
            .push(record);
    }

    let socket = rt.block_on(UdpSocket::bind("127.0.0.1:0")).unwrap();
    let addr: SocketAddr = socket.local_addr().unwrap();
    let queries = Arc::new(std::sync::Mutex::new(0));
    let queries_ = Arc::clone(&queries);

    rt.spawn(async move {
        let mut data = [0; 4096];
        while let Ok((size, from)) = socket.recv_from(&mut data).await {
            let request = Message::from_bytes(&data[..size]).unwrap();
            *queries_.lock().unwrap() += 1;
            let query = request.queries()[0].clone();

            let mut response = Message::new();
            response.set_id(request.id());
            response.set_message_type(MessageType::Response);
            response.set_recursion_desired(request.recursion_desired());
            response.add_query(query.clone());
            match answers.get(&(query.name().clone(), query.query_type())) {
                Some(records) => {
                    response.add_answers(records.iter().cloned());
                }
                None => {
                    response.set_response_code(ResponseCode::NXDomain);
                }
            }

            let _ = socket.send_to(&response.to_bytes().unwrap(), from).await;
        }
    });

    (
        DnsConfig {
            server_addrs: vec![addr],
        },
        queries,
    )
}

fn resolve_service(
    rt: &Arc<Runtime>,
    client: &DnsClient,
    config: &DnsConfig,
    domain: &str,
    service: &str,
) -> Vec<(String, u16)> {
    rt.block_on(async {
        client
            .resolve_service(config.clone(), String::from(domain), String::from(service))
            .await
            .ok()
            .unwrap()
            .collect::<Vec<_>>()
            .await
    })
}

#[test]
fn naptr_records_are_followed_in_order_through_their_srv_records() {
    let rt = Arc::new(Runtime::new().unwrap());
    let (config, _) = dns_server(
        &rt,
        vec![
            naptr(
                "ims.example.com.",
                20,
                10,
                "SIPS+D2T",
                "_sips._tcp.second.example.com.",
            ),
            naptr(
                "ims.example.com.",
                10,
                20,
                "SIPS+D2T",
                "_sips._tcp.first.example.com.",
            ),
            naptr(
                "ims.example.com.",
                5,
                10,
                "SIP+D2U",
                "_sip._udp.ims.example.com.",
            ),
            srv(
                "_sips._tcp.first.example.com.",
                20,
                0,
                5061,
                "c.example.com.",
            ),
            srv(
                "_sips._tcp.first.example.com.",
                10,
                10,
                5061,
                "b.example.com.",
            ),
            srv(
                "_sips._tcp.first.example.com.",
                10,
                60,
                5061,
                "a.example.com.",
            ),
            srv(
                "_sips._tcp.second.example.com.",
                0,
                0,
                5062,
                "d.example.com.",
            ),
            srv("_sip._udp.ims.example.com.", 0, 0, 5060, "udp.example.com."),
        ],
    );
    let client = DnsClient::new(Arc::clone(&rt));

    assert_eq!(
        resolve_service(&rt, &client, &config, "ims.example.com", "SIPS+D2T"),
        [
            (String::from("a.example.com"), 5061),
            (String::from("b.example.com"), 5061),
            (String::from("c.example.com"), 5061),
            (String::from("d.example.com"), 5062),
        ]
    );
}

#[test]
fn without_naptr_records_the_srv_records_are_used() {
    let rt = Arc::new(Runtime::new().unwrap());
    let (config, _) = dns_server(
        &rt,
        vec![
            srv("_sips._tcp.ims.example.com.", 1, 0, 5061, "b.example.com."),
            srv("_sips._tcp.ims.example.com.", 0, 0, 5061, "a.example.com."),
            // "." is no target
            srv("_sips._tcp.ims.example.com.", 2, 0, 5061, "."),
        ],
    );
    let client = DnsClient::new(Arc::clone(&rt));

    assert_eq!(
        resolve_service(&rt, &client, &config, "ims.example.com", "SIPS+D2T"),
        [
            (String::from("a.example.com"), 5061),
            (String::from("b.example.com"), 5061),
        ]
    );
}

#[test]
fn without_naptr_or_srv_records_the_domain_is_used_on_the_default_port() {
    let rt = Arc::new(Runtime::new().unwrap());
    let (config, _) = dns_server(&rt, Vec::new());
    let client = DnsClient::new(Arc::clone(&rt));

    assert_eq!(
        resolve_service(&rt, &client, &config, "tls.example.com", "SIPS+D2T"),
        [(String::from("tls.example.com"), 5061)]
    );
    assert_eq!(
        resolve_service(&rt, &client, &config, "tcp.example.com", "SIP+D2T"),
        [(String::from("tcp.example.com"), 5060)]
    );
}

#[test]
fn an_address_is_not_looked_up() {
    let rt = Arc::new(Runtime::new().unwrap());
    let (config, queries) = dns_server(&rt, Vec::new());
    let client = DnsClient::new(Arc::clone(&rt));

    assert_eq!(
        resolve_service(&rt, &client, &config, "192.0.2.1", "SIP+D2T"),
        [(String::from("192.0.2.1"), 5060)]
    );
    for (host, ip) in [
        ("192.0.2.1", IpAddr::from([192, 0, 2, 1])),
        ("[2001:db8::1]", IpAddr::from_str("2001:db8::1").unwrap()),
    ] {
        let addresses: Vec<IpAddr> = rt.block_on(async {
            client
                .resolve(config.clone(), String::from(host))
                .await
                .ok()
                .unwrap()
                .collect()
                .await
        });
        assert_eq!(addresses, [ip]);
    }
    assert_eq!(*queries.lock().unwrap(), 0);
}
