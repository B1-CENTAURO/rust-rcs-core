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

use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::runtime::Runtime;

use crate::internet::body::Body;

use super::sip_dialog::{GetDialogHeaderInfo, GetDialogHeaders, GetDialogIdentifier};
use super::sip_message::{SipMessage, SUBSCRIBE};
use super::sip_message::{BYE, OPTIONS, REGISTER};
use super::sip_parser::SipParser;
use super::sip_subscription::subscribe_request::SubscribeRequest;
use super::sip_subscription::subscriber::{Subscriber, SubscriberEvent};
use super::sip_subscription::{InitialSubscribeContext, SubscriptionManager};
use super::sip_transaction::client_transaction::ClientTransactionCallbacks;
use super::sip_transaction::SipTransactionManager;
use super::sip_transport::{setup_sip_transport, SipTransport, SipTransportType};
use super::{SipCore, SipDialog};
use crate::internet::header::Header;

fn parse(head: &str, body: &[u8]) -> SipMessage {
    let data = [
        format!("{}Content-Length: {}\r\n\r\n", head, body.len()).as_bytes(),
        body,
    ]
    .concat();

    let mut parser = SipParser::new();
    parser.feed(&data);
    parser.produce().unwrap().expect("a complete message")
}

fn raw_body(message: &SipMessage) -> Vec<u8> {
    match message.get_body().as_deref() {
        Some(Body::Raw(raw)) => raw.clone(),
        _ => panic!("not a raw body"),
    }
}

const NOTIFY: &str = "NOTIFY sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/TCP 192.0.2.2;branch=z9hG4bK776asdhds\r\n\
From: <sip:conference@example.com>;tag=1928301774\r\n\
To: <sip:alice@example.com>;tag=a6c85cf\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 2 NOTIFY\r\n\
Event: refer\r\n\
Subscription-State: active;expires=60\r\n";

#[test]
fn a_sipfrag_body_is_kept_as_it_is() {
    // a NOTIFY reporting on a REFER, as when adding to a group chat, and a
    // fragment starting with a request line, which has a colon in it
    for sipfrag in [
        &b"SIP/2.0 200 OK\r\n"[..],
        b"INVITE sip:bob@example.com SIP/2.0\r\nContact: <sip:bob@192.0.2.3>\r\n",
    ] {
        let message = parse(
            &format!("{}Content-Type: message/sipfrag;version=2.0\r\n", NOTIFY),
            sipfrag,
        );
        assert_eq!(raw_body(&message), sipfrag);
    }
}

#[test]
fn a_body_not_reading_as_its_type_is_kept_as_it_is() {
    for content_type in [
        "Content-Type: multipart/mixed;boundary=other\r\n",
        "Content-Type: multipart/mixed\r\n",
        "Content-Type: message/cpim\r\n",
        "Content-Type: nothing\r\n",
        "",
    ] {
        let message = parse(
            &format!("{}{}", NOTIFY, content_type),
            b"no headers\r\n\r\n--next--",
        );
        assert_eq!(
            raw_body(&message),
            b"no headers\r\n\r\n--next--",
            "{:?}",
            content_type
        );
    }
}

#[test]
fn a_content_length_past_the_end_of_a_message_body_is_not_taken() {
    // it once panicked the parser, and with it the transport's read task
    let cpim = b"From: <sip:anonymous@anonymous.invalid>\r\nContent-Length:500\r\n\r\n\
Content-Type: text/plain\r\n\r\nhi";
    let data = [
        format!(
            "MESSAGE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/TCP 192.0.2.1;branch=z9hG4bK776asdhds\r\n\
From: <sip:alice@example.com>;tag=1928301774\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 1 MESSAGE\r\n\
Max-Forwards: 70\r\n\
Content-Type: message/cpim\r\n\
Content-Length: {}\r\n\r\n",
            cpim.len()
        )
        .as_bytes(),
        cpim,
    ]
    .concat();

    let mut parser = SipParser::new();
    parser.feed(&data);
    let message = parser.produce().unwrap().expect("a complete message");

    match message.get_body().as_deref() {
        Some(Body::Message(cpim)) => match &*cpim.body {
            Body::Raw(raw) => assert_eq!(raw, b"Content-Type: text/plain\r\n\r\nhi"),
            _ => panic!("not raw content"),
        },
        _ => panic!("message/cpim body not parsed"),
    }
}

fn header_value(message: &SipMessage, name: &[u8]) -> Vec<u8> {
    crate::internet::header::search(message.headers().unwrap(), name, true)
        .unwrap()
        .get_value()
        .to_vec()
}

const FOLDED: &[u8] = b"MESSAGE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/TCP 192.0.2.1;branch=z9hG4bK776asdhds\r\n\
From: <sip:alice@example.com>;tag=1928301774\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 1 MESSAGE\r\n\
Subject: I know you're there,\r\n  pick up the phone\r\n\tand talk to me!\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\
\r\n";

#[test]
fn a_header_folded_with_a_space_or_a_tab_is_unfolded() {
    let mut parser = SipParser::new();
    parser.feed(FOLDED);
    let message = parser.produce().unwrap().expect("a complete message");

    assert_eq!(
        header_value(&message, b"Subject"),
        b"I know you're there,  pick up the phone and talk to me!"
    );
    assert_eq!(header_value(&message, b"Max-Forwards"), b"70");
}

#[test]
fn a_folded_header_arriving_in_pieces_is_read_once() {
    // the message split in two at each point, and a byte at a time, as a
    // connection may give it
    let mut feeds: Vec<Vec<&[u8]>> = (1..FOLDED.len())
        .map(|i| vec![&FOLDED[..i], &FOLDED[i..]])
        .collect();
    feeds.push(FOLDED.chunks(1).collect());

    for pieces in feeds {
        let mut parser = SipParser::new();
        let mut message = None;
        for piece in &pieces {
            parser.feed(piece);
            if let Some(m) = parser.produce().unwrap() {
                message = Some(m);
            }
        }
        let message = message.expect("a complete message");

        assert_eq!(
            header_value(&message, b"Subject"),
            b"I know you're there,  pick up the phone and talk to me!",
            "split at {}",
            pieces[0].len()
        );
        assert_eq!(header_value(&message, b"Max-Forwards"), b"70");
    }
}

#[test]
fn a_heartbeat_pings_and_one_unanswered_closes_the_transport() {
    let rt = Arc::new(Runtime::new().unwrap());
    let (tm, _tm_events) = SipTransactionManager::new(&rt);
    let transport = Arc::new(SipTransport::new::<DuplexStream>(
        String::from("192.0.2.10:5060"),
        SipTransportType::TCP,
    ));
    let (ours, mut theirs) = tokio::io::duplex(4096);
    let (exit_tx, exit_rx) = mpsc::channel();
    let tx = setup_sip_transport(
        &transport,
        ours,
        tm.get_ctrl_itf(),
        Arc::clone(&rt),
        move || {
            let _ = exit_tx.send(());
        },
    );
    tm.register_sip_transport(Arc::clone(&transport), tx);
    let mut data = [0; 16];

    // a ping (RFC 5626 section 4.4.1), answered: the transport stays
    tm.send_heartbeat(&transport, &rt);
    let size = rt.block_on(theirs.read(&mut data)).unwrap();
    assert_eq!(&data[..size], b"\r\n\r\n");
    rt.block_on(theirs.write_all(b"\r\n")).unwrap();
    assert_eq!(
        exit_rx.recv_timeout(Duration::from_secs(2)),
        Err(RecvTimeoutError::Timeout)
    );

    // unanswered: the transport is closed, and its owner told
    tm.send_heartbeat(&transport, &rt);
    let size = rt.block_on(theirs.read(&mut data)).unwrap();
    assert_eq!(&data[..size], b"\r\n\r\n");
    exit_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the transport is closed");
    assert_eq!(rt.block_on(theirs.read(&mut data)).unwrap(), 0);
}

/// The far end of a transport, reading what we send and writing to us
struct Peer {
    stream: DuplexStream,
    parser: SipParser,
}

impl Peer {
    fn next(&mut self, rt: &Runtime) -> SipMessage {
        rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    match self.parser.produce().unwrap() {
                        Some(SipMessage::Ping) | Some(SipMessage::Pong) => {}
                        Some(message) => return message,
                        None => {
                            let mut data = [0; 4096];
                            let size = self.stream.read(&mut data).await.unwrap();
                            assert!(size > 0, "the transport closed");
                            self.parser.feed(&data[..size]);
                        }
                    }
                }
            })
            .await
            .expect("a message")
        })
    }

    fn send(&mut self, rt: &Runtime, data: &str) {
        rt.block_on(self.stream.write_all(data.as_bytes())).unwrap();
    }
}

fn status_code(message: &SipMessage) -> u16 {
    match message {
        SipMessage::Response(line, _, _) => line.status_code,
        _ => panic!("not a response"),
    }
}

/// A 200 to `request`, its To given `tag`
fn ok(request: &SipMessage, tag: &str, extra: &str) -> String {
    let mut data = String::from("SIP/2.0 200 OK\r\n");
    for header in request.headers().unwrap() {
        let name = String::from_utf8_lossy(header.get_name());
        let value = String::from_utf8_lossy(header.get_value());
        match &name.to_ascii_lowercase()[..] {
            "via" | "from" | "call-id" | "cseq" => {
                data += &format!("{}: {}\r\n", name, value);
            }
            "to" => data += &format!("To: {};tag={}\r\n", value, tag),
            _ => {}
        }
    }
    data + extra + "Content-Length: 0\r\n\r\n"
}

#[test]
fn notifies_after_the_first_reach_their_subscription() {
    // reg, which cannot fork, and conference, which can; with a Contact, the
    // SUBSCRIBE's 2xx makes the dialog the first NOTIFY then takes
    for (event, contact) in [
        ("reg", true),
        ("reg", false),
        ("conference", true),
        ("conference", false),
    ] {
        let rt = Arc::new(Runtime::new().unwrap());
        let (tm, tm_events) = SipTransactionManager::new(&rt);
        let tm = Arc::new(tm);
        let sm = Arc::new(SubscriptionManager::new(500));
        let core = Arc::new(SipCore::new(
            &sm,
            &tm,
            tm_events,
            vec![b"NOTIFY"],
            Vec::new(),
            &rt,
        ));
        let transport = Arc::new(SipTransport::new::<DuplexStream>(
            String::from("192.0.2.10:5060"),
            SipTransportType::TCP,
        ));
        let (ours, theirs) = tokio::io::duplex(65536);
        let tx = setup_sip_transport(&transport, ours, tm.get_ctrl_itf(), Arc::clone(&rt), || {});
        tm.register_sip_transport(Arc::clone(&transport), tx);
        let mut peer = Peer {
            stream: theirs,
            parser: SipParser::new(),
        };

        let (notified_tx, notified_rx) = mpsc::channel();
        let subscriber = Arc::new(Subscriber::new(
            "test",
            move |subscriber_event| {
                if let SubscriberEvent::ReceivedNotify(_, _, body) = subscriber_event {
                    if let Body::Raw(raw) = body.as_ref() {
                        let _ = notified_tx.send(raw.clone());
                    }
                }
            },
            move |_, expiration| {
                let mut message = SipMessage::new_request(SUBSCRIBE, b"sip:alice@example.com");
                message.add_header(Header::new(b"Call-ID", b"subscription-1"));
                message.add_header(Header::new(b"CSeq", b"1 SUBSCRIBE"));
                message.add_header(Header::new(b"From", b"<sip:alice@example.com>;tag=sub1"));
                message.add_header(Header::new(b"To", b"<sip:alice@example.com>"));
                message.add_header(Header::new(
                    b"Contact",
                    b"<sip:alice@192.0.2.10:5060;transport=tcp>",
                ));
                message.add_header(Header::new(b"Expires", expiration.to_string()));
                message.add_header(Header::new(b"Event", event));
                Ok(message)
            },
        ));
        let request = subscriber.build_request(None, 600).unwrap();
        let subscribe_request = Arc::new(SubscribeRequest::new(&request, subscriber).unwrap());
        sm.register_request(Arc::clone(&subscribe_request), &rt);
        tm.send_request(
            request,
            &transport,
            InitialSubscribeContext::new(subscribe_request, Arc::clone(&core), Arc::clone(&rt)),
            &rt,
        );

        let subscribe = peer.next(&rt);
        peer.send(
            &rt,
            &ok(
                &subscribe,
                "notifier1",
                if contact {
                    "Expires: 600\r\nContact: <sip:notifier@192.0.2.1:5060;transport=tcp>\r\n"
                } else {
                    "Expires: 600\r\n"
                },
            ),
        );

        for seq in 1..=3 {
            peer.send(
                &rt,
                &format!(
                    "NOTIFY sip:alice@192.0.2.10:5060;transport=tcp SIP/2.0\r\n\
Via: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bKnotify{}\r\n\
From: <sip:alice@example.com>;tag=notifier1\r\n\
To: <sip:alice@example.com>;tag=sub1\r\n\
Call-ID: subscription-1\r\n\
CSeq: {} NOTIFY\r\n\
Contact: <sip:notifier@192.0.2.1:5060;transport=tcp>\r\n\
Event: {}\r\n\
Subscription-State: active;expires=600\r\n\
Max-Forwards: 70\r\n\
Content-Type: text/plain\r\n\
Content-Length: 1\r\n\
\r\n\
{}",
                    seq, seq, event, seq
                ),
            );
            let response = peer.next(&rt);
            assert_eq!(
                status_code(&response),
                200,
                "NOTIFY {} of {}, Contact {}",
                seq,
                event,
                contact
            );
            assert_eq!(
                notified_rx.recv_timeout(Duration::from_secs(5)),
                Ok(seq.to_string().into_bytes()),
                "NOTIFY {} of {}",
                seq,
                event
            );
        }
        assert_eq!(
            notified_rx.recv_timeout(Duration::from_millis(500)),
            Err(RecvTimeoutError::Timeout)
        );
    }
}

fn read_message(data: &[u8]) -> SipMessage {
    let mut parser = SipParser::new();
    parser.feed(data);
    parser.produce().unwrap().expect("a complete message")
}

#[test]
fn a_dialog_we_answer_is_ours_from_the_to() {
    // Alice invites us, Bob, and we answer: the dialog is ours as UAS
    let invite = read_message(
        b"INVITE sip:bob@192.0.2.10:5060 SIP/2.0\r\n\
Via: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bKinvite1\r\n\
From: <sip:alice@example.com>;tag=alice1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: session-1\r\n\
CSeq: 7 INVITE\r\n\
Contact: <sip:alice@192.0.2.20:5060;transport=tcp>\r\n\
Content-Length: 0\r\n\r\n",
    );
    let ok = read_message(
        b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bKinvite1\r\n\
From: <sip:alice@example.com>;tag=alice1\r\n\
To: <sip:bob@example.com>;tag=bob1\r\n\
Call-ID: session-1\r\n\
CSeq: 7 INVITE\r\n\
Contact: <sip:bob@192.0.2.10:5060;transport=tcp>\r\n\
Content-Length: 0\r\n\r\n",
    );
    let dialog = SipDialog::try_new_as_uas(&invite, &ok, |_| {}).unwrap();

    let identifier = dialog.dialog_identifier();
    assert_eq!(identifier.local_tag, b"bob1");
    assert_eq!(identifier.remote_tag, b"alice1");

    // a BYE from Alice is in the dialog
    let bye = read_message(
        b"BYE sip:bob@192.0.2.10:5060 SIP/2.0\r\n\
Via: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bKbye1\r\n\
From: <sip:alice@example.com>;tag=alice1\r\n\
To: <sip:bob@example.com>;tag=bob1\r\n\
Call-ID: session-1\r\n\
CSeq: 8 BYE\r\n\
Content-Length: 0\r\n\r\n",
    );
    let (call_id, from, to) = bye.get_dialog_headers().unwrap();
    let from_to = (from, to);
    let (from, to) = from_to.get_dialog_header_info();
    assert!((call_id, from, to, false).get_dialog_identifier() == Some(identifier));

    // and our BYE is from Bob to Alice
    let our_bye = dialog.make_request(BYE, None).unwrap();
    let headers = our_bye.headers().unwrap();
    let value = |name: &[u8]| {
        String::from_utf8_lossy(
            crate::internet::header::search(headers, name, true)
                .unwrap()
                .get_value(),
        )
        .into_owned()
    };
    assert!(
        value(b"From").contains("bob@example.com"),
        "{}",
        value(b"From")
    );
    assert!(value(b"From").contains("tag=bob1"), "{}", value(b"From"));
    assert!(
        value(b"To").contains("alice@example.com"),
        "{}",
        value(b"To")
    );
    assert!(value(b"To").contains("tag=alice1"), "{}", value(b"To"));
}

struct NoCallbacks;

impl ClientTransactionCallbacks for NoCallbacks {
    fn on_provisional_response(&self, _message: SipMessage) {}
    fn on_final_response(&self, _message: SipMessage) {}
    fn on_transport_error(&self) {}
}

#[test]
fn the_service_route_is_preloaded_on_requests_out_of_dialog() {
    let rt = Arc::new(Runtime::new().unwrap());
    let (tm, _tm_events) = SipTransactionManager::new(&rt);
    let transport = Arc::new(SipTransport::new::<DuplexStream>(
        String::from("192.0.2.10:5060"),
        SipTransportType::TCP,
    ));
    let (ours, theirs) = tokio::io::duplex(65536);
    let tx = setup_sip_transport(&transport, ours, tm.get_ctrl_itf(), Arc::clone(&rt), || {});
    tm.register_sip_transport(Arc::clone(&transport), tx);
    let mut peer = Peer {
        stream: theirs,
        parser: SipParser::new(),
    };

    transport.set_service_route(vec![
        b"<sip:orig@scscf1.example.com;lr>".to_vec(),
        b"<sip:scscf2.example.com;lr>".to_vec(),
    ]);

    for (method, to, route, expected) in [
        (
            OPTIONS,
            "<sip:bob@example.com>",
            None,
            vec![
                "<sip:orig@scscf1.example.com;lr>",
                "<sip:scscf2.example.com;lr>",
            ],
        ),
        (REGISTER, "<sip:alice@example.com>", None, vec![]),
        (OPTIONS, "<sip:bob@example.com>;tag=bob1", None, vec![]),
        (
            OPTIONS,
            "<sip:bob@example.com>",
            Some("<sip:elsewhere.example.com;lr>"),
            vec!["<sip:elsewhere.example.com;lr>"],
        ),
    ] {
        let mut message = SipMessage::new_request(method, b"sip:bob@example.com");
        message.add_header(Header::new(b"Call-ID", b"route-1"));
        message.add_header(Header::new(
            b"CSeq",
            format!("1 {}", String::from_utf8_lossy(method)),
        ));
        message.add_header(Header::new(b"From", b"<sip:alice@example.com>;tag=alice1"));
        message.add_header(Header::new(b"To", to));
        if let Some(route) = route {
            message.add_header(Header::new(b"Route", route));
        }
        tm.send_request(message, &transport, NoCallbacks, &rt);

        let sent = peer.next(&rt);
        let routes: Vec<String> =
            crate::internet::header::HeaderSearch::new(sent.headers().unwrap(), b"Route", true)
                .map(|h| String::from_utf8_lossy(h.get_value()).into_owned())
                .collect();
        assert_eq!(
            routes,
            expected,
            "{} to {}",
            String::from_utf8_lossy(method),
            to
        );
    }
}
