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

use crate::internet::body::Body;

use super::sip_message::SipMessage;
use super::sip_parser::SipParser;

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
