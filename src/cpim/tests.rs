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

use std::io::Read;
use std::sync::Arc;

use crate::imdn::GetIMDNInfo;
use crate::internet::body::message_body::MessageBody;
use crate::internet::body::Body;
use crate::internet::header::Header;

use super::CPIMMessage;

const IMDN: &[u8] = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n\
<imdn xmlns=\"urn:ietf:params:xml:ns:imdn\">\r\n\
<message-id>Kn31</message-id>\r\n\
<datetime>2023-04-04T12:16:49.000+08:00</datetime>\r\n\
<delivery-notification><status><delivered/></status></delivery-notification>\r\n\
</imdn>";

/// A CPIM message carrying `content`, written as an RCS client writes one
fn cpim(content_headers: Vec<Header>, content: &[u8]) -> Vec<u8> {
    let body = Body::Message(MessageBody {
        headers: vec![
            Header::new(b"From", b"<sip:anonymous@anonymous.invalid>"),
            Header::new(b"To", b"<sip:anonymous@anonymous.invalid>"),
            Header::new(b"DateTime", b"2023-04-04T12:16:49.000+08:00"),
            Header::new(b"NS", b"imdn <urn:ietf:params:imdn>"),
            Header::new(b"imdn.Message-ID", b"Kn31"),
        ],
        body: Arc::new(Body::Message(MessageBody {
            headers: content_headers,
            body: Arc::new(Body::Raw(content.to_vec())),
        })),
    });

    let mut data = Vec::new();
    body.reader().unwrap().read_to_end(&mut data).unwrap();
    data
}

fn parse(data: &[u8]) -> CPIMMessage {
    CPIMMessage::try_from(&Body::construct_message(data).unwrap()).unwrap()
}

#[test]
fn an_imdn_is_recognised() {
    for content_length in [true, false] {
        let mut headers = vec![
            Header::new(b"Content-Type", b"message/imdn+xml"),
            Header::new(b"Content-Disposition", b"notification"),
        ];
        if content_length {
            headers.push(Header::new(b"Content-Length", IMDN.len().to_string()));
        }
        let data = cpim(headers, IMDN);
        let message = parse(&data);

        assert!(
            message.contains_imdn(),
            "{:?}",
            String::from_utf8_lossy(&data)
        );
        assert_eq!(
            message.get_message_body(),
            Some((Some(&b"message/imdn+xml"[..]), IMDN, false))
        );
        assert_eq!(message.get_imdn_info().unwrap().imdn_id, b"Kn31");
    }
}

#[test]
fn a_chat_message_is_not_an_imdn() {
    let data = cpim(
        vec![
            Header::new(b"Content-Type", b"text/plain;charset=UTF-8"),
            Header::new(b"Content-Length", b"5"),
        ],
        b"hello",
    );
    let message = parse(&data);

    assert!(!message.contains_imdn());
    assert_eq!(
        message.get_message_body(),
        Some((Some(&b"text/plain;charset=UTF-8"[..]), &b"hello"[..], false))
    );
    let info = message.get_info().unwrap();
    assert_eq!(info.imdn_message_id, b"Kn31");
    assert_eq!(info.date, b"2023-04-04T12:16:49.000+08:00");
}

#[test]
fn the_cpim_part_of_a_multipart_body_is_read() {
    // an INVITE body with the first message: the client takes the CPIM from the
    // message/cpim part
    let cpim = cpim(vec![Header::new(b"Content-Type", b"text/plain")], b"hi");
    for content_length in [format!("Content-Length: {}\r\n", cpim.len()), String::new()] {
        let data = [
            &b"--next\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n"[..],
            format!(
                "\r\n--next\r\nContent-Type: message/cpim\r\n{}\r\n",
                content_length
            )
            .as_bytes(),
            &cpim,
            b"\r\n--next--\r\n",
        ]
        .concat();
        the_cpim_part_is_read(&data);
    }
}

fn the_cpim_part_is_read(data: &[u8]) {
    let body = Body::construct_multipart(&data, b"next").unwrap();
    let part = match &body {
        Body::Multipart(multipart) => match &*multipart.parts[1] {
            Body::Message(part) => Arc::clone(&part.body),
            _ => panic!("not a MIME part"),
        },
        _ => panic!("not multipart"),
    };
    let message = CPIMMessage::try_from(&part).unwrap();

    assert_eq!(message.get_info().unwrap().imdn_message_id, b"Kn31");
    assert_eq!(
        message.get_message_body(),
        Some((Some(&b"text/plain"[..]), &b"hi"[..], false))
    );
}

#[test]
fn multipart_content_is_handed_on_as_it_is() {
    // a chatbot message with suggestions
    let content = b"--next\r\nContent-Type: text/plain\r\n\r\nhi\r\n--next\r\n\
Content-Type: application/vnd.gsma.botsuggestion.v1.0+json\r\n\r\n{}\r\n--next--";
    let data = cpim(
        vec![
            Header::new(b"Content-Type", b"multipart/mixed;boundary=next"),
            Header::new(b"Content-Length", content.len().to_string()),
        ],
        content,
    );
    let message = parse(&data);

    assert_eq!(
        message.get_message_body(),
        Some((
            Some(&b"multipart/mixed;boundary=next"[..]),
            &content[..],
            false
        ))
    );
}

#[test]
fn an_imdn_is_recognised_whatever_the_case_of_its_headers() {
    // RFC 5438 writes Content-type and Content-length
    let data = cpim(
        vec![
            Header::new(b"Content-type", b"message/imdn+xml"),
            Header::new(b"Content-Disposition", b"Notification"),
            Header::new(b"Content-length", IMDN.len().to_string()),
        ],
        IMDN,
    );
    let message = parse(&data);

    assert!(message.contains_imdn());
    assert_eq!(
        message.get_message_body(),
        Some((Some(&b"message/imdn+xml"[..]), IMDN, false))
    );
}

#[test]
fn folded_mime_headers_are_read() {
    let data = cpim(
        vec![Header::new(
            b"Content-Type",
            b"text/plain;\r\n charset=UTF-8",
        )],
        b"hi",
    );
    let message = parse(&data);

    assert_eq!(
        message.get_message_body(),
        Some((Some(&b"text/plain; charset=UTF-8"[..]), &b"hi"[..], false))
    );
}
