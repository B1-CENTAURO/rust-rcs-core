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

use super::message_body::MessageBody;
use super::Body;

use crate::internet::header;

fn raw(body: &Body) -> &[u8] {
    match body {
        Body::Raw(raw) => raw,
        _ => panic!("not raw content"),
    }
}

fn value<'a>(message: &'a MessageBody, name: &[u8]) -> &'a [u8] {
    header::search(&message.headers, name, false)
        .unwrap()
        .get_value()
}

#[test]
fn header_values_leave_out_the_whitespace_around_them() {
    let message = MessageBody::construct(
        b"Content-Type: text/plain\r\nX-Padded:  \tsome value \r\nX-Bare:value\r\n\r\nhi",
    )
    .unwrap();

    assert_eq!(value(&message, b"Content-Type"), b"text/plain");
    assert_eq!(value(&message, b"X-Padded"), b"some value");
    assert_eq!(value(&message, b"X-Bare"), b"value");
    assert_eq!(raw(&message.body), b"hi");
}

#[test]
fn content_length_ends_the_content() {
    for separator in [": ", ":"] {
        let data = format!(
            "Content-Type: text/plain\r\nContent-Length{}5\r\n\r\nhello\r\n",
            separator
        );
        let message = MessageBody::construct(data.as_bytes()).unwrap();
        assert_eq!(raw(&message.body), b"hello", "{:?}", data);
    }
}

#[test]
fn content_length_past_the_end_is_not_taken() {
    for separator in [": ", ":"] {
        for length in ["6", "500", "18446744073709551615"] {
            let data = format!(
                "Content-Type: text/plain\r\nContent-Length{}{}\r\n\r\nhello",
                separator, length
            );
            let message = MessageBody::construct(data.as_bytes()).unwrap();
            assert_eq!(raw(&message.body), b"hello", "{:?}", data);
        }
    }
}

#[test]
fn message_cpim_content_is_parsed_and_imdn_content_is_not() {
    let cpim = b"From: <sip:anonymous@anonymous.invalid>\r\n\r\nContent-Type: text/plain\r\n\r\nhi";
    let data = [
        format!(
            "Content-Type: message/cpim\r\nContent-Length: {}\r\n\r\n",
            cpim.len()
        )
        .as_bytes(),
        cpim,
    ]
    .concat();
    let message = MessageBody::construct(&data).unwrap();
    match &*message.body {
        Body::Message(cpim) => {
            assert_eq!(value(cpim, b"From"), b"<sip:anonymous@anonymous.invalid>");
            assert_eq!(raw(&cpim.body), b"Content-Type: text/plain\r\n\r\nhi");
        }
        _ => panic!("message/cpim content not parsed"),
    }

    let imdn = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n\
<imdn xmlns=\"urn:ietf:params:xml:ns:imdn\"><message-id>Kn31</message-id></imdn>";
    let data = [
        format!(
            "Content-Type: message/imdn+xml\r\nContent-Length: {}\r\n\r\n",
            imdn.len()
        )
        .as_bytes(),
        imdn,
    ]
    .concat();
    let message = MessageBody::construct(&data).unwrap();
    assert_eq!(raw(&message.body), imdn);
}

#[test]
fn multipart_parts_are_read_by_their_content_type() {
    // an INVITE body with the first message, as in a chat or large-mode INVITE
    let sdp = b"v=0\r\n";
    let cpim = b"From: <sip:anonymous@anonymous.invalid>\r\n\r\nContent-Type: text/plain\r\n\r\nhi";
    let data = [
        &b"--next\r\n"[..],
        format!(
            "Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n",
            sdp.len()
        )
        .as_bytes(),
        sdp,
        b"\r\n--next\r\n",
        format!(
            "Content-Type: message/cpim\r\nContent-Length: {}\r\n\r\n",
            cpim.len()
        )
        .as_bytes(),
        cpim,
        b"\r\n--next--\r\n",
    ]
    .concat();

    let body = Body::construct_multipart(&data, b"next").unwrap();
    let parts = match &body {
        Body::Multipart(multipart) => &multipart.parts,
        _ => panic!("not multipart"),
    };
    assert_eq!(parts.len(), 2);

    match &*parts[0] {
        Body::Message(part) => {
            assert_eq!(value(part, b"Content-Type"), b"application/sdp");
            assert_eq!(raw(&part.body), sdp);
        }
        _ => panic!("not a MIME part"),
    }

    match &*parts[1] {
        Body::Message(part) => {
            assert_eq!(value(part, b"Content-Type"), b"message/cpim");
            match &*part.body {
                Body::Message(cpim) => {
                    assert_eq!(raw(&cpim.body), b"Content-Type: text/plain\r\n\r\nhi")
                }
                _ => panic!("message/cpim content not parsed"),
            }
        }
        _ => panic!("not a MIME part"),
    }
}

#[test]
fn header_names_are_matched_whatever_their_case() {
    let message =
        MessageBody::construct(b"content-type: message/cpim\r\ncontent-length: 21\r\n\r\nFrom: <sip:a@b>\r\n\r\nhi\r\n\r\n")
            .unwrap();
    match &*message.body {
        Body::Message(cpim) => assert_eq!(raw(&cpim.body), b"hi"),
        _ => panic!("message/cpim content not parsed"),
    }
}
