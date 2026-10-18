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

use super::sip_parser::SipParser;

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
