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

use std::borrow::Cow;
use std::io::Read;
use std::sync::Arc;

use crate::imdn::GetIMDNInfo;
use crate::internet::body::message_body::MessageBody;
use crate::internet::body::multipart_body::MultipartBody;
use crate::internet::body::Body;
use crate::internet::header::Header;
use crate::io::DynamicChain;

use super::{escape, unescape, CPIMHeaderValue, CPIMMessage, CPIMNamespace};

const IMDN: &[u8] = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n\
<imdn xmlns=\"urn:ietf:params:xml:ns:imdn\">\r\n\
<message-id>Kn31</message-id>\r\n\
<datetime>2023-04-04T12:16:49.000+08:00</datetime>\r\n\
<delivery-notification><status><delivered/></status></delivery-notification>\r\n\
</imdn>";

// RFC 3862 section 5.1, without the MIME headers before it
const RFC_3862_EXAMPLE: &[u8] = b"From: MR SANDERS <im:piglet@100akerwood.com>\r\n\
To: Depressed Donkey <im:eeyore@100akerwood.com>\r\n\
DateTime: 2000-12-13T13:40:00-08:00\r\n\
Subject: the weather will be fine today\r\n\
Subject:;lang=fr beau temps prevu pour aujourd'hui\r\n\
NS: MyFeatures <mid:MessageFeatures@id.foo.com>\r\n\
Require: MyFeatures.VitalMessageOption\r\n\
MyFeatures.VitalMessageOption: Confirmation-requested\r\n\
MyFeatures.WackyMessageOption: Use-silly-font\r\n\
\r\n\
Content-type: text/xml; charset=utf-8\r\n\
Content-ID: <1234567890@foo.com>\r\n\
\r\n\
<body>\r\n\
Here is the text of my message.\r\n\
</body>\r\n";

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

fn values(message: &CPIMMessage, name: &[u8]) -> Vec<Vec<u8>> {
    message
        .get_values(name)
        .iter()
        .map(|value| value.value.to_vec())
        .collect()
}

#[test]
fn subjects_are_read_with_their_languages() {
    let message = parse(RFC_3862_EXAMPLE);
    let subjects = message.get_values(b"Subject");

    assert_eq!(subjects.len(), 2);
    assert_eq!(subjects[0].lang(), None);
    assert_eq!(subjects[0].value, b"the weather will be fine today");
    assert_eq!(subjects[1].lang(), Some(&b"fr"[..]));
    assert_eq!(subjects[1].value, b"beau temps prevu pour aujourd'hui");
}

#[test]
fn parameters_are_split_from_values() {
    let value = CPIMHeaderValue::parse(b";lang=fr;x=\"a; \\\"b\";flag text; with ;semicolons");
    assert_eq!(
        value.parameters,
        [
            (&b"lang"[..], &b"fr"[..]),
            (b"x", b"\"a; \\\"b\""),
            (b"flag", b""),
        ]
    );
    assert_eq!(value.value, b"text; with ;semicolons");

    let value = CPIMHeaderValue::parse(b"<sip:alice@example.com>");
    assert!(value.parameters.is_empty());
    assert_eq!(value.value, b"<sip:alice@example.com>");
}

#[test]
fn every_to_and_cc_is_read() {
    let message = parse(
        b"From: <sip:alice@example.com>\r\n\
To:;x=1 <sip:bob@example.com>\r\n\
To: Carol <sip:carol@example.com>\r\n\
cc: <sip:dave@example.com>\r\n\
cc: <sip:erin@example.com>\r\n\
NS: imdn <urn:ietf:params:imdn>\r\n\
imdn.Message-ID: x1\r\n\
DateTime: 2023-04-04T12:16:49Z\r\n\
\r\n\
Content-Type: text/plain\r\n\
\r\n\
hi",
    );

    assert_eq!(
        values(&message, b"To"),
        [
            &b"<sip:bob@example.com>"[..],
            b"Carol <sip:carol@example.com>"
        ]
    );
    assert_eq!(
        values(&message, b"cc"),
        [&b"<sip:dave@example.com>"[..], b"<sip:erin@example.com>"]
    );
    assert_eq!(
        values(&message, b"<urn:ietf:params:imdn>.Message-ID"),
        [b"x1"]
    );

    // the first To, without its parameter
    let info = message.get_info().unwrap();
    assert_eq!(info.to, b"<sip:bob@example.com>");
    assert!(info.to_uri.is_some());
}

#[test]
fn requirements_not_understood_are_listed() {
    let message = parse(RFC_3862_EXAMPLE);
    let vital: &[u8] = b"<mid:MessageFeatures@id.foo.com>.VitalMessageOption";
    assert_eq!(message.get_unmet_requirements(&[]), [vital]);
    assert!(message.get_unmet_requirements(&[vital]).is_empty());

    // several Require headers and lists, with NS and Require understood here
    let message = parse(
        b"From: <sip:alice@example.com>\r\n\
NS: x <urn:example:x>\r\n\
Require: x.One, x.Two,Subject\r\n\
Require: x.One\r\n\
Require: NS,Require\r\n\
\r\n\
Content-Type: text/plain\r\n\
\r\n\
hi",
    );
    assert_eq!(
        message.get_unmet_requirements(&[b"Subject"]),
        [&b"<urn:example:x>.One"[..], b"<urn:example:x>.Two"]
    );
}

#[test]
fn escapes_are_decoded() {
    for (escaped, unescaped) in [
        (&b"a\\\\b \\\"q\\\" \\'s\\'"[..], "a\\b \"q\" 's'"),
        (b"\\b\\t\\n\\r", "\u{8}\t\n\r"),
        (b"caf\\u00e9 \\u0007 \\u00E9", "caf\u{e9} \u{7} \u{e9}"),
        (b"\\uD83D\\uDE00", "\u{1f600}"),
        (b"\\ud83d alone", "\u{fffd} alone"),
        (b"\\x \\u12 \\u+123", "x u12 u+123"),
        (b"end\\", "end"),
    ] {
        assert_eq!(
            unescape(escaped),
            unescaped.as_bytes(),
            "{:?}",
            String::from_utf8_lossy(escaped)
        );
    }

    assert!(matches!(unescape(b"plain"), Cow::Borrowed(b"plain")));
}

#[test]
fn values_are_read_from_a_message_built_with_new() {
    let message = CPIMMessage::new(
        &[(b"imdn", b"urn:ietf:params:imdn")],
        vec![
            Header::new(b"imdn.Message-ID", b"x1"),
            Header::new(b"Subject", b";lang=en hello"),
        ],
        Body::Raw(Vec::new()),
    );

    assert_eq!(
        values(&message, b"<urn:ietf:params:imdn>.Message-ID"),
        [b"x1"]
    );
    assert_eq!(message.get_values(b"Subject")[0].lang(), Some(&b"en"[..]));
}

fn written(message: &CPIMMessage) -> Vec<u8> {
    let mut readers = Vec::new();
    message.get_readers(&mut readers).unwrap();
    let mut data = Vec::new();
    DynamicChain::new(readers).read_to_end(&mut data).unwrap();
    data
}

#[test]
fn a_message_built_with_new_is_written_with_its_namespaces() {
    let message = CPIMMessage::new(
        &[
            (b"imdn", b"urn:ietf:params:imdn"),
            (b"cpm", b"http://www.openmobilealliance.org/cpm/"),
            (b"unused", b"urn:example:unused"),
        ],
        vec![
            Header::new(b"From", b"<sip:anonymous@anonymous.invalid>"),
            Header::new(b"To", b"<sip:anonymous@anonymous.invalid>"),
            Header::new(b"DateTime", b"2023-04-04T12:16:49.000+08:00"),
            Header::new(b"imdn.Message-ID", b"Kn31"),
            Header::new(
                b"imdn.Disposition-Notification",
                b"positive-delivery, display",
            ),
            Header::new(b"cpm.Payload-Type", b"text"),
            Header::new(b"Subject", b";lang=en two\nlines"),
        ],
        Body::Message(MessageBody {
            headers: vec![Header::new(b"Content-Type", b"text/plain")],
            body: Arc::new(Body::Raw(b"hi".to_vec())),
        }),
    );

    let data = written(&message);
    assert_eq!(
        String::from_utf8_lossy(&data),
        "From: <sip:anonymous@anonymous.invalid>\r\n\
To: <sip:anonymous@anonymous.invalid>\r\n\
DateTime: 2023-04-04T12:16:49.000+08:00\r\n\
NS: imdn <urn:ietf:params:imdn>\r\n\
imdn.Message-ID: Kn31\r\n\
imdn.Disposition-Notification: positive-delivery, display\r\n\
NS: cpm <http://www.openmobilealliance.org/cpm/>\r\n\
cpm.Payload-Type: text\r\n\
Subject:;lang=en two\\nlines\r\n\
\r\n\
Content-Type: text/plain\r\n\
\r\n\
hi"
    );

    let message = parse(&data);
    let info = message.get_info().unwrap();
    assert_eq!(info.imdn_message_id, b"Kn31");
    assert_eq!(info.payload_type, Some(&b"text"[..]));
    let subject = &message.get_values(b"Subject")[0];
    assert_eq!(subject.lang(), Some(&b"en"[..]));
    assert_eq!(unescape(subject.value), &b"two\nlines"[..]);
}

#[test]
fn a_message_read_is_written_as_it_came() {
    let imdn = cpim(
        vec![
            Header::new(b"Content-Type", b"message/imdn+xml"),
            Header::new(b"Content-Disposition", b"notification"),
            Header::new(b"Content-Length", IMDN.len().to_string()),
        ],
        IMDN,
    );

    for data in [RFC_3862_EXAMPLE, &imdn] {
        assert_eq!(
            String::from_utf8_lossy(&written(&parse(data))),
            String::from_utf8_lossy(data)
        );
    }
}

#[test]
fn a_prefix_is_declared_again_only_when_bound_elsewhere() {
    for (declaration, written_out) in [
        (
            "x <urn:example:x>",
            "NS: x <urn:example:x>\r\nx.One: 1\r\n\r\nhi",
        ),
        (
            "x <urn:example:other>",
            "NS: x <urn:example:other>\r\nNS: x <urn:example:x>\r\nx.One: 1\r\n\r\nhi",
        ),
    ] {
        let message = CPIMMessage::new(
            &[(b"x", b"urn:example:x")],
            vec![
                Header::new(b"NS", declaration.to_string()),
                Header::new(b"x.One", b"1"),
            ],
            Body::Raw(b"hi".to_vec()),
        );
        assert_eq!(String::from_utf8_lossy(&written(&message)), written_out);
    }
}

#[test]
fn text_is_escaped() {
    assert_eq!(
        escape(b"a\\b\t\"q\"\n\x01\x7f"),
        &b"a\\\\b\\t\"q\"\\n\\u0001\\u007f"[..]
    );
    assert!(matches!(escape(b"plain"), Cow::Borrowed(b"plain")));

    let text = "caf\u{e9} \\ \u{1}\r\n";
    assert_eq!(unescape(&escape(text.as_bytes())), text.as_bytes());
}

#[test]
fn the_deflator_gives_prefixed_names_and_their_declarations() {
    let mut ns = CPIMNamespace::new();
    ns.register(b"imdn", b"urn:ietf:params:imdn");
    // a default namespace, which has no prefix to write names with
    ns.register(b"", b"urn:example:x");
    let deflator = ns.as_deflator();

    let header = Header::new(b"<urn:ietf:params:imdn>.Message-ID", b"x1");
    let (declaration, deflated) = deflator(&header);
    let declaration = declaration.unwrap();
    assert_eq!(declaration.get_name(), b"NS");
    assert_eq!(declaration.get_value(), b"imdn <urn:ietf:params:imdn>");
    assert_eq!(deflated.get_name(), b"imdn.Message-ID");
    assert_eq!(deflated.get_value(), b"x1");

    for name in [&b"From"[..], b"<urn:example:x>.Name", b"imdn.Message-ID"] {
        let header = Header::new(name.to_vec(), b"v".to_vec());
        let (declaration, deflated) = deflator(&header);
        assert!(declaration.is_none());
        assert_eq!(deflated.get_name(), name);
    }
}

#[test]
fn an_rcs_chat_message_is_read() {
    for (content_headers, content, base64) in [
        (
            "Content-Type: text/plain;charset=UTF-8\r\nContent-Length: 11\r\n",
            &b"Hello, Bob!"[..],
            false,
        ),
        (
            "Content-Type: text/plain;charset=UTF-8\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Length: 16\r\n",
            b"SGVsbG8sIEJvYiE=",
            true,
        ),
    ] {
        let data = [
            &b"From: <sip:anonymous@anonymous.invalid>\r\n\
To: <sip:anonymous@anonymous.invalid>\r\n\
NS: imdn <urn:ietf:params:imdn>\r\n\
imdn.Message-ID: Kn31\r\n\
DateTime: 2023-04-04T12:16:49.000+08:00\r\n\
imdn.Disposition-Notification: positive-delivery, display\r\n\
NS: cpm <http://www.openmobilealliance.org/cpm/>\r\n\
cpm.Payload-Type: text\r\n\
\r\n"[..],
            content_headers.as_bytes(),
            b"\r\n",
            content,
        ]
        .concat();
        let message = parse(&data);

        let info = message.get_info().unwrap();
        assert_eq!(info.imdn_message_id, b"Kn31");
        assert_eq!(info.from, b"<sip:anonymous@anonymous.invalid>");
        assert_eq!(info.to, b"<sip:anonymous@anonymous.invalid>");
        assert_eq!(info.date, b"2023-04-04T12:16:49.000+08:00");
        assert_eq!(
            info.from_uri
                .unwrap()
                .string_representation_without_query_and_fragment(),
            b"sip:anonymous@anonymous.invalid"
        );
        assert_eq!(info.payload_type, Some(&b"text"[..]));
        assert_eq!(
            info.disposition_notification,
            Some(&b"positive-delivery, display"[..])
        );

        assert_eq!(
            message.get_message_body(),
            Some((Some(&b"text/plain;charset=UTF-8"[..]), content, base64))
        );
        assert!(!message.contains_imdn());

        let imdn_info = message.get_imdn_info().unwrap();
        assert_eq!(imdn_info.imdn_id, b"Kn31");
        assert_eq!(
            imdn_info.disposition_notification,
            Some(&b"positive-delivery, display"[..])
        );
    }
}

#[test]
fn a_display_notification_is_read() {
    // RFC 5438 section 7.2.1.2, with the blank line between the CPIM headers
    // and the MIME object that RFC 3862 has
    let xml = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n\
<imdn xmlns=\"urn:ietf:params:xml:ns:imdn\">\r\n\
<message-id>34jk324j</message-id>\r\n\
<datetime>2008-04-04T12:16:49-05:00</datetime>\r\n\
<display-notification>\r\n\
<status>\r\n\
<displayed/>\r\n\
</status>\r\n\
</display-notification>\r\n\
</imdn>";
    let data = [
        format!(
            "From: Bob <im:bob@example.com>\r\n\
To: Alice <im:alice@example.com>\r\n\
NS: imdn <urn:ietf:params:imdn>\r\n\
imdn.Message-ID: dfjkleriou432333\r\n\
DateTime: 2008-04-04T12:16:49-05:00\r\n\
\r\n\
Content-type: message/imdn+xml\r\n\
Content-Disposition: notification\r\n\
Content-length: {}\r\n\
\r\n",
            xml.len()
        )
        .as_bytes(),
        xml,
    ]
    .concat();
    let message = parse(&data);

    assert!(message.contains_imdn());
    assert_eq!(
        message.get_imdn_info().unwrap().imdn_id,
        b"dfjkleriou432333"
    );
    assert_eq!(
        message.get_message_body(),
        Some((Some(&b"message/imdn+xml"[..]), &xml[..], false))
    );
    let info = message.get_info().unwrap();
    assert_eq!(info.from, b"Bob <im:bob@example.com>");
    assert_eq!(info.to, b"Alice <im:alice@example.com>");
}

#[test]
fn the_rfc_3862_example_is_read() {
    let message = parse(RFC_3862_EXAMPLE);

    assert_eq!(
        values(&message, b"From"),
        [b"MR SANDERS <im:piglet@100akerwood.com>"]
    );
    assert_eq!(
        values(&message, b"To"),
        [b"Depressed Donkey <im:eeyore@100akerwood.com>"]
    );
    assert_eq!(
        values(&message, b"DateTime"),
        [b"2000-12-13T13:40:00-08:00"]
    );
    assert_eq!(
        values(
            &message,
            b"<mid:MessageFeatures@id.foo.com>.WackyMessageOption"
        ),
        [b"Use-silly-font"]
    );
    assert_eq!(
        message.get_message_body(),
        Some((
            Some(&b"text/xml; charset=utf-8"[..]),
            &b"<body>\r\nHere is the text of my message.\r\n</body>\r\n"[..],
            false
        ))
    );
    match &message.body {
        Body::Message(content) => assert_eq!(
            crate::internet::header::search(&content.headers, b"Content-ID", true)
                .unwrap()
                .get_value(),
            b"<1234567890@foo.com>"
        ),
        _ => panic!("no MIME object"),
    }

    // it is no RCS message, which get_info() reads
    assert!(message.get_info().is_err());
    assert!(!message.contains_imdn());
}

#[test]
fn an_imdn_among_multipart_parts_is_recognised() {
    let part = |content_type: &'static [u8], content: &[u8]| {
        Arc::new(Body::Message(MessageBody {
            headers: vec![
                Header::new(b"Content-Type", content_type),
                Header::new(b"Content-Disposition", b"notification"),
            ],
            body: Arc::new(Body::Raw(content.to_vec())),
        }))
    };

    for (parts, imdn) in [
        (vec![part(b"text/plain", b"hi")], false),
        (
            vec![part(b"text/plain", b"hi"), part(b"message/imdn+xml", IMDN)],
            true,
        ),
    ] {
        let message = CPIMMessage::new(
            &[],
            Vec::new(),
            Body::Multipart(MultipartBody {
                boundary: b"next".to_vec(),
                parts,
            }),
        );
        assert_eq!(message.contains_imdn(), imdn);
    }
}

#[test]
fn a_default_namespace_holds_the_names_after_it() {
    // as in RFC 3862 section 3.4, then back to the core headers
    let data = b"From: <sip:alice@example.com>\r\n\
NS: <http://id.acme.widgets/wily-headers/>\r\n\
runner-trap: set\r\n\
NS: <urn:example:other>\r\n\
runner-trap: unset\r\n\
NS: <urn:ietf:params:cpim-headers:>\r\n\
To: <sip:bob@example.com>\r\n\
NS: imdn <urn:ietf:params:imdn>\r\n\
imdn.Message-ID: x1\r\n\
DateTime: 2023-04-04T12:16:49Z\r\n\
\r\n\
Content-Type: text/plain\r\n\
\r\n\
hi";
    let message = parse(data);

    assert_eq!(
        values(
            &message,
            b"<http://id.acme.widgets/wily-headers/>.runner-trap"
        ),
        [b"set"]
    );
    assert_eq!(
        values(&message, b"<urn:example:other>.runner-trap"),
        [b"unset"]
    );
    assert!(message.get_values(b"runner-trap").is_empty());
    let info = message.get_info().unwrap();
    assert_eq!(info.from, b"<sip:alice@example.com>");
    assert_eq!(info.to, b"<sip:bob@example.com>");

    assert_eq!(
        String::from_utf8_lossy(&written(&message)),
        String::from_utf8_lossy(data)
    );
}

#[test]
fn a_core_header_after_a_default_namespace_is_in_that_namespace() {
    // NS still declares namespaces, so that the default can be changed back
    let message = parse(
        b"NS: <urn:example:x>\r\n\
From: <sip:alice@example.com>\r\n\
NS: imdn <urn:ietf:params:imdn>\r\n\
imdn.Message-ID: x1\r\n\
\r\n\
Content-Type: text/plain\r\n\
\r\n\
hi",
    );

    assert!(message.get_values(b"From").is_empty());
    assert_eq!(
        values(&message, b"<urn:example:x>.From"),
        [b"<sip:alice@example.com>"]
    );
    assert_eq!(
        values(&message, b"<urn:ietf:params:imdn>.Message-ID"),
        [b"x1"]
    );
}

#[test]
fn the_core_namespace_may_have_a_prefix() {
    let message = parse(
        b"NS: cpim <urn:ietf:params:cpim-headers:>\r\n\
cpim.From: <sip:alice@example.com>\r\n\
cpim.To: <sip:bob@example.com>\r\n\
cpim.DateTime: 2023-04-04T12:16:49Z\r\n\
cpim.NS: imdn <urn:ietf:params:imdn>\r\n\
imdn.Message-ID: x1\r\n\
\r\n\
Content-Type: text/plain\r\n\
\r\n\
hi",
    );

    let info = message.get_info().unwrap();
    assert_eq!(info.from, b"<sip:alice@example.com>");
    assert_eq!(info.imdn_message_id, b"x1");

    // written with the core headers in the default namespace they start in
    assert_eq!(
        String::from_utf8_lossy(&written(&message)),
        "From: <sip:alice@example.com>\r\n\
To: <sip:bob@example.com>\r\n\
DateTime: 2023-04-04T12:16:49Z\r\n\
NS: imdn <urn:ietf:params:imdn>\r\n\
imdn.Message-ID: x1\r\n\
\r\n\
Content-Type: text/plain\r\n\
\r\n\
hi"
    );
}
