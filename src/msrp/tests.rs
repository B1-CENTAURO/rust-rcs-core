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

use crate::internet::header::Header;
use crate::io::DynamicChain;

use super::msrp_chunk::{ContinuationFlag, MsrpChunk, MsrpRequestLine, MsrpResponseLine};
use super::msrp_parser::MsrpParser;

// modelled on the Alice and Bob exchange in RFC 4975 section 4
const SEND: &[u8] = b"MSRP a786hjs2 SEND\r\n\
To-Path: msrp://biloxi.example.com:12763/kjhd37s2s20w2a;tcp\r\n\
From-Path: msrp://atlanta.example.com:7654/jshA7weztas;tcp\r\n\
Message-ID: 87652491\r\n\
Byte-Range: 1-23/23\r\n\
Content-Type: text/plain\r\n\
\r\n\
Hey Bob, are you there?\r\n\
-------a786hjs2$\r\n";

const RESPONSE: &[u8] = b"MSRP a786hjs2 200 OK\r\n\
To-Path: msrp://atlanta.example.com:7654/jshA7weztas;tcp\r\n\
From-Path: msrp://biloxi.example.com:12763/kjhd37s2s20w2a;tcp\r\n\
-------a786hjs2$\r\n";

const REPORT: &[u8] = b"MSRP dkei38sd REPORT\r\n\
To-Path: msrp://atlanta.example.com:7654/jshA7weztas;tcp\r\n\
From-Path: msrp://biloxi.example.com:12763/kjhd37s2s20w2a;tcp\r\n\
Message-ID: 87652491\r\n\
Byte-Range: 1-23/23\r\n\
Status: 000 200 OK\r\n\
-------dkei38sd$\r\n";

// RFC 4975 section 5.4: the active endpoint may open with a bodiless SEND
const EMPTY_SEND: &[u8] = b"MSRP 9di4ea SEND\r\n\
To-Path: msrp://biloxi.example.com:12763/kjhd37s2s20w2a;tcp\r\n\
From-Path: msrp://atlanta.example.com:7654/jshA7weztas;tcp\r\n\
Message-ID: 4564dpWd\r\n\
-------9di4ea$\r\n";

const CHUNKS: &[u8] = b"MSRP d93kswow SEND\r\n\
To-Path: msrp://biloxi.example.com:12763/kjhd37s2s20w2a;tcp\r\n\
From-Path: msrp://atlanta.example.com:7654/jshA7weztas;tcp\r\n\
Message-ID: 12339sdqwer\r\n\
Byte-Range: 1-5/11\r\n\
Content-Type: text/plain\r\n\
\r\n\
Hello\r\n\
-------d93kswow+\r\n\
MSRP op2nc9a SEND\r\n\
To-Path: msrp://biloxi.example.com:12763/kjhd37s2s20w2a;tcp\r\n\
From-Path: msrp://atlanta.example.com:7654/jshA7weztas;tcp\r\n\
Message-ID: 12339sdqwer\r\n\
Byte-Range: 6-11/11\r\n\
Content-Type: text/plain\r\n\
\r\n\
\x20world\r\n\
-------op2nc9a$\r\n\
MSRP qe7dl3h SEND\r\n\
To-Path: msrp://biloxi.example.com:12763/kjhd37s2s20w2a;tcp\r\n\
From-Path: msrp://atlanta.example.com:7654/jshA7weztas;tcp\r\n\
Message-ID: 98asdf3e\r\n\
Byte-Range: 1-*/100\r\n\
Content-Type: text/plain\r\n\
\r\n\
interrupted\r\n\
-------qe7dl3h#\r\n";

#[derive(Debug, PartialEq)]
enum Parsed {
    Request(String, String, Vec<(String, String)>, Option<Vec<u8>>, char),
    Response(String, u16, Option<String>, Vec<(String, String)>),
}

fn text(b: &[u8]) -> String {
    String::from_utf8(b.to_vec()).unwrap()
}

fn headers(headers: &[Header]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|h| (text(h.get_name()), text(h.get_value())))
        .collect()
}

fn parsed(chunk: &MsrpChunk) -> Parsed {
    match chunk {
        MsrpChunk::Request(req_line, h, body, flag) => Parsed::Request(
            text(&req_line.transaction_id),
            text(&req_line.request_method),
            headers(h),
            body.clone(),
            match flag {
                ContinuationFlag::Complete => '$',
                ContinuationFlag::Continuation => '+',
                ContinuationFlag::Abort => '#',
            },
        ),
        MsrpChunk::Response(resp_line, h) => Parsed::Response(
            text(&resp_line.transaction_id),
            resp_line.status_code,
            resp_line.comment.as_deref().map(text),
            headers(h),
        ),
    }
}

/// Feeds `data` in pieces of `step` bytes, producing after each one.
fn parse(data: &[u8], step: usize) -> Vec<Parsed> {
    let mut parser = MsrpParser::new();
    let mut messages = Vec::new();
    for piece in data.chunks(step) {
        parser.feed(piece);
        while let Some(chunk) = parser.produce().unwrap() {
            messages.push(parsed(&chunk));
        }
    }
    messages
}

fn parse_error(data: &[u8]) -> &'static str {
    let mut parser = MsrpParser::new();
    parser.feed(data);
    match parser.produce() {
        Err(e) => e,
        Ok(Some(chunk)) => panic!("parsed {:?}", parsed(&chunk)),
        Ok(None) => panic!("waiting for more data"),
    }
}

fn serialize(chunk: &MsrpChunk) -> Vec<u8> {
    let mut readers = Vec::new();
    chunk.get_readers(&mut readers);
    let mut data = Vec::new();
    DynamicChain::new(readers).read_to_end(&mut data).unwrap();
    data
}

fn pairs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect()
}

fn request(
    transaction_id: &str,
    method: &str,
    h: &[(&str, &str)],
    body: Option<&[u8]>,
    flag: ContinuationFlag,
) -> MsrpChunk {
    MsrpChunk::new_request_chunk(
        MsrpRequestLine {
            transaction_id: transaction_id.as_bytes().to_vec(),
            request_method: method.as_bytes().to_vec(),
        },
        h.iter()
            .map(|(n, v)| Header::new(n.to_string(), v.to_string()))
            .collect(),
        body.map(|b| b.to_vec()),
        flag,
    )
}

const BOB: &str = "msrp://biloxi.example.com:12763/kjhd37s2s20w2a;tcp";
const ALICE: &str = "msrp://atlanta.example.com:7654/jshA7weztas;tcp";

#[test]
fn parses_a_send_and_its_response() {
    let mut data = SEND.to_vec();
    data.extend_from_slice(RESPONSE);

    assert_eq!(
        parse(&data, data.len()),
        vec![
            Parsed::Request(
                "a786hjs2".into(),
                "SEND".into(),
                pairs(&[
                    ("To-Path", BOB),
                    ("From-Path", ALICE),
                    ("Message-ID", "87652491"),
                    ("Byte-Range", "1-23/23"),
                    ("Content-Type", "text/plain"),
                ]),
                Some(b"Hey Bob, are you there?".to_vec()),
                '$',
            ),
            Parsed::Response(
                "a786hjs2".into(),
                200,
                Some("OK".into()),
                pairs(&[("To-Path", ALICE), ("From-Path", BOB)]),
            ),
        ]
    );
}

#[test]
fn parses_bodiless_requests() {
    assert_eq!(
        parse(REPORT, REPORT.len()),
        vec![Parsed::Request(
            "dkei38sd".into(),
            "REPORT".into(),
            pairs(&[
                ("To-Path", ALICE),
                ("From-Path", BOB),
                ("Message-ID", "87652491"),
                ("Byte-Range", "1-23/23"),
                ("Status", "000 200 OK"),
            ]),
            None,
            '$',
        )]
    );

    assert_eq!(
        parse(EMPTY_SEND, EMPTY_SEND.len()),
        vec![Parsed::Request(
            "9di4ea".into(),
            "SEND".into(),
            pairs(&[
                ("To-Path", BOB),
                ("From-Path", ALICE),
                ("Message-ID", "4564dpWd")
            ]),
            None,
            '$',
        )]
    );
}

#[test]
fn parses_chunks_by_their_end_line() {
    let messages = parse(CHUNKS, CHUNKS.len());
    let bodies: Vec<_> = messages
        .iter()
        .map(|m| match m {
            Parsed::Request(_, _, _, Some(body), flag) => (text(body), *flag),
            other => panic!("{:?}", other),
        })
        .collect();

    // the last chunk is interrupted well before the end of its Byte-Range
    assert_eq!(
        bodies,
        vec![
            ("Hello".into(), '+'),
            (" world".into(), '$'),
            ("interrupted".into(), '#'),
        ]
    );
}

#[test]
fn parses_any_split_of_the_stream() {
    let mut data = Vec::new();
    for message in [SEND, RESPONSE, REPORT, EMPTY_SEND, CHUNKS] {
        data.extend_from_slice(message);
    }

    let whole = parse(&data, data.len());
    assert_eq!(whole.len(), 7);
    for step in [1, 2, 3, 7, 64] {
        assert_eq!(parse(&data, step), whole, "step {}", step);
    }
}

#[test]
fn body_may_contain_what_looks_like_an_end_line() {
    let body: &[u8] = b"\r\n-------a786hjs2\r\n-------a786hjs2x$\r\n-------a786hjs2$x\r\n\
-------other$\r\nx-------a786hjs2$";
    let chunk = request(
        "a786hjs2",
        "SEND",
        &[("Content-Type", "text/plain")],
        Some(body),
        ContinuationFlag::Complete,
    );
    let data = serialize(&chunk);

    for step in [1, data.len()] {
        assert_eq!(parse(&data, step), vec![parsed(&chunk)], "step {}", step);
    }
}

#[test]
fn body_is_binary_safe() {
    let body: Vec<u8> = (0..=255).collect();
    let chunk = request(
        "a786hjs2",
        "SEND",
        &[("Content-Type", "application/octet-stream")],
        Some(&body),
        ContinuationFlag::Complete,
    );

    assert_eq!(parse(&serialize(&chunk), 5), vec![parsed(&chunk)]);
}

#[test]
fn rejects_malformed_messages() {
    assert_eq!(
        parse_error(b"HTTP/1.1 200 OK\r\n"),
        "Bad format",
        "not MSRP"
    );
    assert_eq!(
        parse_error(b"MSRP a786hjs2 send\r\n"),
        "Bad format",
        "methods are upper case"
    );
    assert_eq!(
        parse_error(b"MSRP a786 hjs2 SEND\r\n"),
        "Bad format",
        "a space in the method"
    );
    assert_eq!(
        parse_error(b"MSRP a786hjs2 SEND\r\nTo-Path\r\n"),
        "Bad format",
        "a header without a colon"
    );
    assert_eq!(
        parse_error(b"MSRP a786hjs2 SEND\r\nTo-Path: x\r\n-------other$\r\n"),
        "Bad format",
        "an end-line for another transaction"
    );
    assert_eq!(
        parse_error(b"MSRP a786hjs2 200 OK\r\nTo-Path: x\r\n\r\nbody\r\n-------a786hjs2$\r\n"),
        "MSRP Responses are not allowed to have body"
    );
}

#[test]
fn serializes_to_the_wire_format() {
    let send = request(
        "a786hjs2",
        "SEND",
        &[
            ("To-Path", BOB),
            ("From-Path", ALICE),
            ("Message-ID", "87652491"),
            ("Byte-Range", "1-23/23"),
            ("Content-Type", "text/plain"),
        ],
        Some(b"Hey Bob, are you there?"),
        ContinuationFlag::Complete,
    );
    assert_eq!(text(&serialize(&send)), text(SEND));

    let response = MsrpChunk::new_response_chunk(
        MsrpResponseLine {
            transaction_id: b"a786hjs2".to_vec(),
            status_code: 200,
            comment: Some(b"OK".to_vec()),
        },
        vec![Header::new("To-Path", ALICE), Header::new("From-Path", BOB)],
    );
    assert_eq!(text(&serialize(&response)), text(RESPONSE));

    let report = request(
        "dkei38sd",
        "REPORT",
        &[
            ("To-Path", ALICE),
            ("From-Path", BOB),
            ("Message-ID", "87652491"),
            ("Byte-Range", "1-23/23"),
            ("Status", "000 200 OK"),
        ],
        None,
        ContinuationFlag::Complete,
    );
    assert_eq!(text(&serialize(&report)), text(REPORT));

    for chunk in [&send, &response, &report] {
        assert_eq!(parse(&serialize(chunk), 1), vec![parsed(chunk)]);
    }
}

#[test]
fn serializes_continuation_flags_and_empty_bodies() {
    for (flag, c) in [
        (ContinuationFlag::Continuation, '+'),
        (ContinuationFlag::Abort, '#'),
    ] {
        let chunk = request(
            "d93kswow",
            "SEND",
            &[("Content-Type", "text/plain")],
            Some(b""),
            flag,
        );
        let data = serialize(&chunk);
        assert!(text(&data).ends_with(&format!("\r\n\r\n\r\n-------d93kswow{}\r\n", c)));
        assert_eq!(parse(&data, 1), vec![parsed(&chunk)]);
    }
}
