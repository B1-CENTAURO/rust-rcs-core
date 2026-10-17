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
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout, Duration};

use crate::internet::header::Header;
use crate::internet::headers::byte_range;
use crate::io::DynamicChain;

use rust_strict_sdp::AsSDP;

use super::info::msrp_info_reader::AsMsrpInfo;
use super::info::{MsrpDirection, MsrpFileInfo, MsrpInfo, MsrpInterfaceType, MsrpSetupMethod};
use super::msrp_channel::{route, MsrpChannel, MsrpChannelManager};
use super::msrp_chunk::{ContinuationFlag, MsrpChunk, MsrpRequestLine, MsrpResponseLine};
use super::msrp_demuxer::MsrpDemuxer;
use super::msrp_muxer::{MsrpDataWriter, MsrpMessageReceiver, MsrpMuxer};
use super::msrp_parser::MsrpParser;
use super::msrp_transport::msrp_transport_start;

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

#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<String>>>);

impl Log {
    fn push(&self, entry: String) {
        self.0.lock().unwrap().push(entry);
    }

    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

struct Writer(Log, bool);

impl MsrpDataWriter for Writer {
    fn write(&mut self, data: &[u8]) -> Result<usize, (u16, &'static str)> {
        if self.1 {
            return Err((413, "Full"));
        }
        self.0
            .push(format!("write {}", String::from_utf8_lossy(data)));
        Ok(data.len())
    }

    fn complete(&mut self) -> Result<(), (u16, &'static str)> {
        self.0.push("complete".into());
        Ok(())
    }

    fn abort(&mut self) {
        self.0.push("abort".into());
    }
}

struct Receiver(Log, bool);

impl MsrpMessageReceiver for Receiver {
    fn on_message(
        &mut self,
        message_id: &[u8],
        content_type: &[u8],
    ) -> Result<Box<dyn MsrpDataWriter + Send + Sync>, (u16, &'static str)> {
        self.0.push(format!(
            "message {} {}",
            text(message_id),
            text(content_type)
        ));
        Ok(Box::new(Writer(self.0.clone(), self.1)))
    }
}

fn muxer(log: &Log) -> MsrpMuxer {
    MsrpMuxer::new(Receiver(log.clone(), false))
}

fn send(
    message_id: &str,
    byte_range: Option<&str>,
    body: Option<&str>,
    flag: ContinuationFlag,
) -> MsrpChunk {
    let mut h = vec![
        ("To-Path", BOB),
        ("From-Path", ALICE),
        ("Message-ID", message_id),
    ];
    if let Some(byte_range) = byte_range {
        h.push(("Byte-Range", byte_range));
    }
    if body.is_some() {
        h.push(("Content-Type", "text/plain"));
    }
    request("t1", "SEND", &h, body.map(str::as_bytes), flag)
}

#[test]
fn byte_range_total_may_be_unknown() {
    let parse = |s: &[u8]| byte_range::parse(s).map(|r| (r.from, r.to, r.total));

    assert_eq!(parse(b"1-11/11"), Some((1, Some(11), Some(11))));
    assert_eq!(parse(b"1-*/11"), Some((1, None, Some(11))));
    assert_eq!(parse(b"6-11/*"), Some((6, Some(11), None)));
    assert_eq!(parse(b"1-*/*"), Some((1, None, None)));
    assert_eq!(parse(b"1-0/0"), Some((1, Some(0), Some(0))));
    assert_eq!(parse(b"6-5/11"), None);
    assert_eq!(parse(b"1-12/11"), None);
    assert_eq!(parse(b"1-x/11"), None);
}

#[test]
fn muxer_completes_a_message_sent_in_one_chunk() {
    let log = Log::default();
    let mut muxer = muxer(&log);

    assert_eq!(
        muxer.feed(send(
            "m1",
            Some("1-11/11"),
            Some("Hello world"),
            ContinuationFlag::Complete
        )),
        Ok(Some(11))
    );
    assert_eq!(
        log.take(),
        vec!["message m1 text/plain", "write Hello world", "complete"]
    );
}

#[test]
fn muxer_reassembles_chunks() {
    use ContinuationFlag::{Complete, Continuation};

    let cases: Vec<(&str, Vec<(Option<&str>, &str, ContinuationFlag)>)> = vec![
        (
            "in order",
            vec![
                (Some("1-5/11"), "Hello", Continuation),
                (Some("6-11/11"), " world", Complete),
            ],
        ),
        (
            "out of order",
            vec![
                (Some("6-11/11"), " world", Complete),
                (Some("1-5/11"), "Hello", Continuation),
            ],
        ),
        (
            "total unknown",
            vec![
                (Some("1-5/*"), "Hello", Continuation),
                (Some("6-*/*"), " world", Complete),
            ],
        ),
        (
            "sent again, overlapping",
            vec![
                (Some("1-5/11"), "Hello", Continuation),
                (Some("1-5/11"), "Hello", Continuation),
                (Some("4-11/11"), "lo world", Complete),
            ],
        ),
        ("no Byte-Range", vec![(None, "Hello world", Complete)]),
    ];

    for (case, chunks) in cases {
        let log = Log::default();
        let mut muxer = muxer(&log);
        let n = chunks.len();

        for (i, (byte_range, body, flag)) in chunks.into_iter().enumerate() {
            let expected = if i + 1 == n { Some(11) } else { None };
            assert_eq!(
                muxer.feed(send("m1", byte_range, Some(body), flag)),
                Ok(expected),
                "{} chunk {}",
                case,
                i
            );
        }

        let log = log.take();
        let written: String = log
            .iter()
            .filter_map(|entry| entry.strip_prefix("write "))
            .collect();
        assert_eq!(written, "Hello world", "{}", case);
        assert_eq!(log.first().unwrap(), "message m1 text/plain", "{}", case);
        assert_eq!(log.last().unwrap(), "complete", "{}", case);
        assert_eq!(
            log.iter().filter(|e| *e == "complete").count(),
            1,
            "{}",
            case
        );
    }
}

#[test]
fn muxer_accepts_a_send_without_body() {
    let log = Log::default();
    let mut muxer = muxer(&log);

    assert_eq!(
        muxer.feed(send("m1", None, None, ContinuationFlag::Complete)),
        Ok(None)
    );
    assert_eq!(
        muxer.feed(request(
            "t1",
            "SEND",
            &[("To-Path", BOB), ("From-Path", ALICE)],
            None,
            ContinuationFlag::Complete
        )),
        Ok(None),
        "without Message-ID"
    );
    assert!(log.take().is_empty());
}

#[test]
fn muxer_aborts_a_message_ending_in_hash() {
    let log = Log::default();
    let mut muxer = muxer(&log);

    assert_eq!(
        muxer.feed(send(
            "m1",
            Some("1-5/11"),
            Some("Hello"),
            ContinuationFlag::Continuation
        )),
        Ok(None)
    );
    assert_eq!(
        muxer.feed(send(
            "m1",
            Some("6-8/11"),
            Some(" wo"),
            ContinuationFlag::Abort
        )),
        Ok(None)
    );
    assert_eq!(
        log.take(),
        vec!["message m1 text/plain", "write Hello", "abort"]
    );
}

#[test]
fn muxer_rejects_what_it_cannot_take() {
    let log = Log::default();
    let mut muxer = muxer(&log);

    assert_eq!(
        muxer.feed(request(
            "t1",
            "SEND",
            &[("To-Path", BOB), ("From-Path", ALICE), ("Message-ID", "m1")],
            Some(b"Hello"),
            ContinuationFlag::Complete
        )),
        Err((400, "Missing Content-Type header"))
    );
    assert_eq!(
        muxer.feed(send(
            "m1",
            Some("6-5/11"),
            Some("Hello"),
            ContinuationFlag::Complete
        )),
        Err((400, "Invalid Byte-Range header"))
    );

    let mut failing = MsrpMuxer::new(Receiver(log.clone(), true));
    assert_eq!(
        failing.feed(send(
            "m2",
            Some("1-5/5"),
            Some("Hello"),
            ContinuationFlag::Complete
        )),
        Err((413, "Full"))
    );
    assert_eq!(log.take(), vec!["message m2 text/plain", "abort"]);
}

type Results = Arc<Mutex<Vec<(u16, String)>>>;

fn start_sending<R>(
    demuxer: &MsrpDemuxer,
    reader: R,
    total: usize,
    rt: &Arc<Runtime>,
) -> (mpsc::Receiver<MsrpChunk>, Results)
where
    R: Read + Send + Sync + 'static,
{
    let (tx, rx) = mpsc::channel(8);
    let results: Results = Arc::default();
    let results_ = Arc::clone(&results);
    demuxer.start(
        ALICE.as_bytes().to_vec(),
        BOB.as_bytes().to_vec(),
        Some(b"text/plain".to_vec()),
        total,
        reader,
        move |status_code, reason_phrase| {
            results_.lock().unwrap().push((status_code, reason_phrase));
        },
        tx,
        rt,
    );
    (rx, results)
}

fn sent_chunks(rt: &Runtime, rx: &mut mpsc::Receiver<MsrpChunk>, n: usize) -> Vec<MsrpChunk> {
    rt.block_on(async {
        let mut chunks = Vec::new();
        for _ in 0..n {
            let chunk = timeout(Duration::from_secs(10), rx.recv()).await;
            chunks.push(chunk.expect("no chunk sent").expect("channel closed"));
        }
        chunks
    })
}

fn response_to(chunk: &MsrpChunk, status_code: u16, comment: &str) -> MsrpChunk {
    let transaction_id = match chunk {
        MsrpChunk::Request(req_line, _, _, _) => req_line.transaction_id.clone(),
        MsrpChunk::Response(_, _) => panic!("not a request"),
    };
    MsrpChunk::new_response_chunk(
        MsrpResponseLine {
            transaction_id,
            status_code,
            comment: Some(comment.as_bytes().to_vec()),
        },
        vec![Header::new("To-Path", ALICE), Header::new("From-Path", BOB)],
    )
}

fn demuxer() -> MsrpDemuxer {
    MsrpDemuxer::new(ALICE.as_bytes().to_vec(), BOB.as_bytes().to_vec())
}

#[test]
fn demuxer_reports_success_once_every_chunk_is_accepted() {
    let rt = Arc::new(Runtime::new().unwrap());
    let demuxer = demuxer();
    let body = vec![b'x'; 25 * 1024];
    let (mut rx, results) = start_sending(&demuxer, std::io::Cursor::new(body), 25 * 1024, &rt);

    let chunks = sent_chunks(&rt, &mut rx, 3);
    let summary: Vec<_> = chunks
        .iter()
        .map(|chunk| match parsed(chunk) {
            Parsed::Request(_, method, h, body, flag) => (
                method,
                h[0].clone(),
                h[1].0.clone(),
                h.iter().find(|(n, _)| n == "Byte-Range").unwrap().1.clone(),
                body.unwrap().len(),
                flag,
            ),
            other => panic!("{:?}", other),
        })
        .collect();
    let to_path = ("To-Path".to_string(), BOB.to_string());
    assert_eq!(
        summary,
        vec![
            (
                "SEND".into(),
                to_path.clone(),
                "From-Path".into(),
                "1-10240/25600".into(),
                10240,
                '+'
            ),
            (
                "SEND".into(),
                to_path.clone(),
                "From-Path".into(),
                "10241-20480/25600".into(),
                10240,
                '+'
            ),
            (
                "SEND".into(),
                to_path,
                "From-Path".into(),
                "20481-25600/25600".into(),
                5120,
                '$'
            ),
        ]
    );

    for i in [2, 0] {
        assert!(demuxer
            .on_response(response_to(&chunks[i], 200, "OK"))
            .is_ok());
        assert!(results.lock().unwrap().is_empty(), "after chunk {}", i);
    }
    assert!(demuxer
        .on_response(response_to(&chunks[1], 200, "OK"))
        .is_ok());
    assert_eq!(*results.lock().unwrap(), vec![(200, "Ok".to_string())]);

    assert!(demuxer
        .on_response(response_to(&chunks[1], 200, "OK"))
        .is_err());
    assert_eq!(results.lock().unwrap().len(), 1);
}

#[test]
fn demuxer_reports_the_first_failure() {
    let rt = Arc::new(Runtime::new().unwrap());
    let demuxer = demuxer();
    let body = vec![b'x'; 25 * 1024];
    let (mut rx, results) = start_sending(&demuxer, std::io::Cursor::new(body), 25 * 1024, &rt);
    let chunks = sent_chunks(&rt, &mut rx, 3);

    assert!(demuxer
        .on_response(response_to(&chunks[0], 200, "OK"))
        .is_ok());
    assert!(demuxer
        .on_response(response_to(&chunks[1], 413, "Too big"))
        .is_ok());
    let _ = demuxer.on_response(response_to(&chunks[2], 200, "OK"));

    assert_eq!(*results.lock().unwrap(), vec![(413, "Too big".to_string())]);
}

#[test]
fn demuxer_sends_an_empty_message_as_a_send_without_body() {
    let rt = Arc::new(Runtime::new().unwrap());
    let demuxer = demuxer();
    let (mut rx, results) = start_sending(&demuxer, std::io::empty(), 0, &rt);
    let chunks = sent_chunks(&rt, &mut rx, 1);

    match parsed(&chunks[0]) {
        Parsed::Request(_, method, h, body, flag) => {
            assert_eq!((method.as_str(), body, flag), ("SEND", None, '$'));
            let names: Vec<_> = h.iter().map(|(n, _)| n.as_str()).collect();
            assert_eq!(
                names,
                vec!["To-Path", "From-Path", "Message-ID", "Failure-Report"]
            );
        }
        other => panic!("{:?}", other),
    }

    assert!(demuxer
        .on_response(response_to(&chunks[0], 200, "OK"))
        .is_ok());
    assert_eq!(*results.lock().unwrap(), vec![(200, "Ok".to_string())]);
}

struct FailingReader(Option<Vec<u8>>);

impl Read for FailingReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.0.take() {
            Some(data) => {
                buf[..data.len()].copy_from_slice(&data);
                Ok(data.len())
            }
            None => Err(std::io::Error::from(std::io::ErrorKind::Other)),
        }
    }
}

#[test]
fn demuxer_aborts_the_message_when_reading_fails() {
    let rt = Arc::new(Runtime::new().unwrap());
    let demuxer = demuxer();
    let reader = FailingReader(Some(b"Hello".to_vec()));
    let (mut rx, results) = start_sending(&demuxer, reader, 11, &rt);
    let chunks = sent_chunks(&rt, &mut rx, 1);

    match parsed(&chunks[0]) {
        Parsed::Request(_, _, h, body, flag) => {
            assert_eq!((body, flag), (Some(b"Hello".to_vec()), '#'));
            assert!(h.contains(&("Byte-Range".to_string(), "1-5/11".to_string())));
        }
        other => panic!("{:?}", other),
    }
    assert_eq!(
        *results.lock().unwrap(),
        vec![(500, "Internal Error".to_string())]
    );
}

fn flag_of(chunk: &MsrpChunk) -> char {
    match parsed(chunk) {
        Parsed::Request(_, _, _, _, flag) => flag,
        other => panic!("{:?}", other),
    }
}

#[test]
fn demuxer_aborts_a_message_that_fails_while_being_sent() {
    // RFC 4975 section 7.3.2: the rest of the message is not sent, and the
    // chunk that would have been next ends in #
    let rt = Arc::new(Runtime::new().unwrap());
    let demuxer = demuxer();
    let (tx, mut rx) = mpsc::channel(1); // the sender waits on the receiver
    let results: Results = Arc::default();
    let results_ = Arc::clone(&results);
    demuxer.start(
        ALICE.as_bytes().to_vec(),
        BOB.as_bytes().to_vec(),
        Some(b"text/plain".to_vec()),
        50 * 1024,
        std::io::Cursor::new(vec![b'x'; 50 * 1024]),
        move |status_code, reason_phrase| {
            results_.lock().unwrap().push((status_code, reason_phrase));
        },
        tx,
        &rt,
    );

    let first = sent_chunks(&rt, &mut rx, 1).remove(0);
    assert_eq!(flag_of(&first), '+');
    assert!(demuxer
        .on_response(response_to(&first, 413, "Too big"))
        .is_ok());
    assert_eq!(*results.lock().unwrap(), vec![(413, "Too big".to_string())]);

    // the chunks already queued, then the one that ends the message
    let rest = rt.block_on(async {
        let mut chunks = Vec::new();
        while let Some(chunk) = timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("the sender hangs")
        {
            chunks.push(chunk);
        }
        chunks
    });
    let flags: Vec<char> = rest.iter().map(flag_of).collect();
    assert_eq!(flags.last(), Some(&'#'), "{:?}", flags);
    assert!(
        flags[..flags.len() - 1].iter().all(|flag| *flag == '+'),
        "{:?}",
        flags
    );
    assert!(rest.len() < 4, "the rest is not sent: {:?}", flags);
}

#[test]
fn a_failure_report_fails_the_session() {
    let rt = Arc::new(Runtime::new().unwrap());
    let demuxer = demuxer();
    let hello = || std::io::Cursor::new(b"Hello".to_vec());

    // a failure response ends its message only
    let (mut rx, refused) = start_sending(&demuxer, hello(), 5, &rt);
    let chunks = sent_chunks(&rt, &mut rx, 1);
    assert!(demuxer
        .on_response(response_to(&chunks[0], 415, "Unsupported"))
        .is_ok());
    assert_eq!(
        *refused.lock().unwrap(),
        vec![(415, "Unsupported".to_string())]
    );
    assert_eq!(demuxer.session_failure(), None);

    // a failure REPORT ends every message on the session (section 7.3.2)
    let (mut rx, reported) = start_sending(&demuxer, hello(), 5, &rt);
    let message_id = header_of(&sent_chunks(&rt, &mut rx, 1)[0], "Message-ID").unwrap();
    let (mut rx, pending) = start_sending(&demuxer, hello(), 5, &rt);
    sent_chunks(&rt, &mut rx, 1);

    assert!(demuxer
        .on_report(report_for(&message_id, "1-5/5", "000 413 Too big"))
        .is_ok());
    let failure = (413, "Too big".to_string());
    assert_eq!(*reported.lock().unwrap(), vec![failure.clone()]);
    assert_eq!(*pending.lock().unwrap(), vec![failure.clone()]);
    assert_eq!(demuxer.session_failure(), Some(failure.clone()));

    // and those started after it, which send nothing
    let (mut rx, later) = start_sending(&demuxer, hello(), 5, &rt);
    let sent = rt.block_on(async {
        timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("the sender hangs")
    });
    assert!(sent.is_none());
    assert_eq!(*later.lock().unwrap(), vec![failure]);
}

#[test]
fn demuxer_times_out_without_a_response() {
    let rt = Arc::new(
        Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap(),
    );
    let demuxer = demuxer();
    let (mut rx, results) =
        start_sending(&demuxer, std::io::Cursor::new(b"Hello".to_vec()), 5, &rt);
    let chunks = sent_chunks(&rt, &mut rx, 1);

    rt.block_on(async { sleep(Duration::from_secs(29)).await });
    assert!(results.lock().unwrap().is_empty());

    rt.block_on(async { sleep(Duration::from_secs(2)).await });
    assert_eq!(*results.lock().unwrap(), vec![(408, "Timeout".to_string())]);

    assert!(demuxer
        .on_response(response_to(&chunks[0], 200, "OK"))
        .is_err());
    assert_eq!(results.lock().unwrap().len(), 1);
}

fn channel(log: &Log) -> MsrpChannel {
    MsrpChannel::new(
        BOB.as_bytes().to_vec(),
        ALICE.as_bytes().to_vec(),
        Arc::new(MsrpDemuxer::new(
            BOB.as_bytes().to_vec(),
            ALICE.as_bytes().to_vec(),
        )),
        muxer(log),
    )
}

fn with_headers(chunk: MsrpChunk, extra: &[(&'static str, &'static str)]) -> MsrpChunk {
    let mut chunk = chunk;
    for (name, value) in extra {
        chunk.add_header(Header::new(*name, *value));
    }
    chunk
}

#[test]
fn channel_sends_a_success_report_when_asked() {
    let log = Log::default();
    let mut channel = channel(&log);
    let chunk = with_headers(
        send(
            "m1",
            Some("1-11/11"),
            Some("Hello world"),
            ContinuationFlag::Complete,
        ),
        &[("Success-Report", "yes")],
    );

    let replies = channel.on_message(chunk).unwrap();
    assert_eq!(replies.len(), 2);
    assert!(matches!(
        parsed(&replies[0]),
        Parsed::Response(transaction_id, 200, _, _) if transaction_id == "t1"
    ));
    match parsed(&replies[1]) {
        Parsed::Request(_, method, h, body, flag) => {
            assert_eq!((method.as_str(), body, flag), ("REPORT", None, '$'));
            assert_eq!(
                h,
                pairs(&[
                    ("To-Path", ALICE),
                    ("From-Path", BOB),
                    ("Message-ID", "m1"),
                    ("Byte-Range", "1-11/11"),
                    ("Status", "000 200 OK"),
                ])
            );
        }
        other => panic!("{:?}", other),
    }
    assert_eq!(parse(&serialize(&replies[1]), 1), vec![parsed(&replies[1])]);

    let chunk = with_headers(
        send(
            "m2",
            Some("1-5/5"),
            Some("Hello"),
            ContinuationFlag::Complete,
        ),
        &[("Success-Report", "yes"), ("Failure-Report", "no")],
    );
    let replies = channel.on_message(chunk).unwrap();
    assert_eq!(replies.len(), 1, "a REPORT but no response");
    assert!(
        matches!(parsed(&replies[0]), Parsed::Request(_, method, _, _, _) if method == "REPORT")
    );
}

#[test]
fn channel_accepts_a_send_without_body() {
    let log = Log::default();
    let mut channel = channel(&log);

    let replies = channel
        .on_message(send("m1", None, None, ContinuationFlag::Complete))
        .unwrap();
    assert_eq!(replies.len(), 1);
    assert!(matches!(
        parsed(&replies[0]),
        Parsed::Response(_, 200, _, _)
    ));
    assert!(log.take().is_empty());
}

#[test]
fn a_message_goes_from_demuxer_to_channel_and_back() {
    let rt = Arc::new(Runtime::new().unwrap());
    let alice_demuxer = Arc::new(demuxer());
    let mut alice = MsrpChannel::new(
        ALICE.as_bytes().to_vec(),
        BOB.as_bytes().to_vec(),
        Arc::clone(&alice_demuxer),
        muxer(&Log::default()),
    );
    let bob_log = Log::default();
    let mut bob = channel(&bob_log);

    let body: Vec<u8> = (0..25 * 1024).map(|i| b'a' + (i % 26) as u8).collect();
    let (mut rx, results) = start_sending(
        &alice_demuxer,
        std::io::Cursor::new(body.clone()),
        body.len(),
        &rt,
    );

    // every chunk and every reply goes through the wire format
    let mut to_bob = MsrpParser::new();
    let mut to_alice = MsrpParser::new();
    for chunk in sent_chunks(&rt, &mut rx, 3) {
        to_bob.feed(&serialize(&chunk));
        let chunk = to_bob.produce().unwrap().unwrap();
        for reply in bob.on_message(chunk).unwrap() {
            to_alice.feed(&serialize(&reply));
            let reply = to_alice.produce().unwrap().unwrap();
            assert!(alice.on_message(reply).unwrap().is_empty());
        }
    }

    assert_eq!(*results.lock().unwrap(), vec![(200, "Ok".to_string())]);
    let log = bob_log.take();
    let received: String = log
        .iter()
        .filter_map(|entry| entry.strip_prefix("write "))
        .collect();
    assert_eq!(received.as_bytes(), &body[..]);
    assert_eq!(log.last().unwrap(), "complete");
}

fn send_message(
    demuxer: &MsrpDemuxer,
    from_path: &str,
    to_path: &str,
    body: Vec<u8>,
    tx: mpsc::Sender<MsrpChunk>,
    rt: &Arc<Runtime>,
) -> Results {
    let results: Results = Arc::default();
    let results_ = Arc::clone(&results);
    demuxer.start(
        from_path.as_bytes().to_vec(),
        to_path.as_bytes().to_vec(),
        Some(b"text/plain".to_vec()),
        body.len(),
        std::io::Cursor::new(body),
        move |status_code, reason_phrase| {
            results_.lock().unwrap().push((status_code, reason_phrase));
        },
        tx,
        rt,
    );
    results
}

fn wait_for<T>(what: &str, mut check: impl FnMut() -> Option<T>) -> T {
    for _ in 0..500 {
        if let Some(value) = check() {
            return value;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("timed out waiting for {}", what);
}

fn received(log: &Log) -> Option<Vec<u8>> {
    let log = log.0.lock().unwrap();
    if log.last().map(String::as_str) == Some("complete") {
        Some(
            log.iter()
                .filter_map(|entry| entry.strip_prefix("write "))
                .collect::<String>()
                .into_bytes(),
        )
    } else {
        None
    }
}

fn result(results: &Results) -> Option<Vec<(u16, String)>> {
    let results = results.lock().unwrap();
    if results.is_empty() {
        None
    } else {
        Some(results.clone())
    }
}

/// Starts a transport on `io` that routes to `channels`, and returns a sender
/// of chunks onto it.
fn transport(
    io: DuplexStream,
    channels: &Arc<Mutex<Vec<MsrpChannel>>>,
    rt: &Arc<Runtime>,
) -> mpsc::Sender<MsrpChunk> {
    let (data_tx, data_rx) = mpsc::channel(8);
    let channels = Arc::clone(channels);
    msrp_transport_start(
        io,
        "bob".into(),
        data_tx.clone(),
        data_rx,
        move |message| route(&channels, message),
        || {},
        rt,
    );

    let (tx, mut rx) = mpsc::channel::<MsrpChunk>(8);
    rt.spawn(async move {
        while let Some(chunk) = rx.recv().await {
            let _ = data_tx.send(Some(serialize(&chunk))).await;
        }
    });
    tx
}

#[test]
fn messages_cross_one_connection_both_ways() {
    let rt = Arc::new(Runtime::new().unwrap());
    let (alice_io, bob_io) = tokio::io::duplex(64 * 1024);

    let bob_log = Log::default();
    let bob_demuxer = Arc::new(MsrpDemuxer::new(
        BOB.as_bytes().to_vec(),
        ALICE.as_bytes().to_vec(),
    ));
    let bob_channels = Arc::new(Mutex::new(vec![MsrpChannel::new(
        BOB.as_bytes().to_vec(),
        ALICE.as_bytes().to_vec(),
        Arc::clone(&bob_demuxer),
        muxer(&bob_log),
    )]));
    let bob_tx = transport(bob_io, &bob_channels, &rt);

    // Alice's manager opens the connection with her first chunk
    let opened = Arc::new(Mutex::new(0));
    let opened_ = Arc::clone(&opened);
    let alice_io = Mutex::new(Some(alice_io));
    let (alice_tx, alice_rx) = mpsc::channel(8);
    let manager = MsrpChannelManager::new(
        alice_rx,
        move |_: &[u8], _: &[u8]| {
            *opened_.lock().unwrap() += 1;
            alice_io
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| tokio::io::duplex(1).0)
        },
        Arc::clone(&rt),
    );
    let alice_log = Log::default();
    let alice_demuxer = Arc::new(demuxer());
    manager.register_channel(MsrpChannel::new(
        ALICE.as_bytes().to_vec(),
        BOB.as_bytes().to_vec(),
        Arc::clone(&alice_demuxer),
        muxer(&alice_log),
    ));

    let to_bob: Vec<u8> = (0..25 * 1024).map(|i| b'a' + (i % 26) as u8).collect();
    let alice_results = send_message(&alice_demuxer, ALICE, BOB, to_bob.clone(), alice_tx, &rt);
    assert_eq!(wait_for("Bob to receive", || received(&bob_log)), to_bob);
    assert_eq!(
        wait_for("Alice's result", || result(&alice_results)),
        vec![(200, "Ok".to_string())]
    );
    assert_eq!(*opened.lock().unwrap(), 1, "one connection for all chunks");

    let to_alice: Vec<u8> = (0..12 * 1024).map(|i| b'A' + (i % 26) as u8).collect();
    let bob_results = send_message(&bob_demuxer, BOB, ALICE, to_alice.clone(), bob_tx, &rt);
    assert_eq!(
        wait_for("Alice to receive", || received(&alice_log)),
        to_alice
    );
    assert_eq!(
        wait_for("Bob's result", || result(&bob_results)),
        vec![(200, "Ok".to_string())]
    );
    assert_eq!(*opened.lock().unwrap(), 1);
}

fn read_messages(rt: &Runtime, io: &mut DuplexStream, n: usize) -> Vec<Parsed> {
    rt.block_on(async {
        let mut parser = MsrpParser::new();
        let mut messages = Vec::new();
        let mut buf = [0; 4096];
        while messages.len() < n {
            let size = timeout(Duration::from_secs(5), io.read(&mut buf))
                .await
                .expect("no reply")
                .unwrap();
            assert!(size > 0, "connection closed");
            parser.feed(&buf[..size]);
            while let Some(chunk) = parser.produce().unwrap() {
                messages.push(parsed(&chunk));
            }
        }
        messages
    })
}

#[test]
fn a_connection_outlives_requests_for_no_session() {
    let rt = Arc::new(Runtime::new().unwrap());
    let (mut alice_io, bob_io) = tokio::io::duplex(64 * 1024);
    let bob_channels = Arc::new(Mutex::new(Vec::new()));
    let _bob_tx = transport(bob_io, &bob_channels, &rt);

    // a REPORT, which gets no response, and two SENDs in one write
    let mut data = REPORT.to_vec();
    data.extend_from_slice(SEND);
    data.extend_from_slice(EMPTY_SEND);
    rt.block_on(alice_io.write_all(&data)).unwrap();

    let no_session = |transaction_id: &str| {
        Parsed::Response(
            transaction_id.into(),
            481,
            Some("Session does not exist".into()),
            pairs(&[("To-Path", ALICE), ("From-Path", BOB)]),
        )
    };
    assert_eq!(
        read_messages(&rt, &mut alice_io, 2),
        vec![no_session("a786hjs2"), no_session("9di4ea")]
    );

    let bob_log = Log::default();
    bob_channels.lock().unwrap().push(channel(&bob_log));
    rt.block_on(alice_io.write_all(SEND)).unwrap();
    assert_eq!(
        read_messages(&rt, &mut alice_io, 1),
        vec![Parsed::Response(
            "a786hjs2".into(),
            200,
            Some("OK".into()),
            pairs(&[
                ("To-Path", ALICE),
                ("From-Path", BOB),
                ("Message-ID", "87652491")
            ]),
        )]
    );
    assert_eq!(
        received(&bob_log),
        Some(b"Hey Bob, are you there?".to_vec())
    );
}

#[test]
fn sessions_are_matched_by_uri() {
    let bob_log = Log::default();
    let channels = Mutex::new(vec![channel(&bob_log)]);
    let status = |to_path: &str| {
        let chunk = request(
            "t1",
            "SEND",
            &[
                ("To-Path", to_path),
                ("From-Path", ALICE),
                ("Message-ID", "m1"),
            ],
            None,
            ContinuationFlag::Complete,
        );
        match route(&channels, chunk).unwrap().first().map(parsed) {
            Some(Parsed::Response(_, status_code, _, _)) => status_code,
            other => panic!("{:?}", other),
        }
    };

    assert_eq!(status(BOB), 200);
    assert_eq!(
        status("MSRP://Biloxi.Example.COM:12763/kjhd37s2s20w2a;TCP;x=y"),
        200,
        "case and parameters do not count"
    );
    assert_eq!(
        status("msrp://biloxi.example.com:12763/KJHD37S2S20W2A;tcp"),
        481,
        "the session-id is case sensitive"
    );
    assert_eq!(
        status("msrp://biloxi.example.com:12764/kjhd37s2s20w2a;tcp"),
        481,
        "another port"
    );
}

#[test]
fn a_transport_ends_when_the_peer_closes() {
    let rt = Arc::new(Runtime::new().unwrap());
    let (io, peer) = tokio::io::duplex(1024);
    let (data_tx, data_rx) = mpsc::channel(8);
    let released = Arc::new(Mutex::new(false));
    let released_ = Arc::clone(&released);
    msrp_transport_start(
        io,
        "closing".into(),
        data_tx,
        data_rx,
        |_| Ok(Vec::new()),
        move || *released_.lock().unwrap() = true,
        &rt,
    );

    drop(peer);
    wait_for("the transport to end", || {
        if *released.lock().unwrap() {
            Some(())
        } else {
            None
        }
    });
}

/// What as_msrp_info() finds in `sdp`, one field per line.
fn msrp_sdp(sdp: &str) -> Option<Vec<String>> {
    let sdp = sdp.as_bytes().as_sdp()?;
    let info = sdp.as_msrp_info()?;

    let mut fields = vec![
        format!("protocol {}", text(info.protocol)),
        format!(
            "address {} {}",
            match info.interface_type {
                MsrpInterfaceType::IPv4 => "IP4",
                MsrpInterfaceType::IPv6 => "IP6",
            },
            text(info.address)
        ),
        format!("port {}", info.port),
        format!("path {}", text(info.path)),
        format!(
            "direction {}",
            if info.inactive {
                "inactive"
            } else {
                match info.direction {
                    MsrpDirection::SendOnly => "sendonly",
                    MsrpDirection::ReceiveOnly => "recvonly",
                    MsrpDirection::SendReceive => "sendrecv",
                }
            }
        ),
        format!(
            "setup {}",
            match info.setup_method {
                MsrpSetupMethod::Active => "active",
                MsrpSetupMethod::Passive => "passive",
            }
        ),
        format!("accept-types {}", text(info.accept_types)),
        format!(
            "accept-wrapped-types {:?}",
            info.accept_wrapped_types.map(text)
        ),
    ];

    if let Some(file_info) = &info.file_info {
        fields.push(format!("file-selector {}", text(file_info.file_selector)));
        fields.push(format!(
            "file-transfer-id {}",
            text(file_info.file_transfer_id)
        ));
        fields.push(format!(
            "file-disposition {:?}",
            file_info.file_disposition.map(text)
        ));
        fields.push(format!("file-range {:?}", file_info.file_range.map(text)));
        fields.push(format!("file-icon {:?}", file_info.file_icon.map(text)));
    }

    Some(fields)
}

fn strings(lines: &[&str]) -> Vec<String> {
    lines.iter().map(|line| line.to_string()).collect()
}

#[test]
fn reads_an_msrp_offer() {
    let sdp = "v=0\r\n\
o=- 3866767545 3866767545 IN IP4 192.0.2.2\r\n\
s=-\r\n\
c=IN IP4 192.0.2.2\r\n\
t=0 0\r\n\
m=message 2855 TCP/MSRP *\r\n\
a=accept-types:message/cpim application/im-iscomposing+xml\r\n\
a=accept-wrapped-types:text/plain message/imdn+xml\r\n\
a=path:msrp://192.0.2.2:2855/xyz;tcp\r\n\
a=setup:active\r\n\
a=sendrecv\r\n";

    assert_eq!(
        msrp_sdp(sdp),
        Some(strings(&[
            "protocol TCP/MSRP",
            "address IP4 192.0.2.2",
            "port 2855",
            "path msrp://192.0.2.2:2855/xyz;tcp",
            "direction sendrecv",
            "setup active",
            "accept-types message/cpim application/im-iscomposing+xml",
            "accept-wrapped-types Some(\"text/plain message/imdn+xml\")",
        ]))
    );
}

#[test]
fn reads_defaults_and_overrides() {
    // the session is inactive, the media's c= line wins, and the path goes
    // through a relay
    let sdp = |direction: &str| {
        format!(
            "v=0\r\n\
o=- 1 1 IN IP4 192.0.2.9\r\n\
s=-\r\n\
c=IN IP4 192.0.2.9\r\n\
t=0 0\r\n\
a=inactive\r\n\
m=message 2856 TCP/TLS/MSRP *\r\n\
c=IN IP6 2001:db8::2\r\n\
a=accept-types:message/cpim\r\n\
a=path:msrps://[2001:db8::1]:2856/relay;tcp msrps://[2001:db8::2]:2856/abc;tcp\r\n\
{}",
            direction
        )
    };
    let expected = |direction: &str| {
        Some(strings(&[
            "protocol TCP/TLS/MSRP",
            "address IP6 2001:db8::2",
            "port 2856",
            "path msrps://[2001:db8::1]:2856/relay;tcp msrps://[2001:db8::2]:2856/abc;tcp",
            direction,
            "setup passive",
            "accept-types message/cpim",
            "accept-wrapped-types None",
        ]))
    };

    assert_eq!(msrp_sdp(&sdp("")), expected("direction inactive"));
    assert_eq!(
        msrp_sdp(&sdp("a=recvonly\r\n")),
        expected("direction recvonly"),
        "the media overrides the session"
    );
    assert_eq!(
        msrp_sdp(&sdp("").replace("a=inactive\r\n", "")),
        expected("direction sendrecv"),
        "sendrecv is the default"
    );
}

#[test]
fn reads_file_transfer_attributes() {
    let sdp = "v=0\r\n\
o=- 1 1 IN IP4 192.0.2.2\r\n\
s=-\r\n\
c=IN IP4 192.0.2.2\r\n\
t=0 0\r\n\
m=message 2855 TCP/MSRP *\r\n\
a=sendonly\r\n\
a=accept-types:message/cpim\r\n\
a=path:msrp://192.0.2.2:2855/xyz;tcp\r\n\
a=file-selector:name:\"My cool picture.jpg\" type:image/jpeg size:32349\r\n\
a=file-transfer-id:vBnG916bdberum2fFEABR1FR3ExZMUrd\r\n\
a=file-disposition:attachment\r\n\
a=file-range:1-32349\r\n\
a=file-icon:cid:id2@alicepc.example.com\r\n";

    let fields = msrp_sdp(sdp).unwrap();
    assert_eq!(
        &fields[8..],
        &strings(&[
            "file-selector name:\"My cool picture.jpg\" type:image/jpeg size:32349",
            "file-transfer-id vBnG916bdberum2fFEABR1FR3ExZMUrd",
            "file-disposition Some(\"attachment\")",
            "file-range Some(\"1-32349\")",
            "file-icon Some(\"cid:id2@alicepc.example.com\")",
        ])[..]
    );
    assert_eq!(fields[4], "direction sendonly");
}

fn msrp_info(inactive: bool) -> MsrpInfo<'static> {
    MsrpInfo {
        protocol: b"TCP/MSRP",
        address: b"192.0.2.1",
        interface_type: MsrpInterfaceType::IPv4,
        port: 2855,
        path: b"msrp://192.0.2.1:2855/abc;tcp",
        inactive,
        direction: MsrpDirection::SendReceive,
        setup_method: MsrpSetupMethod::Active,
        accept_types: b"message/cpim application/im-iscomposing+xml",
        accept_wrapped_types: Some(b"text/plain message/imdn+xml"),
        cema: false,
        file_info: Some(MsrpFileInfo {
            file_selector: b"name:\"a.jpg\" type:image/jpeg size:10",
            file_transfer_id: b"vBnG916bdberum2f",
            file_range: None,
            file_icon: None,
            file_disposition: Some(b"render"),
        }),
    }
}

#[test]
fn writes_sdp_that_reads_back() {
    let sdp: String = msrp_info(false).into();

    assert!(sdp.ends_with("\r\n"));
    let lines: Vec<&str> = sdp.trim_end_matches("\r\n").split("\r\n").collect();
    for line in &lines {
        assert!(
            line.len() > 2 && line.as_bytes()[1] == b'=' && !line.contains('\n'),
            "{:?}",
            line
        );
    }

    let origin: Vec<&str> = lines[1].split(' ').collect();
    assert_eq!(origin[0], "o=-");
    assert!(origin[1].parse::<u64>().is_ok() && origin[1] == origin[2]);
    assert_eq!(&origin[3..], &["IN", "IP4", "192.0.2.1"]);

    let directions = ["a=sendrecv", "a=sendonly", "a=recvonly", "a=inactive"];
    assert_eq!(lines.iter().filter(|l| directions.contains(l)).count(), 1);

    assert_eq!(
        msrp_sdp(&sdp),
        Some(strings(&[
            "protocol TCP/MSRP",
            "address IP4 192.0.2.1",
            "port 2855",
            "path msrp://192.0.2.1:2855/abc;tcp",
            "direction sendrecv",
            "setup active",
            "accept-types message/cpim application/im-iscomposing+xml",
            "accept-wrapped-types Some(\"text/plain message/imdn+xml\")",
            "file-selector name:\"a.jpg\" type:image/jpeg size:10",
            "file-transfer-id vBnG916bdberum2f",
            "file-disposition Some(\"render\")",
            "file-range None",
            "file-icon None",
        ]))
    );

    let sdp: String = msrp_info(true).into();
    assert!(sdp.contains("\r\na=inactive\r\n") && !sdp.contains("a=sendrecv"));
    assert_eq!(msrp_sdp(&sdp).unwrap()[4], "direction inactive");
}

fn read_nothing(rt: &Runtime, io: &mut DuplexStream) {
    rt.block_on(async {
        let mut buf = [0; 4096];
        match timeout(Duration::from_millis(300), io.read(&mut buf)).await {
            Err(_) => {}
            Ok(read) => panic!("read {:?}", read.map(|size| text(&buf[..size]))),
        }
    })
}

/// A manager that must not open connections, with a passive channel for Bob.
fn passive_bob(
    rt: &Arc<Runtime>,
    log: &Log,
) -> (
    MsrpChannelManager,
    Arc<MsrpDemuxer>,
    mpsc::Sender<MsrpChunk>,
) {
    let (tx, rx) = mpsc::channel(8);
    let manager = MsrpChannelManager::new(
        rx,
        |_: &[u8], _: &[u8]| -> DuplexStream { panic!("a passive session opened a connection") },
        Arc::clone(rt),
    );
    let demuxer = Arc::new(MsrpDemuxer::new(
        BOB.as_bytes().to_vec(),
        ALICE.as_bytes().to_vec(),
    ));
    manager.register_passive_channel(MsrpChannel::new(
        BOB.as_bytes().to_vec(),
        ALICE.as_bytes().to_vec(),
        Arc::clone(&demuxer),
        muxer(log),
    ));
    (manager, demuxer, tx)
}

#[test]
fn a_passive_session_sends_once_the_remote_end_connects() {
    let rt = Arc::new(Runtime::new().unwrap());
    let (alice_io, bob_io) = tokio::io::duplex(64 * 1024);

    let bob_log = Log::default();
    let (bob, bob_demuxer, bob_tx) = passive_bob(&rt, &bob_log);

    // Bob has something to say before Alice connects
    let first: Vec<u8> = (0..25 * 1024).map(|i| b'a' + (i % 26) as u8).collect();
    let first_results = send_message(&bob_demuxer, BOB, ALICE, first.clone(), bob_tx.clone(), &rt);

    let alice_io = Mutex::new(Some(alice_io));
    let (alice_tx, alice_rx) = mpsc::channel(8);
    let alice = MsrpChannelManager::new(
        alice_rx,
        move |_: &[u8], _: &[u8]| alice_io.lock().unwrap().take().unwrap(),
        Arc::clone(&rt),
    );
    let alice_log = Log::default();
    let alice_demuxer = Arc::new(demuxer());
    alice.register_channel(MsrpChannel::new(
        ALICE.as_bytes().to_vec(),
        BOB.as_bytes().to_vec(),
        Arc::clone(&alice_demuxer),
        muxer(&alice_log),
    ));

    bob.accept(bob_io);
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert!(result(&first_results).is_none(), "nothing went out yet");

    // Alice's first SEND binds the connection to the session
    let to_bob = b"Hey Bob, are you there?".to_vec();
    let alice_results = send_message(&alice_demuxer, ALICE, BOB, to_bob.clone(), alice_tx, &rt);
    assert_eq!(wait_for("Bob to receive", || received(&bob_log)), to_bob);
    assert_eq!(
        wait_for("Alice's result", || result(&alice_results)),
        vec![(200, "Ok".to_string())]
    );

    assert_eq!(wait_for("Alice to receive", || received(&alice_log)), first);
    assert_eq!(
        wait_for("Bob's first result", || result(&first_results)),
        vec![(200, "Ok".to_string())]
    );

    alice_log.take();
    let second = b"Yes, I am".to_vec();
    let second_results = send_message(&bob_demuxer, BOB, ALICE, second.clone(), bob_tx, &rt);
    assert_eq!(
        wait_for("Alice to receive", || received(&alice_log)),
        second
    );
    assert_eq!(
        wait_for("Bob's second result", || result(&second_results)),
        vec![(200, "Ok".to_string())]
    );
}

#[test]
fn a_connection_binds_a_session_only_from_its_remote_end() {
    let rt = Arc::new(Runtime::new().unwrap());
    let bob_log = Log::default();
    let (bob, bob_demuxer, bob_tx) = passive_bob(&rt, &bob_log);
    let held = send_message(
        &bob_demuxer,
        BOB,
        ALICE,
        b"held".to_vec(),
        bob_tx.clone(),
        &rt,
    );

    let (mut alice_io, bob_io) = tokio::io::duplex(64 * 1024);
    bob.accept(bob_io);

    // To-Path is Bob's but From-Path is not Alice's: delivered, not bound
    let mallory = "msrp://mallory.example.com:2855/9fjskh3;tcp";
    let chunk = request(
        "mx1",
        "SEND",
        &[
            ("To-Path", BOB),
            ("From-Path", mallory),
            ("Message-ID", "m1"),
        ],
        None,
        ContinuationFlag::Complete,
    );
    rt.block_on(alice_io.write_all(&serialize(&chunk))).unwrap();
    assert!(matches!(
        &read_messages(&rt, &mut alice_io, 1)[..],
        [Parsed::Response(transaction_id, 200, _, _)] if transaction_id == "mx1"
    ));
    read_nothing(&rt, &mut alice_io);
    assert!(result(&held).is_none());

    // a path through a relay that ends with Alice binds it
    let from_path = format!("msrp://relay.example.com:2855/r1;tcp {}", ALICE);
    let chunk = request(
        "ax1",
        "SEND",
        &[
            ("To-Path", BOB),
            ("From-Path", &from_path),
            ("Message-ID", "m2"),
        ],
        None,
        ContinuationFlag::Complete,
    );
    rt.block_on(alice_io.write_all(&serialize(&chunk))).unwrap();
    let mut messages = read_messages(&rt, &mut alice_io, 2);
    messages.sort_by_key(|message| matches!(message, Parsed::Request(..)));
    assert!(
        matches!(&messages[0], Parsed::Response(transaction_id, 200, _, _) if transaction_id == "ax1")
    );
    match &messages[1] {
        Parsed::Request(_, method, _, body, _) => {
            assert_eq!(
                (method.as_str(), body.as_deref()),
                ("SEND", Some(&b"held"[..]))
            );
        }
        other => panic!("{:?}", other),
    }
}

#[test]
fn a_passive_session_waits_again_when_its_connection_closes() {
    let rt = Arc::new(Runtime::new().unwrap());
    let bob_log = Log::default();
    let (bob, bob_demuxer, bob_tx) = passive_bob(&rt, &bob_log);

    let bind = |io: &mut DuplexStream, transaction_id: &str| {
        let chunk = request(
            transaction_id,
            "SEND",
            &[("To-Path", BOB), ("From-Path", ALICE), ("Message-ID", "m1")],
            None,
            ContinuationFlag::Complete,
        );
        rt.block_on(io.write_all(&serialize(&chunk))).unwrap();
    };

    let (mut first_io, bob_io) = tokio::io::duplex(64 * 1024);
    bob.accept(bob_io);
    bind(&mut first_io, "c1");
    assert!(matches!(
        &read_messages(&rt, &mut first_io, 1)[..],
        [Parsed::Response(_, 200, _, _)]
    ));
    let waiting = |waiting: bool| {
        if bob.is_waiting(BOB.as_bytes(), ALICE.as_bytes()) == waiting {
            Some(())
        } else {
            None
        }
    };
    wait_for("the connection to be bound", || waiting(false));
    drop(first_io);
    wait_for("the connection to be released", || waiting(true));

    // the panicking socket factory shows that nothing tries to connect; the
    // last sender of chunks goes away while the chunk is held
    let held = send_message(&bob_demuxer, BOB, ALICE, b"held".to_vec(), bob_tx, &rt);
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert!(result(&held).is_none());

    // the response and the held chunk go out in either order
    let (mut second_io, bob_io) = tokio::io::duplex(64 * 1024);
    bob.accept(bob_io);
    bind(&mut second_io, "c2");
    let mut messages = read_messages(&rt, &mut second_io, 2);
    messages.sort_by_key(|message| matches!(message, Parsed::Request(..)));
    assert!(matches!(&messages[0], Parsed::Response(_, 200, _, _)));
    match &messages[1] {
        Parsed::Request(_, _, _, body, _) => assert_eq!(body.as_deref(), Some(&b"held"[..])),
        other => panic!("{:?}", other),
    }
}

#[test]
fn a_manager_stops_once_it_and_its_connections_are_gone() {
    let rt = Arc::new(Runtime::new().unwrap());
    let (tx, rx) = mpsc::channel::<MsrpChunk>(8);
    let manager = MsrpChannelManager::new(
        rx,
        |_: &[u8], _: &[u8]| -> DuplexStream { panic!("no connection is opened") },
        Arc::clone(&rt),
    );
    let (io, peer) = tokio::io::duplex(1024);
    manager.accept(io);

    drop(tx);
    drop(manager);
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert!(
        rt.metrics().num_alive_tasks() > 0,
        "the accepted connection is open"
    );

    drop(peer);
    wait_for("every task to end", || {
        if rt.metrics().num_alive_tasks() == 0 {
            Some(())
        } else {
            None
        }
    });
}

fn read_eof(rt: &Runtime, io: &mut DuplexStream) {
    rt.block_on(async {
        let mut buf = [0; 4096];
        loop {
            let size = timeout(Duration::from_secs(5), io.read(&mut buf))
                .await
                .expect("the connection stayed open")
                .unwrap();
            if size == 0 {
                return;
            }
        }
    })
}

fn bodiless_send(transaction_id: &str, to_path: &str, from_path: &str) -> Vec<u8> {
    serialize(&request(
        transaction_id,
        "SEND",
        &[
            ("To-Path", to_path),
            ("From-Path", from_path),
            ("Message-ID", transaction_id),
        ],
        None,
        ContinuationFlag::Complete,
    ))
}

fn status_of(messages: Vec<Parsed>) -> Vec<(String, u16)> {
    messages
        .into_iter()
        .map(|message| match message {
            Parsed::Response(transaction_id, status_code, _, _) => (transaction_id, status_code),
            other => panic!("{:?}", other),
        })
        .collect()
}

#[test]
fn an_ended_session_is_removed_and_its_connection_closes_last() {
    const BOB_2: &str = "msrp://biloxi.example.com:12763/second;tcp";
    const ALICE_2: &str = "msrp://atlanta.example.com:7654/second;tcp";

    let rt = Arc::new(Runtime::new().unwrap());
    let (_tx, rx) = mpsc::channel(8);
    let bob = MsrpChannelManager::new(
        rx,
        |_: &[u8], _: &[u8]| -> DuplexStream { panic!("no connection is opened") },
        Arc::clone(&rt),
    );
    for (local, remote) in [(BOB, ALICE), (BOB_2, ALICE_2)] {
        bob.register_passive_channel(MsrpChannel::new(
            local.as_bytes().to_vec(),
            remote.as_bytes().to_vec(),
            Arc::new(MsrpDemuxer::new(
                local.as_bytes().to_vec(),
                remote.as_bytes().to_vec(),
            )),
            muxer(&Log::default()),
        ));
    }

    // both sessions bind the one connection
    let (mut alice_io, bob_io) = tokio::io::duplex(64 * 1024);
    bob.accept(bob_io);
    let mut data = bodiless_send("s1", BOB, ALICE);
    data.extend(bodiless_send("s2", BOB_2, ALICE_2));
    rt.block_on(alice_io.write_all(&data)).unwrap();
    let mut statuses = status_of(read_messages(&rt, &mut alice_io, 2));
    statuses.sort();
    assert_eq!(statuses, vec![("s1".into(), 200), ("s2".into(), 200)]);
    wait_for("both sessions to be bound", || {
        let bound = !bob.is_waiting(BOB.as_bytes(), ALICE.as_bytes())
            && !bob.is_waiting(BOB_2.as_bytes(), ALICE_2.as_bytes());
        bound.then_some(())
    });

    assert!(bob.unregister_channel(BOB.as_bytes(), ALICE.as_bytes()));
    assert!(!bob.unregister_channel(BOB.as_bytes(), ALICE.as_bytes()));

    // the other session keeps the connection
    let mut data = bodiless_send("s3", BOB, ALICE);
    data.extend(bodiless_send("s4", BOB_2, ALICE_2));
    rt.block_on(alice_io.write_all(&data)).unwrap();
    assert_eq!(
        status_of(read_messages(&rt, &mut alice_io, 2)),
        vec![("s3".into(), 481), ("s4".into(), 200)]
    );
    read_nothing(&rt, &mut alice_io);

    assert!(bob.unregister_channel(BOB_2.as_bytes(), ALICE_2.as_bytes()));
    read_eof(&rt, &mut alice_io);
}

#[test]
fn an_ended_session_drops_what_it_held() {
    let rt = Arc::new(Runtime::new().unwrap());
    let bob_log = Log::default();
    let (bob, bob_demuxer, bob_tx) = passive_bob(&rt, &bob_log);
    let held = send_message(&bob_demuxer, BOB, ALICE, b"held".to_vec(), bob_tx, &rt);

    assert!(bob.unregister_channel(BOB.as_bytes(), ALICE.as_bytes()));

    let (mut alice_io, bob_io) = tokio::io::duplex(64 * 1024);
    bob.accept(bob_io);
    rt.block_on(alice_io.write_all(&bodiless_send("s1", BOB, ALICE)))
        .unwrap();
    assert_eq!(
        status_of(read_messages(&rt, &mut alice_io, 1)),
        vec![("s1".into(), 481)]
    );
    read_nothing(&rt, &mut alice_io);
    assert!(result(&held).is_none());
}

fn start_sending_reported<R>(
    demuxer: &MsrpDemuxer,
    reader: R,
    total: usize,
    rt: &Arc<Runtime>,
) -> (mpsc::Receiver<MsrpChunk>, Results)
where
    R: Read + Send + Sync + 'static,
{
    let (tx, rx) = mpsc::channel(8);
    let results: Results = Arc::default();
    let results_ = Arc::clone(&results);
    demuxer.start_with_success_report(
        ALICE.as_bytes().to_vec(),
        BOB.as_bytes().to_vec(),
        Some(b"text/plain".to_vec()),
        total,
        reader,
        move |status_code, reason_phrase| {
            results_.lock().unwrap().push((status_code, reason_phrase));
        },
        tx,
        rt,
    );
    (rx, results)
}

fn header_of(chunk: &MsrpChunk, name: &str) -> Option<String> {
    chunk
        .headers()
        .iter()
        .find(|h| h.get_name() == name.as_bytes())
        .map(|h| text(h.get_value()))
}

fn report_for(message_id: &str, byte_range: &str, status: &str) -> MsrpChunk {
    request(
        "r1",
        "REPORT",
        &[
            ("To-Path", ALICE),
            ("From-Path", BOB),
            ("Message-ID", message_id),
            ("Byte-Range", byte_range),
            ("Status", status),
        ],
        None,
        ContinuationFlag::Complete,
    )
}

#[test]
fn demuxer_waits_for_success_reports_covering_the_message() {
    let rt = Arc::new(Runtime::new().unwrap());
    let demuxer = demuxer();
    let body = vec![b'x'; 25 * 1024];
    let (mut rx, results) =
        start_sending_reported(&demuxer, std::io::Cursor::new(body), 25 * 1024, &rt);
    let chunks = sent_chunks(&rt, &mut rx, 3);

    for chunk in &chunks {
        assert_eq!(header_of(chunk, "Success-Report").as_deref(), Some("yes"));
    }
    let message_id = header_of(&chunks[0], "Message-ID").unwrap();

    for chunk in &chunks {
        assert!(demuxer.on_response(response_to(chunk, 200, "OK")).is_ok());
    }
    assert!(
        results.lock().unwrap().is_empty(),
        "accepted, not yet reported"
    );

    assert!(demuxer
        .on_report(report_for(&message_id, "1-10240/25600", "000 200 OK"))
        .is_ok());
    assert!(results.lock().unwrap().is_empty(), "only part is reported");

    assert!(demuxer
        .on_report(report_for(&message_id, "10241-25600/25600", "000 200 OK"))
        .is_ok());
    assert_eq!(*results.lock().unwrap(), vec![(200, "Ok".to_string())]);

    assert!(demuxer
        .on_report(report_for(&message_id, "1-25600/25600", "000 200 OK"))
        .is_err());
    assert_eq!(results.lock().unwrap().len(), 1);
}

#[test]
fn demuxer_takes_reports_before_responses_and_failure_reports() {
    let rt = Arc::new(Runtime::new().unwrap());
    let demuxer = demuxer();

    let (mut rx, results) =
        start_sending_reported(&demuxer, std::io::Cursor::new(b"Hello".to_vec()), 5, &rt);
    let chunks = sent_chunks(&rt, &mut rx, 1);
    let message_id = header_of(&chunks[0], "Message-ID").unwrap();
    assert!(demuxer
        .on_report(report_for(&message_id, "1-5/5", "000 200 OK"))
        .is_ok());
    assert_eq!(*results.lock().unwrap(), vec![(200, "Ok".to_string())]);

    let (mut rx, results) =
        start_sending_reported(&demuxer, std::io::Cursor::new(b"Hello".to_vec()), 5, &rt);
    let chunks = sent_chunks(&rt, &mut rx, 1);
    let message_id = header_of(&chunks[0], "Message-ID").unwrap();
    assert!(demuxer
        .on_response(response_to(&chunks[0], 200, "OK"))
        .is_ok());
    assert!(demuxer
        .on_report(report_for(&message_id, "1-5/5", "000 413 Too big"))
        .is_ok());
    assert_eq!(*results.lock().unwrap(), vec![(413, "Too big".to_string())]);
}

#[test]
fn demuxer_times_out_without_success_reports() {
    let rt = Arc::new(
        Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap(),
    );
    let demuxer = demuxer();
    let (mut rx, results) =
        start_sending_reported(&demuxer, std::io::Cursor::new(b"Hello".to_vec()), 5, &rt);
    let chunks = sent_chunks(&rt, &mut rx, 1);
    assert!(demuxer
        .on_response(response_to(&chunks[0], 200, "OK"))
        .is_ok());

    rt.block_on(async { sleep(Duration::from_secs(59)).await });
    assert!(results.lock().unwrap().is_empty());

    rt.block_on(async { sleep(Duration::from_secs(2)).await });
    assert_eq!(*results.lock().unwrap(), vec![(408, "Timeout".to_string())]);
}

#[test]
fn an_empty_message_ends_with_its_response_even_when_reports_are_asked_for() {
    let rt = Arc::new(Runtime::new().unwrap());
    let demuxer = demuxer();
    let (mut rx, results) = start_sending_reported(&demuxer, std::io::empty(), 0, &rt);
    let chunks = sent_chunks(&rt, &mut rx, 1);

    assert_eq!(header_of(&chunks[0], "Success-Report"), None);
    assert!(demuxer
        .on_response(response_to(&chunks[0], 200, "OK"))
        .is_ok());
    assert_eq!(*results.lock().unwrap(), vec![(200, "Ok".to_string())]);
}

#[test]
fn a_success_report_comes_back_through_the_wire_format() {
    let rt = Arc::new(Runtime::new().unwrap());
    let alice_demuxer = Arc::new(demuxer());
    let mut alice = MsrpChannel::new(
        ALICE.as_bytes().to_vec(),
        BOB.as_bytes().to_vec(),
        Arc::clone(&alice_demuxer),
        muxer(&Log::default()),
    );
    let bob_log = Log::default();
    let mut bob = channel(&bob_log);

    let body: Vec<u8> = (0..25 * 1024).map(|i| b'a' + (i % 26) as u8).collect();
    let (mut rx, results) = start_sending_reported(
        &alice_demuxer,
        std::io::Cursor::new(body.clone()),
        body.len(),
        &rt,
    );

    let mut to_bob = MsrpParser::new();
    let mut to_alice = MsrpParser::new();
    let mut replies = Vec::new();
    for chunk in sent_chunks(&rt, &mut rx, 3) {
        to_bob.feed(&serialize(&chunk));
        let chunk = to_bob.produce().unwrap().unwrap();
        for reply in bob.on_message(chunk).unwrap() {
            to_alice.feed(&serialize(&reply));
            let reply = to_alice.produce().unwrap().unwrap();
            replies.push(match &reply {
                MsrpChunk::Request(req_line, _, _, _) => text(&req_line.request_method),
                MsrpChunk::Response(resp_line, _) => resp_line.status_code.to_string(),
            });
            assert!(alice.on_message(reply).unwrap().is_empty());
            if replies.len() == 3 {
                assert!(
                    results.lock().unwrap().is_empty(),
                    "three 200s are not enough"
                );
            }
        }
    }

    assert_eq!(replies, vec!["200", "200", "200", "REPORT"]);
    assert_eq!(*results.lock().unwrap(), vec![(200, "Ok".to_string())]);
    assert_eq!(received(&bob_log), Some(body));
}

fn sdp_with(media_lines: &str) -> String {
    sdp_at("IN IP4 192.0.2.9", 2856, media_lines)
}

/// An SDP with `connection` in c= and `port` in m=.
fn sdp_at(connection: &str, port: u16, media_lines: &str) -> String {
    format!(
        "v=0\r\n\
o=- 1 1 IN IP4 192.0.2.9\r\n\
s=-\r\n\
t=0 0\r\n\
m=message {} TCP/MSRP *\r\n\
c={}\r\n\
a=accept-types:message/cpim\r\n\
{}",
        port, connection, media_lines
    )
}

fn connection_address(sdp: &str, local_cema: bool) -> Option<(String, u16)> {
    let sdp = sdp.as_bytes().as_sdp().unwrap();
    let info = sdp.as_msrp_info().unwrap();
    info.connection_address(local_cema)
        .map(|(host, port)| (text(host), port))
}

fn connection_matches_path(connection: &str, port: u16, path: &str) -> Option<bool> {
    let sdp = sdp_at(connection, port, &format!("a=path:{}\r\n", path));
    let sdp = sdp.as_bytes().as_sdp().unwrap();
    let info = sdp.as_msrp_info().unwrap();
    info.connection_matches_path()
}

#[test]
fn reads_and_writes_msrp_cema() {
    let path = "a=path:msrp://198.51.100.7:2855/xyz;tcp\r\n";
    for (lines, cema) in [
        (format!("{}a=msrp-cema\r\n", path), true),
        (path.to_string(), false),
    ] {
        let sdp = sdp_with(&lines);
        let sdp = sdp.as_bytes().as_sdp().unwrap();
        assert_eq!(sdp.as_msrp_info().unwrap().cema, cema);
    }

    for cema in [true, false] {
        let mut info = msrp_info(false);
        info.cema = cema;
        let sdp: String = info.into();
        assert_eq!(sdp.contains("\r\na=msrp-cema\r\n"), cema);
        let read = sdp.as_bytes().as_sdp().unwrap();
        assert_eq!(read.as_msrp_info().unwrap().cema, cema);
    }
}

#[test]
fn connects_where_cema_says() {
    // an intermediary rewrote c= and m= to 192.0.2.9:2856, a=path still
    // names the endpoint; what counts is whether this end does CEMA, not
    // whether the remote one does (RFC 6714 sections 4.2 and 4.3)
    let path = "a=path:msrp://198.51.100.7:2855/xyz;tcp\r\n";
    for remote in [path.to_string(), format!("{}a=msrp-cema\r\n", path)] {
        let sdp = sdp_with(&remote);
        assert_eq!(
            connection_address(&sdp, true),
            Some(("192.0.2.9".into(), 2856)),
            "doing CEMA, the c= address and m= port: {}",
            remote
        );
        assert_eq!(
            connection_address(&sdp, false),
            Some(("198.51.100.7".into(), 2855)),
            "not doing CEMA, the a=path URI: {}",
            remote
        );
    }

    assert_eq!(
        connection_address(
            &sdp_with(
                "a=path:msrps://bob@[2001:db8::1]:2857/relay;tcp msrps://[2001:db8::2]:2858/abc;tcp\r\n"
            ),
            false
        ),
        Some(("2001:db8::1".into(), 2857)),
        "the first hop of a path, IPv6"
    );
    assert_eq!(
        connection_address(
            &sdp_with("a=path:msrp://relay.example.com/xyz;tcp\r\n"),
            false
        ),
        None,
        "no port"
    );
}

#[test]
fn tells_a_rewritten_connection_address() {
    // RFC 6714 section 4.4
    let v4 = "IN IP4 192.0.2.9";
    let name = "IN IP4 alice.example.com";

    for (connection, port, path, matches, why) in [
        (
            v4,
            2856,
            "msrp://192.0.2.9:2856/xyz;tcp",
            Some(true),
            "the endpoint's own",
        ),
        (
            v4,
            2856,
            "msrp://198.51.100.7:2855/xyz;tcp",
            Some(false),
            "rewritten",
        ),
        (
            v4,
            2857,
            "msrp://192.0.2.9:2856/xyz;tcp",
            Some(false),
            "another port",
        ),
        (
            "IN IP6 2001:db8::1",
            2856,
            "msrp://[2001:0db8:0:0:0:0:0:1]:2856/xyz;tcp",
            Some(true),
            "IPv6 spelled otherwise",
        ),
        (
            v4,
            2856,
            "msrps://relay.example.com:2855/r;tcp msrps://192.0.2.9:2856/xyz;tcp",
            Some(true),
            "any URI of the path",
        ),
        (
            name,
            2856,
            "msrp://ALICE.example.com:2856/xyz;tcp",
            Some(true),
            "the same name",
        ),
        (
            v4,
            2856,
            "msrp://alice.example.com:2856/xyz;tcp",
            None,
            "a name in a=path",
        ),
        (
            name,
            2856,
            "msrp://192.0.2.9:2856/xyz;tcp",
            None,
            "a name in c=",
        ),
        (
            v4,
            2856,
            "msrp://alice.example.com:2855/xyz;tcp",
            Some(false),
            "a name, but another port",
        ),
    ] {
        assert_eq!(
            connection_matches_path(connection, port, path),
            matches,
            "{}",
            why
        );
    }
}
