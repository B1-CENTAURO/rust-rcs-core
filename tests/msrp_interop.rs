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

//! MSRP against msrplib, AG Projects' implementation used by Blink and
//! SylkServer, over TCP on localhost; see interop/README.md. The tests need
//! MSRPLIB_PYTHON, a Python that can import msrplib, as made by
//! interop/msrplib/setup.sh:
//!
//!     MSRPLIB_PYTHON=... cargo test --test msrp_interop -- --ignored

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Cursor};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc as std_mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use data_encoding::HEXLOWER;
use ring::digest::{digest, SHA256};
use serde_json::Value;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

use rust_rcs_core::msrp::msrp_channel::{MsrpChannel, MsrpChannelManager};
use rust_rcs_core::msrp::msrp_chunk::MsrpChunk;
use rust_rcs_core::msrp::msrp_demuxer::MsrpDemuxer;
use rust_rcs_core::msrp::msrp_muxer::{MsrpDataWriter, MsrpMessageReceiver, MsrpMuxer};

const TIMEOUT: Duration = Duration::from_secs(60);

// label, size, content type, success report; msrplib takes text/plain and
// application/octet-stream only
const MESSAGES: [(&str, usize, &str, bool); 4] = [
    ("rs-small", 5, "text/plain", true),
    ("rs-chunked", 25 * 1024, "application/octet-stream", true),
    ("rs-plain", 3000, "text/plain", false),
    ("rs-rejected", 5, "application/x-rejected", false),
];

// what msrplib sends, see MESSAGES in peer.py
const PEER_ACCEPTED: [(&str, usize); 4] = [
    ("py-small", 5),
    ("py-chunked", 25000),
    ("py-whole", 5000),
    ("py-no-response", 5),
];

// the same bodies as peer.py makes
fn body(label: &str, size: usize) -> Vec<u8> {
    label.bytes().cycle().take(size).collect()
}

fn sha256(data: &[u8]) -> String {
    HEXLOWER.encode(digest(&SHA256, data).as_ref())
}

#[derive(Default)]
struct Incoming {
    content_type: String,
    data: Vec<u8>,
    complete: bool,
    aborted: bool,
}

/// What arrives, by Message-ID; application/x-rejected is refused with 415.
#[derive(Clone, Default)]
struct Inbox(Arc<Mutex<HashMap<String, Incoming>>>);

struct Writer(Inbox, String);

impl MsrpDataWriter for Writer {
    fn write(&mut self, data: &[u8]) -> Result<usize, (u16, &'static str)> {
        let mut guard = (self.0).0.lock().unwrap();
        guard.get_mut(&self.1).unwrap().data.extend_from_slice(data);
        Ok(data.len())
    }

    fn complete(&mut self) -> Result<(), (u16, &'static str)> {
        (self.0)
            .0
            .lock()
            .unwrap()
            .get_mut(&self.1)
            .unwrap()
            .complete = true;
        Ok(())
    }

    fn abort(&mut self) {
        (self.0).0.lock().unwrap().get_mut(&self.1).unwrap().aborted = true;
    }
}

impl MsrpMessageReceiver for Inbox {
    fn on_message(
        &mut self,
        message_id: &[u8],
        content_type: &[u8],
    ) -> Result<Box<dyn MsrpDataWriter + Send + Sync>, (u16, &'static str)> {
        if content_type == b"application/x-rejected" {
            return Err((415, "Unsupported Media Type"));
        }
        let message_id = String::from_utf8_lossy(message_id).to_string();
        self.0.lock().unwrap().insert(
            message_id.clone(),
            Incoming {
                content_type: String::from_utf8_lossy(content_type).to_string(),
                ..Default::default()
            },
        );
        Ok(Box::new(Writer(self.clone(), message_id)))
    }
}

/// The msrplib end, writing its events to a channel.
struct Peer {
    child: Child,
    events: std_mpsc::Receiver<Value>,
    seen: Vec<Value>,
}

impl Peer {
    fn start(mode: &str, local_uri: &str, remote_uri: &str) -> Peer {
        let python = std::env::var("MSRPLIB_PYTHON")
            .expect("MSRPLIB_PYTHON is a Python with msrplib, see interop/README.md");
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("interop/msrplib/peer.py");
        let mut child = Command::new(python)
            .arg("-I")
            .arg(script)
            .args([mode, local_uri, remote_uri])
            .stdout(Stdio::piped())
            .spawn()
            .expect("cannot run MSRPLIB_PYTHON");

        let stdout = child.stdout.take().unwrap();
        let (tx, events) = std_mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let line = match line {
                    Ok(line) => line,
                    Err(_) => break,
                };
                match serde_json::from_str(&line) {
                    Ok(event) => {
                        if tx.send(event).is_err() {
                            break;
                        }
                    }
                    Err(_) => eprintln!("peer: {}", line),
                }
            }
        });

        Peer {
            child,
            events,
            seen: Vec::new(),
        }
    }

    /// Waits for the event, keeping those before it.
    fn wait_for(&mut self, event: &str) -> Value {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.events.recv_timeout(left) {
                Ok(value) => {
                    self.seen.push(value.clone());
                    if value["event"] == event {
                        return value;
                    }
                }
                Err(_) => panic!("no {} from msrplib; got {:#?}", event, self.seen),
            }
        }
    }

    fn events(&self, event: &str) -> Vec<&Value> {
        self.seen.iter().filter(|v| v["event"] == event).collect()
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

type Results = Arc<Mutex<HashMap<&'static str, (u16, String)>>>;

/// Our end of the session: its channel, registered as passive or with
/// connections opened to `connect_to`, and the messages of MESSAGES sent.
struct Endpoint {
    manager: MsrpChannelManager,
    demuxer: Arc<MsrpDemuxer>,
    inbox: Inbox,
    results: Results,
}

impl Endpoint {
    fn new(
        rt: &Arc<Runtime>,
        local_uri: &str,
        remote_uri: &str,
        connect_to: Option<SocketAddr>,
    ) -> Endpoint {
        let (tx, rx) = mpsc::channel::<MsrpChunk>(64);
        let manager = MsrpChannelManager::new(
            rx,
            move |_: &[u8], _: &[u8]| {
                let addr = connect_to.expect("a passive session opened a connection");
                let stream = std::net::TcpStream::connect(addr).unwrap();
                stream.set_nonblocking(true).unwrap();
                tokio::net::TcpStream::from_std(stream).unwrap()
            },
            Arc::clone(rt),
        );

        let demuxer = Arc::new(MsrpDemuxer::new(
            local_uri.as_bytes().to_vec(),
            remote_uri.as_bytes().to_vec(),
        ));
        let inbox = Inbox::default();
        let channel = MsrpChannel::new(
            local_uri.as_bytes().to_vec(),
            remote_uri.as_bytes().to_vec(),
            Arc::clone(&demuxer),
            MsrpMuxer::new(inbox.clone()),
        );
        if connect_to.is_some() {
            manager.register_channel(channel);
        } else {
            manager.register_passive_channel(channel);
        }

        let results: Results = Arc::default();
        for (label, size, content_type, success_report) in MESSAGES {
            let results = Arc::clone(&results);
            let callback = move |status_code, reason_phrase| {
                results
                    .lock()
                    .unwrap()
                    .insert(label, (status_code, reason_phrase));
            };
            let args = (
                local_uri.as_bytes().to_vec(),
                remote_uri.as_bytes().to_vec(),
                Some(content_type.as_bytes().to_vec()),
                size,
                Cursor::new(body(label, size)),
            );
            if success_report {
                demuxer.start_with_success_report(
                    args.0,
                    args.1,
                    args.2,
                    args.3,
                    args.4,
                    callback,
                    tx.clone(),
                    rt,
                );
            } else {
                demuxer.start(
                    args.0,
                    args.1,
                    args.2,
                    args.3,
                    args.4,
                    callback,
                    tx.clone(),
                    rt,
                );
            }
        }

        Endpoint {
            manager,
            demuxer,
            inbox,
            results,
        }
    }

    fn wait_for_results(&self) {
        let deadline = Instant::now() + TIMEOUT;
        while self.results.lock().unwrap().len() < MESSAGES.len() {
            assert!(
                Instant::now() < deadline,
                "messages not ended: {:?}",
                self.results.lock().unwrap()
            );
            thread::sleep(Duration::from_millis(50));
        }
    }
}

/// What both ends should have seen once msrplib is done.
fn check(peer: &mut Peer, endpoint: &Endpoint) {
    endpoint.wait_for_results();
    peer.wait_for("done");

    // ours, at msrplib
    let results = endpoint.results.lock().unwrap();
    for (label, _, _, _) in MESSAGES {
        let expected = if label == "rs-rejected" { 415 } else { 200 };
        assert_eq!(
            results[label].0, expected,
            "{}: {:?}",
            label, results[label]
        );
    }
    let received = peer.events("received");
    for (label, size, content_type, _) in MESSAGES {
        let at_peer: Vec<_> = received
            .iter()
            .filter(|v| v["sha256"] == sha256(&body(label, size)))
            .collect();
        if label == "rs-rejected" {
            assert!(at_peer.is_empty(), "{:?}", at_peer);
            continue;
        }
        assert_eq!(at_peer.len(), 1, "{}: {:#?}", label, received);
        assert_eq!(at_peer[0]["size"], size, "{}", label);
        assert_eq!(at_peer[0]["content_type"], content_type, "{}", label);
    }
    let chunked = received.iter().find(|v| v["size"] == 25 * 1024).unwrap();
    assert_eq!(chunked["flags"], "++$", "sent in three chunks");

    // msrplib's, here
    let inbox = endpoint.inbox.0.lock().unwrap();
    for (label, size) in PEER_ACCEPTED {
        let message = inbox
            .get(label)
            .unwrap_or_else(|| panic!("{} not received", label));
        assert!(message.complete && !message.aborted, "{}", label);
        assert_eq!(message.data, body(label, size), "{}", label);
        let sent = peer
            .events("message")
            .into_iter()
            .find(|v| v["label"] == label)
            .unwrap();
        assert_eq!(sent["sha256"], sha256(&message.data), "{}", label);
    }
    assert!(!inbox.contains_key("py-rejected"));
    assert_eq!(inbox["py-small"].content_type, "text/plain");
    assert_eq!(inbox["py-chunked"].content_type, "application/octet-stream");

    // our responses to msrplib's chunks
    let responses: Vec<(String, Option<u64>)> = peer
        .events("response")
        .iter()
        .map(|v| (v["label"].as_str().unwrap().to_string(), v["code"].as_u64()))
        .collect();
    let expected: Vec<(String, Option<u64>)> = [
        ("py-small", Some(200)),
        ("py-chunked", Some(200)),
        ("py-chunked", Some(200)),
        ("py-chunked", Some(200)),
        ("py-whole", Some(200)),
        ("py-no-response", None), // msrplib does not wait for one
        ("py-rejected", Some(415)),
    ]
    .iter()
    .map(|(label, code)| (label.to_string(), *code))
    .collect();
    assert_eq!(responses, expected);

    // and none to a chunk with Failure-Report: no
    let no_response = peer
        .events("sent")
        .into_iter()
        .find(|v| v["label"] == "py-no-response")
        .unwrap()["transaction_id"]
        .clone();
    let answered: Vec<_> = peer
        .events("chunk")
        .into_iter()
        .filter(|v| v["transaction_id"] == no_response)
        .collect();
    assert!(answered.is_empty(), "{:?}", answered);

    // our success REPORTs, for what msrplib asked them for
    let reports: Vec<(String, u64, String)> = peer
        .events("report")
        .iter()
        .map(|v| {
            (
                v["message_id"].as_str().unwrap().to_string(),
                v["code"].as_u64().unwrap(),
                v["byte_range"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    assert_eq!(
        reports,
        vec![
            ("py-small".to_string(), 200, "1-5/5".to_string()),
            ("py-chunked".to_string(), 200, "1-25000/25000".to_string()),
        ]
    );

    assert_eq!(endpoint.demuxer.session_failure(), None);
}

// kept for the whole test run: the library's tasks hold clones, and the last
// one dropped from inside a task would panic
fn rt() -> Arc<Runtime> {
    let rt = Arc::new(Runtime::new().unwrap());
    std::mem::forget(Arc::clone(&rt));
    rt
}

#[test]
#[ignore = "needs msrplib, see interop/README.md"]
fn we_connect_to_msrplib() {
    let rt = rt();
    let ours = "msrp://127.0.0.1:2855/rust-active;tcp";
    let mut peer = Peer::start("accept", "msrp://127.0.0.1:0/py-passive;tcp", ours);
    let theirs = peer.wait_for("listening")["uri"]
        .as_str()
        .unwrap()
        .to_string();
    let port = theirs
        .rsplit(':')
        .next()
        .and_then(|rest| rest.split('/').next())
        .and_then(|port| port.parse::<u16>().ok())
        .unwrap();

    let endpoint = Endpoint::new(
        &rt,
        ours,
        &theirs,
        Some(SocketAddr::from(([127, 0, 0, 1], port))),
    );
    check(&mut peer, &endpoint);
}

#[test]
#[ignore = "needs msrplib, see interop/README.md"]
fn msrplib_connects_to_us() {
    let rt = rt();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let ours = format!(
        "msrp://127.0.0.1:{}/rust-passive;tcp",
        listener.local_addr().unwrap().port()
    );
    let theirs = "msrp://127.0.0.1:2855/py-active;tcp";

    let endpoint = Endpoint::new(&rt, &ours, theirs, None);
    let mut peer = Peer::start("connect", theirs, &ours);

    let (stream, _) = listener.accept().unwrap();
    stream.set_nonblocking(true).unwrap();
    let _guard = rt.enter();
    endpoint
        .manager
        .accept(tokio::net::TcpStream::from_std(stream).unwrap());

    check(&mut peer, &endpoint);
}
