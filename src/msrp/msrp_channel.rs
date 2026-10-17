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
// use std::sync::mpsc;
use std::sync::{Arc, Mutex};
// use std::thread;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

use crate::internet::header::Header;

use crate::io::{DynamicChain, Serializable};

use crate::util::rand;

use super::msrp_chunk::ContinuationFlag;
use super::msrp_chunk::MsrpChunk;
use super::msrp_chunk::MsrpChunkInfo;
use super::msrp_chunk::MsrpRequestLine;
use super::msrp_chunk::MsrpResponseLine;
use super::msrp_chunk::ReportFailure;
use super::msrp_chunk::ReportSuccess;
use super::msrp_demuxer::MsrpDemuxer;
use super::msrp_muxer::MsrpMuxer;
use super::msrp_transport::msrp_transport_start;
// use super::msrp_transport::MsrpTransportFactory;
// use super::msrp_transport::{MsrpTransport, MsrpTransportWrapper};

pub struct MsrpChannel {
    from_path: Vec<u8>, // local_path
    #[allow(dead_code)] // routing only needs the local path
    to_path: Vec<u8>, // remote_path
    demuxer: Arc<MsrpDemuxer>,
    muxer: MsrpMuxer,
}

impl MsrpChannel {
    pub fn new(
        from_path: Vec<u8>,
        to_path: Vec<u8>,
        demuxer: Arc<MsrpDemuxer>,
        muxer: MsrpMuxer,
    ) -> MsrpChannel {
        MsrpChannel {
            from_path,
            to_path,
            demuxer,
            muxer,
        }
    }

    pub fn on_message<'a>(&mut self, message: MsrpChunk) -> Result<Vec<MsrpChunk>, &'static str> {
        match &message {
            MsrpChunk::Request(req_line, _, _, _) => {
                if let Some(chunk_info) = message.get_chunk_info() {
                    let transaction_id = req_line.transaction_id.clone();
                    let mut resp_headers = response_headers(&chunk_info);

                    if req_line.request_method == b"SEND" {
                        let mut success_report = None;

                        if let Some(message_id) = chunk_info.message_id {
                            resp_headers.push(Header::new(b"Message-ID", message_id.to_vec()));

                            if let Some(ReportSuccess::Yes) = chunk_info.success_report {
                                success_report =
                                    Some((chunk_info.from_path.to_vec(), message_id.to_vec()));
                            }
                        }

                        let mut failure_report = ReportFailure::Yes;
                        if let Some(failure_report_) = chunk_info.failure_report {
                            failure_report = failure_report_;
                        }

                        match self.muxer.feed(message) {
                            Ok(size) => {
                                let mut chunks = Vec::new();

                                if let ReportFailure::Yes = failure_report {
                                    chunks.push(MsrpChunk::new_response_chunk(
                                        MsrpResponseLine {
                                            transaction_id,
                                            status_code: 200,
                                            comment: Some(b"OK".to_vec()),
                                        },
                                        resp_headers,
                                    ));
                                }

                                if let (Some(size), Some((to_path, message_id))) =
                                    (size, success_report)
                                {
                                    chunks.push(make_success_report(
                                        to_path,
                                        self.from_path.clone(),
                                        message_id,
                                        size,
                                    ));
                                }

                                Ok(chunks)
                            }

                            Err((status_code, comment)) => match failure_report {
                                ReportFailure::Yes | ReportFailure::Partial => {
                                    Ok(vec![MsrpChunk::new_response_chunk(
                                        MsrpResponseLine {
                                            transaction_id,
                                            status_code,
                                            comment: Some(comment.as_bytes().to_vec()),
                                        },
                                        resp_headers,
                                    )])
                                }
                                _ => Ok(Vec::new()),
                            },
                        }
                    } else if req_line.request_method == b"REPORT" {
                        if let Ok(_) = self.demuxer.on_report(message) {
                            Ok(Vec::new())
                        } else {
                            Ok(Vec::new())
                        }
                    } else {
                        Ok(vec![MsrpChunk::new_response_chunk(
                            MsrpResponseLine {
                                transaction_id,
                                status_code: 501,
                                comment: Some(b"Unknown request method".to_vec()),
                            },
                            resp_headers,
                        )])
                    }
                } else {
                    Err("Bad Format")
                }
            }
            MsrpChunk::Response(_, _) => match self.demuxer.on_response(message) {
                Ok(_) => Ok(Vec::new()),

                Err(_) => Ok(Vec::new()),
            },
        }
    }
}

// RFC 4975 section 7.1.2, a REPORT covering the whole message back along the
// From-Path of the SEND
fn make_success_report(
    to_path: Vec<u8>,
    from_path: Vec<u8>,
    message_id: Vec<u8>,
    size: usize,
) -> MsrpChunk {
    MsrpChunk::new_request_chunk(
        MsrpRequestLine {
            transaction_id: rand::create_raw_alpha_numeric_string(16),
            request_method: b"REPORT".to_vec(),
        },
        vec![
            Header::new(b"To-Path", to_path),
            Header::new(b"From-Path", from_path),
            Header::new(b"Message-ID", message_id),
            Header::new(b"Byte-Range", format!("1-{}/{}", size, size)),
            Header::new(b"Status", b"000 200 OK"),
        ],
        None,
        ContinuationFlag::Complete,
    )
}

type Transports = Arc<Mutex<Vec<(Vec<u8>, Vec<u8>, Arc<mpsc::Sender<Option<Vec<u8>>>>)>>>;

pub struct MsrpChannelManager {
    // tx: mpsc::Sender<MsrpChunk>,
    // transports: Arc<Mutex<Vec<(Vec<u8>, Vec<u8>, Arc<mpsc::Sender<Option<Vec<u8>>>>)>>>,
    channels: Arc<Mutex<Vec<MsrpChannel>>>,
}

impl MsrpChannelManager {
    /// Sends the chunks it receives on `rx`, over one connection per pair of
    /// From-Path and To-Path, which the first chunk opens with `socket_factory`.
    /// What arrives on a connection goes to the registered channels.
    pub fn new<F, T>(
        mut rx: mpsc::Receiver<MsrpChunk>,
        socket_factory: F,
        rt: Arc<Runtime>,
    ) -> MsrpChannelManager
    where
        F: Fn(&[u8], &[u8]) -> T + Send + 'static,
        T: AsyncRead + AsyncWrite + Send + 'static,
    {
        let transports: Transports = Arc::new(Mutex::new(Vec::new()));

        let channels: Arc<Mutex<Vec<MsrpChannel>>> = Arc::new(Mutex::new(Vec::new()));
        let channels_ = Arc::clone(&channels);

        let rt_ = Arc::clone(&rt);
        rt.spawn(async move {
            while let Some(message) = rx.recv().await {
                if let Some(chunk_info) = message.get_chunk_info() {
                    let tx = {
                        let mut guard = transports.lock().unwrap();
                        match guard.iter().find(|(from_path, to_path, _)| {
                            *from_path == chunk_info.from_path && *to_path == chunk_info.to_path
                        }) {
                            Some((_, _, tx)) => Arc::clone(tx),

                            None => {
                                let t = socket_factory(chunk_info.from_path, chunk_info.to_path);
                                let t_id = format!(
                                    "{}-{}",
                                    String::from_utf8_lossy(chunk_info.from_path),
                                    String::from_utf8_lossy(chunk_info.to_path),
                                );

                                let (data_tx, data_rx) = mpsc::channel(8);
                                let data_tx = Arc::new(data_tx);
                                let data_tx_r = Arc::clone(&data_tx);

                                let channels = Arc::clone(&channels_);
                                let transports = Arc::clone(&transports);

                                msrp_transport_start(
                                    t,
                                    t_id,
                                    data_tx.as_ref().clone(),
                                    data_rx,
                                    move |message| route(&channels, message),
                                    move || {
                                        let mut guard = transports.lock().unwrap();
                                        if let Some(idx) = guard
                                            .iter()
                                            .position(|(_, _, tx)| Arc::ptr_eq(&tx, &data_tx_r))
                                        {
                                            guard.swap_remove(idx);
                                        }
                                    },
                                    &rt_,
                                );

                                guard.push((
                                    chunk_info.from_path.to_vec(),
                                    chunk_info.to_path.to_vec(),
                                    Arc::clone(&data_tx),
                                ));

                                data_tx
                            }
                        }
                    };

                    let data_size = message.estimated_size();
                    let mut data = Vec::with_capacity(data_size);
                    {
                        let mut readers = Vec::new();
                        message.get_readers(&mut readers);
                        match DynamicChain::new(readers).read_to_end(&mut data) {
                            Ok(_) => {}
                            Err(_) => {} // to-do: early failure
                        }
                    }

                    // in order, and waiting while the connection is busy
                    match tx.send(Some(data)).await {
                        Ok(()) => {}
                        Err(_) => {}
                    }
                }
            }
        });

        MsrpChannelManager {
            // tx,
            // transports,
            channels,
        }
    }

    pub fn register_channel(&self, channel: MsrpChannel) {
        let mut guard = self.channels.lock().unwrap();
        (*guard).push(channel);
    }

    // pub fn register_transport(&self, from_path: Vec<u8>, to_path: Vec<u8>, t: Arc<MsrpTransport>) {
    //     let mut guard = self.transports.lock().unwrap();
    //     guard.push((from_path, to_path, t));
    // }

    // pub fn get_tx(&self) -> mpsc::Sender<(MsrpChunk, Option<Arc<MsrpTransport>>)> {
    //     self.tx.clone()
    // }
}

// RFC 4975 section 7.3: what arrives on a connection belongs to the session
// whose URI is the first in its To-Path, and a request for no session is
// answered 481
pub(super) fn route(
    channels: &Mutex<Vec<MsrpChannel>>,
    message: MsrpChunk,
) -> Result<Vec<MsrpChunk>, &'static str> {
    let local_path = match message.get_chunk_info() {
        Some(chunk_info) => first_uri(chunk_info.to_path).to_vec(),
        None => return Err("Bad Format"),
    };

    {
        let mut guard = channels.lock().unwrap();
        if let Some(channel) = guard
            .iter_mut()
            .find(|channel| uri_eq(first_uri(&channel.from_path), &local_path))
        {
            return channel.on_message(message);
        }
    }

    if let MsrpChunk::Request(req_line, _, _, _) = &message {
        if req_line.request_method != b"REPORT" {
            if let Some(chunk_info) = message.get_chunk_info() {
                if let Some(ReportFailure::No) = chunk_info.failure_report {
                    return Ok(Vec::new());
                }

                return Ok(vec![MsrpChunk::new_response_chunk(
                    MsrpResponseLine {
                        transaction_id: req_line.transaction_id.clone(),
                        status_code: 481,
                        comment: Some(b"Session does not exist".to_vec()),
                    },
                    response_headers(&chunk_info),
                )]);
            }
        }
    }

    Ok(Vec::new())
}

// RFC 4975 section 7.2: a response goes to the previous hop, the first URI of
// the request's From-Path, from the first URI of its To-Path
fn response_headers(chunk_info: &MsrpChunkInfo) -> Vec<Header> {
    vec![
        Header::new(b"To-Path", first_uri(chunk_info.from_path).to_vec()),
        Header::new(b"From-Path", first_uri(chunk_info.to_path).to_vec()),
    ]
}

// a path is a list of URIs separated by spaces
fn first_uri(path: &[u8]) -> &[u8] {
    path.split(|c| *c == b' ')
        .find(|uri| !uri.is_empty())
        .unwrap_or(path)
}

// RFC 4975 section 6.1: schemes, authorities and transports compare without
// case and session-ids with it, URI parameters are not compared
fn uri_eq(a: &[u8], b: &[u8]) -> bool {
    match (uri_parts(a), uri_parts(b)) {
        (Some(a), Some(b)) => {
            a.0.eq_ignore_ascii_case(b.0)
                && a.1.eq_ignore_ascii_case(b.1)
                && a.2 == b.2
                && a.3.eq_ignore_ascii_case(b.3)
        }
        _ => a == b,
    }
}

// msrp[s]://authority[/session-id];transport[;parameters]
fn uri_parts(uri: &[u8]) -> Option<(&[u8], &[u8], &[u8], &[u8])> {
    let idx = uri.windows(3).position(|w| w == b"://")?;
    let scheme = &uri[..idx];
    let rest = &uri[idx + 3..];

    let idx = rest.iter().position(|c| *c == b';')?;
    let (address, parameters) = (&rest[..idx], &rest[idx + 1..]);
    let transport = parameters.split(|c| *c == b';').next()?;

    let (authority, session_id) = match address.iter().position(|c| *c == b'/') {
        Some(idx) => (&address[..idx], &address[idx + 1..]),
        None => (address, &address[address.len()..]),
    };

    Some((scheme, authority, session_id, transport))
}
