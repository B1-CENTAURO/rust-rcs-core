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
use tokio::runtime::{Handle, Runtime};
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
use super::msrp_transport::msrp_transport_start_on;
// use super::msrp_transport::MsrpTransportFactory;
// use super::msrp_transport::{MsrpTransport, MsrpTransportWrapper};

pub struct MsrpChannel {
    from_path: Vec<u8>, // local_path
    to_path: Vec<u8>,   // remote_path
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

                            // the error is known as the chunk is answered, so it goes
                            // in the response; RFC 4975 section 7.1.4 leaves failure
                            // REPORTs to errors found later, as at a gateway
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

type Connection = Arc<mpsc::Sender<Option<Vec<u8>>>>;

enum Link {
    Connected(Connection),
    Waiting(Vec<Vec<u8>>), // until the remote end connects, what to send then
}

// the connection that carries what a session sends, by its local and remote
// paths; for a passive session the remote end opens it
struct Transport {
    from_path: Vec<u8>,
    to_path: Vec<u8>,
    passive: bool,
    link: Link,
}

type Transports = Arc<Mutex<Vec<Transport>>>;

// what happens to connections and sessions, handled in order by the manager
enum Event {
    Bound(Vec<u8>, Vec<u8>, Connection), // a request for a session arrived on it
    Released(Connection),                // it closed
    Ended(Vec<u8>, Vec<u8>),             // a session was unregistered
}

pub struct MsrpChannelManager {
    // tx: mpsc::Sender<MsrpChunk>,
    transports: Transports,
    channels: Arc<Mutex<Vec<MsrpChannel>>>,
    event_tx: mpsc::UnboundedSender<Event>,
    rt: Arc<Runtime>,
}

impl MsrpChannelManager {
    /// Sends the chunks it receives on `rx`, over one connection per pair of
    /// From-Path and To-Path. The first chunk of a session opens it with
    /// `socket_factory`, unless the session was registered as passive.
    /// What arrives on a connection goes to the registered channels.
    /// `MsrpInfo::connection_address` of the remote SDP says where to connect,
    /// CEMA included.
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
        let transports_ = Arc::clone(&transports);

        let channels: Arc<Mutex<Vec<MsrpChannel>>> = Arc::new(Mutex::new(Vec::new()));
        let channels_ = Arc::clone(&channels);

        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        // weak, so that the loop ends once the manager and its connections are gone
        let event_tx_ = event_tx.downgrade();

        // a handle, not the runtime, see msrp_transport_start_on()
        let rt_ = rt.handle().clone();
        rt.spawn(async move {
            let transports = transports_;

            // chunks and events are handled here one at a time, so a session's
            // chunks keep their order and a connection is bound before it is
            // released; held chunks still go out once rx has closed
            let mut sending = true;
            loop {
                tokio::select! {
                    message = rx.recv(), if sending => match message {
                        Some(message) => {
                            if let Some(chunk_info) = message.get_chunk_info() {
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

                                let tx = {
                                    let mut guard = transports.lock().unwrap();
                                    match guard.iter_mut().find(|t| {
                                        t.from_path == chunk_info.from_path
                                            && t.to_path == chunk_info.to_path
                                    }) {
                                        Some(Transport {
                                            link: Link::Connected(tx),
                                            ..
                                        }) => Arc::clone(tx),

                                        Some(Transport {
                                            link: Link::Waiting(pending),
                                            ..
                                        }) => {
                                            pending.push(data);
                                            continue;
                                        }

                                        None => {
                                            let t = socket_factory(
                                                chunk_info.from_path,
                                                chunk_info.to_path,
                                            );
                                            let t_id = format!(
                                                "{}-{}",
                                                String::from_utf8_lossy(chunk_info.from_path),
                                                String::from_utf8_lossy(chunk_info.to_path),
                                            );

                                            // without the manager, nothing needs its events
                                            let event_tx = event_tx_
                                                .upgrade()
                                                .unwrap_or_else(|| mpsc::unbounded_channel().0);

                                            let tx = start_transport(
                                                t,
                                                t_id,
                                                &channels_,
                                                &event_tx,
                                                false,
                                                &rt_,
                                            );

                                            guard.push(Transport {
                                                from_path: chunk_info.from_path.to_vec(),
                                                to_path: chunk_info.to_path.to_vec(),
                                                passive: false,
                                                link: Link::Connected(Arc::clone(&tx)),
                                            });

                                            tx
                                        }
                                    }
                                };

                                // in order, and waiting while the connection is busy
                                match tx.send(Some(data)).await {
                                    Ok(()) => {}
                                    Err(_) => {}
                                }
                            }
                        }

                        None => sending = false,
                    },

                    Some(event) = event_rx.recv() => match event {
                        Event::Bound(from_path, to_path, tx) => {
                            bind(&transports, from_path, to_path, tx).await;
                        }

                        Event::Released(tx) => release(&transports, &tx),

                        Event::Ended(from_path, to_path) => {
                            end(&transports, from_path, to_path).await;
                        }
                    },

                    else => break,
                }
            }
        });

        MsrpChannelManager {
            // tx,
            transports,
            channels,
            event_tx,
            rt,
        }
    }

    pub fn register_channel(&self, channel: MsrpChannel) {
        let mut guard = self.channels.lock().unwrap();
        (*guard).push(channel);
    }

    /// Registers a channel for a session that the remote end connects, as for
    /// an a=setup:passive of ours. What the session sends waits until one of
    /// its requests arrives on a connection given to accept(), and again after
    /// that connection closes.
    pub fn register_passive_channel(&self, channel: MsrpChannel) {
        {
            let mut guard = self.transports.lock().unwrap();
            if !guard
                .iter()
                .any(|t| t.from_path == channel.from_path && t.to_path == channel.to_path)
            {
                guard.push(Transport {
                    from_path: channel.from_path.clone(),
                    to_path: channel.to_path.clone(),
                    passive: true,
                    link: Link::Waiting(Vec::new()),
                });
            }
        }

        self.register_channel(channel);
    }

    /// Removes the channel of a session that ended, by its local and remote
    /// paths, returning whether there was one. Requests for it are answered
    /// 481 from now on. What it sent before still goes out, what it holds for
    /// a remote end that has not connected is dropped, and its connection
    /// closes unless another session uses it. The session sends nothing more.
    pub fn unregister_channel(&self, from_path: &[u8], to_path: &[u8]) -> bool {
        let removed = {
            let mut guard = self.channels.lock().unwrap();
            let len = guard.len();
            guard.retain(|channel| !(channel.from_path == from_path && channel.to_path == to_path));
            guard.len() < len
        };

        match self
            .event_tx
            .send(Event::Ended(from_path.to_vec(), to_path.to_vec()))
        {
            Ok(()) => {}
            Err(_) => {}
        }

        removed
    }

    /// Takes a connection the remote end opened. What arrives on it goes to
    /// the registered channels, and a session it carries a request for sends
    /// over it from then on (RFC 4975 section 5.4).
    pub fn accept<T>(&self, t: T)
    where
        T: AsyncRead + AsyncWrite + Send + 'static,
    {
        start_transport(
            t,
            String::from("accepted"),
            &self.channels,
            &self.event_tx,
            true,
            self.rt.handle(),
        );
    }

    #[cfg(test)]
    pub(super) fn is_waiting(&self, from_path: &[u8], to_path: &[u8]) -> bool {
        let guard = self.transports.lock().unwrap();
        guard.iter().any(|t| {
            t.from_path == from_path && t.to_path == to_path && matches!(t.link, Link::Waiting(_))
        })
    }

    // pub fn register_transport(&self, from_path: Vec<u8>, to_path: Vec<u8>, t: Arc<MsrpTransport>) {
    //     let mut guard = self.transports.lock().unwrap();
    //     guard.push((from_path, to_path, t));
    // }

    // pub fn get_tx(&self) -> mpsc::Sender<(MsrpChunk, Option<Arc<MsrpTransport>>)> {
    //     self.tx.clone()
    // }
}

// starts a transport on t, returning what writes to it; when it was accepted,
// its requests bind it to their sessions
fn start_transport<T>(
    t: T,
    t_id: String,
    channels: &Arc<Mutex<Vec<MsrpChannel>>>,
    event_tx: &mpsc::UnboundedSender<Event>,
    accepted: bool,
    rt: &Handle,
) -> Connection
where
    T: AsyncRead + AsyncWrite + Send + 'static,
{
    let (data_tx, data_rx) = mpsc::channel(8);
    let data_tx = Arc::new(data_tx);
    let connection = Arc::clone(&data_tx);
    let connection_r = Arc::clone(&data_tx);

    let channels = Arc::clone(channels);
    let event_tx = event_tx.clone();
    let event_tx_r = event_tx.clone();

    msrp_transport_start_on(
        t,
        t_id,
        data_tx.as_ref().clone(),
        data_rx,
        move |message| {
            if accepted {
                if let Some((from_path, to_path)) = session_of(&channels, &message) {
                    match event_tx.send(Event::Bound(from_path, to_path, Arc::clone(&connection))) {
                        Ok(()) => {}
                        Err(_) => {}
                    }
                }
            }
            route(&channels, message)
        },
        move || match event_tx_r.send(Event::Released(connection_r)) {
            Ok(()) => {}
            Err(_) => {}
        },
        rt,
    );

    data_tx
}

// RFC 4975 section 5.4: a session sends over the connection its request
// arrived on, unless it has one already; what a passive session held back
// goes first
async fn bind(transports: &Transports, from_path: Vec<u8>, to_path: Vec<u8>, tx: Connection) {
    let pending = {
        let mut guard = transports.lock().unwrap();
        match guard
            .iter_mut()
            .find(|t| t.from_path == from_path && t.to_path == to_path)
        {
            Some(Transport {
                link: Link::Connected(_),
                ..
            }) => return,

            Some(Transport {
                link: Link::Waiting(pending),
                ..
            }) => std::mem::take(pending),

            None => {
                guard.push(Transport {
                    from_path: from_path.clone(),
                    to_path: to_path.clone(),
                    passive: false,
                    link: Link::Waiting(Vec::new()),
                });
                Vec::new()
            }
        }
    };

    for data in pending {
        match tx.send(Some(data)).await {
            Ok(()) => {}
            Err(_) => {}
        }
    }

    let mut guard = transports.lock().unwrap();
    if let Some(t) = guard
        .iter_mut()
        .find(|t| t.from_path == from_path && t.to_path == to_path)
    {
        t.link = Link::Connected(tx);
    }
}

// an ended session sends nothing more, and its connection closes when no
// other session sends over it
async fn end(transports: &Transports, from_path: Vec<u8>, to_path: Vec<u8>) {
    let tx = {
        let mut guard = transports.lock().unwrap();
        let idx = match guard
            .iter()
            .position(|t| t.from_path == from_path && t.to_path == to_path)
        {
            Some(idx) => idx,
            None => return,
        };

        match guard.remove(idx).link {
            Link::Connected(tx)
                if !guard.iter().any(
                    |t| matches!(&t.link, Link::Connected(other) if Arc::ptr_eq(other, &tx)),
                ) =>
            {
                tx
            }
            _ => return,
        }
    };

    // the transport shuts its side down, after what is queued
    match tx.send(None).await {
        Ok(()) => {}
        Err(_) => {}
    }
}

// a closed connection carries nothing more: a passive session waits for the
// remote end again, any other opens a new one when it next sends
fn release(transports: &Transports, connection: &Connection) {
    let mut guard = transports.lock().unwrap();
    guard.retain_mut(|t| match &t.link {
        Link::Connected(tx) if Arc::ptr_eq(tx, connection) => {
            if t.passive {
                t.link = Link::Waiting(Vec::new());
            }
            t.passive
        }
        _ => true,
    });
}

// the local and remote paths of the channel a request is for, when its
// From-Path ends with the channel's remote endpoint
fn session_of(
    channels: &Mutex<Vec<MsrpChannel>>,
    message: &MsrpChunk,
) -> Option<(Vec<u8>, Vec<u8>)> {
    if let MsrpChunk::Request(_, _, _, _) = message {
        let chunk_info = message.get_chunk_info()?;
        let guard = channels.lock().unwrap();
        let channel = guard.iter().find(|channel| {
            uri_eq(first_uri(&channel.from_path), first_uri(chunk_info.to_path))
                && uri_eq(last_uri(&channel.to_path), last_uri(chunk_info.from_path))
        })?;
        return Some((channel.from_path.clone(), channel.to_path.clone()));
    }

    None
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

fn last_uri(path: &[u8]) -> &[u8] {
    path.split(|c| *c == b' ')
        .filter(|uri| !uri.is_empty())
        .last()
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
