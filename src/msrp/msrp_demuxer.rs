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

use std::ops::Range;
// use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::time::sleep;

use crate::internet::header::Header;
use crate::internet::headers::byte_range;

use crate::util::rand;
use crate::util::ranges::RangeOperations;
// use crate::util::timer::Timer;

use super::msrp_chunk::ContinuationFlag;
use super::msrp_chunk::MsrpChunk;
use super::msrp_chunk::MsrpRequestLine;

const MAX_MSRP_CHUNK_SIZE: usize = 10 * 1024;

// the 30 seconds a chunk's response may take, and as long again for the
// success REPORTs that follow
const REPORT_TIMEOUT: Duration = Duration::from_secs(60);

enum DeliveryStatus {
    AwaitPositiveReport(Vec<Range<usize>>, usize),
    AwaitNegativeReport,
    AwaitPositiveAndNegativeReport(Vec<Range<usize>>, usize),
    DontCare,
}

enum TransactionStatus {
    AwaitResponse,
    AwaitResponseAndTimeout,
    Sent,
    DontCare,
}

type Callback = Arc<Mutex<Option<Box<dyn FnOnce(u16, String) + Send + Sync>>>>;

// for each message being sent: its Message-ID, the reports it waits for, the
// transactions of its chunks, whether all of its chunks are queued, and the
// callback that is told how it ended
type Waitlist = Arc<
    Mutex<
        Vec<(
            Vec<u8>,
            DeliveryStatus,
            Vec<(Vec<u8>, TransactionStatus)>,
            bool,
            Callback,
        )>,
    >,
>;

pub struct MsrpDemuxer {
    pub from_path: Vec<u8>,
    pub to_path: Vec<u8>,
    waitlist: Waitlist,
}

impl MsrpDemuxer {
    pub fn new(from_path: Vec<u8>, to_path: Vec<u8>) -> MsrpDemuxer {
        MsrpDemuxer {
            from_path,
            to_path,
            waitlist: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Sends what `r` reads as one message, in chunks. `c` is called once: with
    /// 200 when every chunk got a 200 response, otherwise with the failure.
    pub fn start<R, C>(
        &self,
        from_path: Vec<u8>,
        to_path: Vec<u8>,
        content_type: Option<Vec<u8>>,
        total: usize,
        r: R,
        c: C,
        // tx: mpsc::Sender<MsrpChunk>,
        tx: mpsc::Sender<MsrpChunk>,
        // timer: Arc<Timer>,
        rt: &Arc<Runtime>,
    ) where
        // R: MsrpDataReader + Send + Sync + 'static,
        R: std::io::Read + Send + Sync + 'static,
        C: FnOnce(u16, String) + Send + Sync + 'static,
    {
        self.start_message(from_path, to_path, content_type, total, r, c, false, tx, rt);
    }

    /// As start(), asking the receiver for success REPORTs (RFC 4975 section
    /// 7.1.2). `c` then gets 200 once the REPORTs cover the whole message, or
    /// 408 when they have not 60 seconds after the last chunk was queued. An
    /// empty message has nothing to report on and ends with its 200 response.
    pub fn start_with_success_report<R, C>(
        &self,
        from_path: Vec<u8>,
        to_path: Vec<u8>,
        content_type: Option<Vec<u8>>,
        total: usize,
        r: R,
        c: C,
        tx: mpsc::Sender<MsrpChunk>,
        rt: &Arc<Runtime>,
    ) where
        R: std::io::Read + Send + Sync + 'static,
        C: FnOnce(u16, String) + Send + Sync + 'static,
    {
        self.start_message(from_path, to_path, content_type, total, r, c, true, tx, rt);
    }

    fn start_message<R, C>(
        &self,
        from_path: Vec<u8>,
        to_path: Vec<u8>,
        content_type: Option<Vec<u8>>,
        total: usize,
        mut r: R,
        c: C,
        success_report: bool,
        tx: mpsc::Sender<MsrpChunk>,
        rt: &Arc<Runtime>,
    ) where
        R: std::io::Read + Send + Sync + 'static,
        C: FnOnce(u16, String) + Send + Sync + 'static,
    {
        let c: Callback = Arc::new(Mutex::new(Some(Box::new(c))));

        let success_report = success_report && total > 0;

        let waitlist = Arc::clone(&self.waitlist);

        let rt_ = Arc::clone(rt);

        rt.spawn(async move {
            let message_id = rand::create_raw_alpha_numeric_string(16);

            {
                let mut guard = waitlist.lock().unwrap();
                guard.push((
                    message_id.clone(),
                    if success_report {
                        DeliveryStatus::AwaitPositiveAndNegativeReport(Vec::new(), total)
                    } else {
                        DeliveryStatus::AwaitNegativeReport
                    },
                    Vec::new(),
                    false,
                    c,
                ));
            }

            let mut sent: usize = 0;
            let mut buffer = [0; MAX_MSRP_CHUNK_SIZE];
            let mut filled_buffer: Option<Vec<u8>> = None;

            // a chunk is held back until the next read tells whether it is the last
            loop {
                match r.read(&mut buffer[..]) {
                    Ok(0) => break,

                    Ok(size) => {
                        if let Some(data) = filled_buffer.replace(buffer[..size].to_vec()) {
                            let transaction_id = rand::create_raw_alpha_numeric_string(16);
                            let chunk = build_msrp_chunk(
                                &transaction_id,
                                &from_path,
                                &to_path,
                                &message_id,
                                &content_type,
                                Some(data),
                                &mut sent,
                                total,
                                ContinuationFlag::Continuation,
                                success_report,
                            );

                            if !send_chunk(
                                &waitlist,
                                &message_id,
                                transaction_id,
                                chunk,
                                false,
                                &tx,
                                &rt_,
                            )
                            .await
                            {
                                return;
                            }
                        }
                    }

                    Err(_) => {
                        fail(&waitlist, &message_id, 500, "Internal Error");

                        // tells the receiver that the message ends here
                        let transaction_id = rand::create_raw_alpha_numeric_string(16);
                        let chunk = build_msrp_chunk(
                            &transaction_id,
                            &from_path,
                            &to_path,
                            &message_id,
                            &content_type,
                            filled_buffer,
                            &mut sent,
                            total,
                            ContinuationFlag::Abort,
                            success_report,
                        );

                        match tx.send(chunk).await {
                            Ok(()) => {}
                            Err(_) => {}
                        }

                        return;
                    }
                }
            }

            let transaction_id = rand::create_raw_alpha_numeric_string(16);
            let chunk = build_msrp_chunk(
                &transaction_id,
                &from_path,
                &to_path,
                &message_id,
                &content_type,
                filled_buffer,
                &mut sent,
                total,
                ContinuationFlag::Complete,
                success_report,
            );

            if send_chunk(
                &waitlist,
                &message_id,
                transaction_id,
                chunk,
                true,
                &tx,
                &rt_,
            )
            .await
                && success_report
            {
                start_report_timeout(&waitlist, message_id, &rt_);
            }
        });
    }

    /// Takes a REPORT for a message being sent: a success REPORT counts the
    /// bytes it covers until they are the whole message, a failure REPORT ends
    /// the message with its status.
    pub fn on_report(&self, message: MsrpChunk) -> Result<(), &'static str> {
        let report_status = match message.get_report_status() {
            Some(report_status) if report_status.ns == 0 => report_status,
            _ => return Err("Server Internal Error"),
        };

        let mut guard = self.waitlist.lock().unwrap();
        let i = match guard
            .iter()
            .position(|(message_id, _, _, _, _)| message_id == report_status.message_id)
        {
            Some(i) => i,
            None => return Err("Server Internal Error"),
        };

        let ended = match (&mut guard[i].1, report_status.status_code) {
            (
                DeliveryStatus::AwaitPositiveReport(ranges, total)
                | DeliveryStatus::AwaitPositiveAndNegativeReport(ranges, total),
                200,
            ) => {
                let byte_range = match report_status.byte_range.and_then(byte_range::parse) {
                    Some(byte_range) if byte_range.from > 0 => byte_range,
                    _ => return Err("Server Internal Error"),
                };

                let mut range = Range {
                    start: byte_range.from - 1,
                    end: byte_range.to.unwrap_or(*total),
                };

                // merged with the ranges reported before
                let mut j = 0;
                while j < ranges.len() {
                    if let Some(union) = range.union(&ranges[j]) {
                        range = union;
                        ranges.remove(j);
                        j = 0;
                    } else {
                        j = j + 1;
                    }
                }

                let complete = range.covering(&Range {
                    start: 0,
                    end: *total,
                });
                ranges.push(range);
                complete
            }

            (
                DeliveryStatus::AwaitNegativeReport
                | DeliveryStatus::AwaitPositiveAndNegativeReport(_, _),
                status_code,
            ) => status_code != 200,

            _ => false,
        };

        if !ended {
            return Ok(());
        }

        let (_, _, _, _, c) = guard.remove(i);
        drop(guard);

        if report_status.status_code == 200 {
            report(&c, 200, String::from("Ok"));
        } else {
            let reason_phrase = if let Some(comment) = report_status.comment {
                String::from_utf8_lossy(comment).to_string()
            } else {
                String::from("")
            };
            report(&c, report_status.status_code, reason_phrase);
        }

        Ok(())
    }

    pub fn on_response(&self, message: MsrpChunk) -> Result<(), (u16, &'static str)> {
        if let MsrpChunk::Response(resp_line, _) = message {
            let mut guard = self.waitlist.lock().unwrap();
            for i in 0..guard.len() {
                let (_, delivery_status, transaction_status_arr, all_sent, _) = &mut guard[i];
                if let Some((_, status)) = transaction_status_arr
                    .iter_mut()
                    .find(|(t, _)| *t == resp_line.transaction_id)
                {
                    match status {
                        TransactionStatus::AwaitResponse
                        | TransactionStatus::AwaitResponseAndTimeout => {}
                        _ => return Ok(()),
                    }

                    if resp_line.status_code == 200 {
                        *status = TransactionStatus::Sent;

                        if !*all_sent
                            || transaction_status_arr
                                .iter()
                                .any(|(_, status)| !matches!(status, TransactionStatus::Sent))
                        {
                            return Ok(());
                        }

                        // it is delivered once success REPORTs cover it
                        if let DeliveryStatus::AwaitPositiveReport(_, _)
                        | DeliveryStatus::AwaitPositiveAndNegativeReport(_, _) = delivery_status
                        {
                            return Ok(());
                        }
                    }

                    let (_, _, _, _, c) = guard.remove(i);
                    drop(guard);

                    if resp_line.status_code == 200 {
                        report(&c, 200, String::from("Ok"));
                    } else {
                        let reason_phrase = if let Some(comment) = &resp_line.comment {
                            String::from_utf8_lossy(comment).to_string()
                        } else {
                            String::from("")
                        };
                        report(&c, resp_line.status_code, reason_phrase);
                    }

                    return Ok(());
                }
            }
        }

        Err((500, "Server Internal Error"))
    }
}

// tracks the transaction of a chunk and queues the chunk, false when the
// message has already failed and the rest of it should not be sent
async fn send_chunk(
    waitlist: &Waitlist,
    message_id: &[u8],
    transaction_id: Vec<u8>,
    chunk: MsrpChunk,
    last: bool,
    tx: &mpsc::Sender<MsrpChunk>,
    rt: &Arc<Runtime>,
) -> bool {
    {
        let mut guard = waitlist.lock().unwrap();
        match guard.iter_mut().find(|(id, _, _, _, _)| id == message_id) {
            Some((_, _, transaction_status_arr, all_sent, _)) => {
                transaction_status_arr.push((
                    transaction_id.clone(),
                    TransactionStatus::AwaitResponseAndTimeout,
                ));
                *all_sent = last;
            }
            None => return false,
        }
    }

    match tx.send(chunk).await {
        Ok(()) => {
            start_timeout(waitlist, transaction_id, rt);
            true
        }

        Err(_) => {
            fail(waitlist, message_id, 408, "Timeout");
            false
        }
    }
}

// drops the message from the waitlist and reports how it ended
fn fail(waitlist: &Waitlist, message_id: &[u8], status_code: u16, reason_phrase: &str) {
    let c = {
        let mut guard = waitlist.lock().unwrap();
        match guard.iter().position(|(id, _, _, _, _)| id == message_id) {
            Some(i) => guard.remove(i).4,
            None => return,
        }
    };

    report(&c, status_code, String::from(reason_phrase));
}

fn report(c: &Callback, status_code: u16, reason_phrase: String) {
    let callback = c.lock().unwrap().take();
    if let Some(callback) = callback {
        callback(status_code, reason_phrase);
    }
}

fn build_msrp_chunk(
    transaction_id: &[u8],
    from_path: &[u8],
    to_path: &[u8],
    message_id: &[u8],
    content_type: &Option<Vec<u8>>,
    data: Option<Vec<u8>>,
    sent: &mut usize,
    total: usize,
    continuation_flag: ContinuationFlag,
    success_report: bool,
) -> MsrpChunk {
    let mut message = MsrpChunk::new_request_chunk(
        MsrpRequestLine {
            transaction_id: transaction_id.to_vec(),
            request_method: b"SEND".to_vec(),
        },
        Vec::new(),
        data,
        continuation_flag,
    );

    message.add_header(Header::new(b"To-Path", to_path.to_vec()));

    message.add_header(Header::new(b"From-Path", from_path.to_vec()));

    message.add_header(Header::new(b"Message-ID", message_id.to_vec()));

    if let Some(body) = message.get_body() {
        if let Some(content_type) = content_type {
            let length = body.len();

            message.add_header(Header::new(
                b"Byte-Range",
                format!("{}-{}/{}", *sent + 1, *sent + length, total),
            ));

            message.add_header(Header::new(b"Content-Type", content_type.to_vec()));

            *sent = *sent + length;
        } else {
            panic!("")
        }
    }

    if success_report {
        message.add_header(Header::new(b"Success-Report", b"yes"));
    }

    message.add_header(Header::new(b"Failure-Report", b"yes"));

    message
}

// a message waiting for success REPORTs fails when they have not come in time
fn start_report_timeout(waitlist: &Waitlist, message_id: Vec<u8>, rt: &Arc<Runtime>) {
    let waitlist = Arc::clone(waitlist);
    rt.spawn(async move {
        sleep(REPORT_TIMEOUT).await;
        fail(&waitlist, &message_id, 408, "Timeout");
    });
}

fn start_timeout(waitlist: &Waitlist, transaction_id: Vec<u8>, rt: &Arc<Runtime>) {
    let waitlist = Arc::clone(&waitlist);
    rt.spawn(async move {
        sleep(Duration::from_secs(30)).await;
        let c = {
            let mut guard = waitlist.lock().unwrap();
            let position = guard
                .iter()
                .position(|(_, _, transaction_status_arr, _, _)| {
                    transaction_status_arr.iter().any(|(t, status)| {
                        *t == transaction_id
                            && matches!(status, TransactionStatus::AwaitResponseAndTimeout)
                    })
                });
            match position {
                Some(i) => guard.remove(i).4,
                None => return,
            }
        };

        report(&c, 408, String::from("Timeout"));
    });
}
