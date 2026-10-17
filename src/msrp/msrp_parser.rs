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

use crate::internet::header::Header;
use crate::internet::syntax;

use crate::util::raw_string::{StrFind, ToInt};

use super::msrp_chunk::ContinuationFlag;
use super::msrp_chunk::MsrpChunk;
use super::msrp_chunk::MsrpRequestLine;
use super::msrp_chunk::MsrpResponseLine;

enum MsrpFirstLine {
    Request(MsrpRequestLine),
    Response(MsrpResponseLine),
}

impl MsrpFirstLine {
    fn transaction_id(&self) -> &[u8] {
        match self {
            MsrpFirstLine::Request(req_line) => &req_line.transaction_id,
            MsrpFirstLine::Response(resp_line) => &resp_line.transaction_id,
        }
    }
}

enum ParsingState {
    ReadingFirstLine,
    ReadingHeaders(MsrpFirstLine, Vec<Header>),
    // the body starts at the parser position, the end-line is searched for
    // from the offset so that bytes are not searched twice
    ReadingBody(MsrpRequestLine, Vec<Header>, usize),
}

/// Parses MSRP requests and responses (RFC 4975 section 9) out of a byte
/// stream.
///
/// A body ends at the first CRLF end-line with the request's transaction id,
/// since a sender may interrupt a chunk before the end of its Byte-Range;
/// checking Byte-Range is left to whoever reassembles the message.
pub struct MsrpParser {
    buffer: Vec<u8>,
    p: usize,
    state: ParsingState,
}

impl MsrpParser {
    pub fn new() -> MsrpParser {
        MsrpParser {
            buffer: Vec::new(),
            p: 0,
            state: ParsingState::ReadingFirstLine,
        }
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Returns the next complete message, or None until more data is fed.
    /// One feed can carry several messages, so call it until it returns None.
    pub fn produce(&mut self) -> Result<Option<MsrpChunk>, &'static str> {
        loop {
            match std::mem::replace(&mut self.state, ParsingState::ReadingFirstLine) {
                ParsingState::ReadingFirstLine => match self.next_line() {
                    Some(line) => {
                        let first_line = parse_first_line(&self.buffer[line])?;
                        self.state = ParsingState::ReadingHeaders(first_line, Vec::new());
                    }

                    None => return Ok(None),
                },

                ParsingState::ReadingHeaders(first_line, mut headers) => {
                    let line = match self.next_line() {
                        Some(line) => line,
                        None => {
                            self.state = ParsingState::ReadingHeaders(first_line, headers);
                            return Ok(None);
                        }
                    };

                    if let Some(continuation_flag) =
                        end_line(&self.buffer[line.clone()], first_line.transaction_id())
                    {
                        self.consume();
                        return Ok(Some(match first_line {
                            MsrpFirstLine::Request(req_line) => MsrpChunk::new_request_chunk(
                                req_line,
                                headers,
                                None,
                                continuation_flag,
                            ),
                            MsrpFirstLine::Response(resp_line) => {
                                MsrpChunk::new_response_chunk(resp_line, headers)
                            }
                        }));
                    }

                    let line = &self.buffer[line];

                    if line.is_empty() {
                        match first_line {
                            MsrpFirstLine::Request(req_line) => {
                                self.state = ParsingState::ReadingBody(req_line, headers, self.p);
                            }

                            MsrpFirstLine::Response(_) => {
                                return Err("MSRP Responses are not allowed to have body");
                            }
                        }
                    } else if let Some(idx) = line.iter().position(|c| *c == b':') {
                        headers.push(Header::new(
                            syntax::trim(&line[..idx]).to_vec(),
                            syntax::trim(&line[idx + 1..]).to_vec(),
                        ));
                        self.state = ParsingState::ReadingHeaders(first_line, headers);
                    } else {
                        return Err("Bad format");
                    }
                }

                ParsingState::ReadingBody(req_line, headers, from) => {
                    // data CRLF end-line
                    let mut boundary = b"\r\n-------".to_vec();
                    boundary.extend_from_slice(&req_line.transaction_id);

                    match self.buffer[from..].index_of(&boundary) {
                        Some(idx) => {
                            let end = from + idx;
                            let flag = end + boundary.len();

                            if self.buffer.len() < flag + 3 {
                                self.state = ParsingState::ReadingBody(req_line, headers, end);
                                return Ok(None);
                            }

                            match continuation_flag(self.buffer[flag]) {
                                Some(continuation_flag)
                                    if &self.buffer[flag + 1..flag + 3] == b"\r\n" =>
                                {
                                    let body = self.buffer[self.p..end].to_vec();
                                    self.p = flag + 3;
                                    self.consume();
                                    return Ok(Some(MsrpChunk::new_request_chunk(
                                        req_line,
                                        headers,
                                        Some(body),
                                        continuation_flag,
                                    )));
                                }

                                _ => {
                                    // content that only looks like an end-line
                                    self.state =
                                        ParsingState::ReadingBody(req_line, headers, end + 1);
                                }
                            }
                        }

                        None => {
                            // the boundary may be split across feeds
                            let from = std::cmp::max(
                                from,
                                (self.buffer.len() + 1).saturating_sub(boundary.len()),
                            );
                            self.state = ParsingState::ReadingBody(req_line, headers, from);
                            return Ok(None);
                        }
                    }
                }
            }
        }
    }

    // the next CRLF terminated line, without the CRLF, moving past it
    fn next_line(&mut self) -> Option<Range<usize>> {
        let idx = self.buffer[self.p..].index_of(b"\r\n")?;
        let line = self.p..self.p + idx;
        self.p = self.p + idx + 2;
        Some(line)
    }

    // drops the message that was just produced
    fn consume(&mut self) {
        self.buffer.drain(..self.p);
        self.p = 0;
    }
}

// req-start  = "MSRP" SP transact-id SP method CRLF
// resp-start = "MSRP" SP transact-id SP status-code [SP comment] CRLF
fn parse_first_line(line: &[u8]) -> Result<MsrpFirstLine, &'static str> {
    let mut iter = line.splitn(3, |c| *c == b' ');
    let (pmsrp, transaction_id, rest) = match (iter.next(), iter.next(), iter.next()) {
        (Some(pmsrp), Some(transaction_id), Some(rest)) => (pmsrp, transaction_id, rest),
        _ => return Err("Bad format"),
    };

    if pmsrp != b"MSRP" || !is_ident(transaction_id) {
        return Err("Bad format");
    }

    if rest.len() >= 3
        && rest[..3].iter().all(u8::is_ascii_digit)
        && (rest.len() == 3 || rest[3] == b' ')
    {
        let status_code: u16 = rest[..3].to_int().map_err(|_| "Bad format")?;
        return Ok(MsrpFirstLine::Response(MsrpResponseLine {
            transaction_id: transaction_id.to_vec(),
            status_code,
            comment: if rest.len() > 4 {
                Some(rest[4..].to_vec())
            } else {
                None
            },
        }));
    }

    if !rest.is_empty() && rest.iter().all(u8::is_ascii_uppercase) {
        return Ok(MsrpFirstLine::Request(MsrpRequestLine {
            transaction_id: transaction_id.to_vec(),
            request_method: rest.to_vec(),
        }));
    }

    Err("Bad format")
}

// ident-char = ALPHANUM / "." / "-" / "+" / "%" / "="
fn is_ident(s: &[u8]) -> bool {
    !s.is_empty()
        && s.iter()
            .all(|c| c.is_ascii_alphanumeric() || b".-+%=".contains(c))
}

// end-line = "-------" transact-id continuation-flag CRLF, given without the CRLF
fn end_line(line: &[u8], transaction_id: &[u8]) -> Option<ContinuationFlag> {
    if line.len() == 7 + transaction_id.len() + 1
        && line.start_with(b"-------")
        && &line[7..7 + transaction_id.len()] == transaction_id
    {
        return continuation_flag(line[line.len() - 1]);
    }

    None
}

fn continuation_flag(c: u8) -> Option<ContinuationFlag> {
    match c {
        b'$' => Some(ContinuationFlag::Complete),
        b'+' => Some(ContinuationFlag::Continuation),
        b'#' => Some(ContinuationFlag::Abort),
        _ => None,
    }
}
