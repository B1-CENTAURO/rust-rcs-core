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

use std::collections::hash_map::Entry;
use std::collections::HashMap;

use crate::internet::headers::byte_range;

use super::msrp_chunk::ContinuationFlag;
use super::msrp_chunk::MsrpChunk;

pub trait MsrpDataWriter {
    fn write(&mut self, data: &[u8]) -> Result<usize, (u16, &'static str)>;
    fn complete(&mut self) -> Result<(), (u16, &'static str)>; // to-do: use FnOnce to improve code readability

    /// The message will not complete: the sender aborted it with a chunk
    /// ending in #, or writing it failed.
    fn abort(&mut self) {}
}

pub trait MsrpMessageReceiver {
    fn on_message(
        &mut self,
        message_id: &[u8],
        content_type: &[u8],
    ) -> Result<Box<dyn MsrpDataWriter + Send + Sync>, (u16, &'static str)>;
}

struct DanglingChunk {
    from: usize,
    data: Vec<u8>,
}

struct IncomingMessage {
    writer: Box<dyn MsrpDataWriter + Send + Sync>,
    dangling_chunks: Vec<DanglingChunk>, // arrived ahead of the written bytes, by from
    written: usize,                      // bytes 1 to written are written
    total: Option<usize>,
    end: Option<usize>, // the last byte of the chunk that ended in $
}

impl IncomingMessage {
    fn receive(&mut self, from: usize, data: &[u8]) -> Result<(), (u16, &'static str)> {
        if from > self.written + 1 {
            let position = self
                .dangling_chunks
                .iter()
                .position(|dangling| dangling.from > from)
                .unwrap_or(self.dangling_chunks.len());
            self.dangling_chunks.insert(
                position,
                DanglingChunk {
                    from,
                    data: data.to_vec(),
                },
            );
            return Ok(());
        }

        self.write(from, data)?;

        while let Some(dangling) = self.dangling_chunks.first() {
            if dangling.from > self.written + 1 {
                break;
            }
            let dangling = self.dangling_chunks.remove(0);
            self.write(dangling.from, &dangling.data)?;
        }

        Ok(())
    }

    // from is at most written + 1, bytes already written, e.g. by a chunk that
    // was sent again, are skipped
    fn write(&mut self, from: usize, data: &[u8]) -> Result<(), (u16, &'static str)> {
        let skip = self.written + 1 - from;
        if skip < data.len() {
            let size = self.writer.write(&data[skip..])?;
            if size != data.len() - skip {
                return Err((413, "Could not write the message"));
            }
            self.written = self.written + size;
        }
        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.total.map_or(false, |total| self.written >= total)
            || self.end.map_or(false, |end| self.written >= end)
    }
}

pub struct MsrpMuxer {
    message_receiver: Box<dyn MsrpMessageReceiver + Send + Sync>,
    messages: HashMap<Vec<u8>, IncomingMessage>,
}

impl MsrpMuxer {
    pub fn new<R>(message_receiver: R) -> MsrpMuxer
    where
        R: MsrpMessageReceiver + Send + Sync + 'static,
    {
        MsrpMuxer {
            message_receiver: Box::new(message_receiver),
            messages: HashMap::new(),
        }
    }

    /// Takes a chunk of a SEND request, returning the size of the message when
    /// the chunk completes it. A SEND without a body carries no message; RFC
    /// 4975 section 5.4 has one open a connection.
    pub fn feed(&mut self, chunk: MsrpChunk) -> Result<Option<usize>, (u16, &'static str)> {
        let (body, continuation_flag) = match &chunk {
            MsrpChunk::Request(_, _, body, continuation_flag) => (body, continuation_flag),
            MsrpChunk::Response(_, _) => return Err((400, "Invalid chunk info")),
        };

        let chunk_info = match chunk.get_chunk_info() {
            Some(chunk_info) => chunk_info,
            None => return Err((400, "Invalid chunk info")),
        };

        let message_id = match chunk_info.message_id {
            Some(message_id) => message_id,
            None if body.is_none() => return Ok(None),
            None => return Err((400, "Missing Message-ID header")),
        };

        if let ContinuationFlag::Abort = continuation_flag {
            if let Some(mut message) = self.messages.remove(message_id) {
                message.writer.abort();
            }
            return Ok(None);
        }

        let data = match body {
            Some(data) => data,
            None => return Ok(None),
        };

        // without Byte-Range the chunk starts at the first byte
        let (from, total) = match chunk_info.byte_range {
            Some(byte_range) => match byte_range::parse(byte_range) {
                Some(byte_range) if byte_range.from > 0 => (byte_range.from, byte_range.total),
                _ => return Err((400, "Invalid Byte-Range header")),
            },
            None => (1, None),
        };

        let message = match self.messages.entry(message_id.to_vec()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => match chunk_info.content_type {
                Some(content_type) => {
                    let writer = self.message_receiver.on_message(message_id, content_type)?;
                    entry.insert(IncomingMessage {
                        writer,
                        dangling_chunks: Vec::new(),
                        written: 0,
                        total,
                        end: None,
                    })
                }
                None => return Err((400, "Missing Content-Type header")),
            },
        };

        if total.is_some() {
            message.total = total;
        }

        if let ContinuationFlag::Complete = continuation_flag {
            message.end = Some(from + data.len() - 1);
        }

        let result = message.receive(from, data).map(|()| message.is_complete());

        match result {
            Ok(true) => match self.messages.remove(message_id) {
                Some(mut message) => {
                    message.writer.complete()?;
                    Ok(Some(message.written))
                }
                None => Ok(None),
            },

            Ok(false) => Ok(None),

            Err(e) => {
                if let Some(mut message) = self.messages.remove(message_id) {
                    message.writer.abort();
                }
                Err(e)
            }
        }
    }
}
