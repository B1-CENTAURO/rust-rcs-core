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
use std::sync::Arc;

use crate::internet::header::headers_get_readers;
use crate::io::Serializable;
use crate::util::raw_string::{StrEq, StrFind, ToInt};

use super::super::header::Header;
use super::super::header_field::AsHeaderField;
use super::super::headers::content_type::AsContentType;
use super::super::syntax;
use super::{Body, BodySerializationError};

#[derive(Debug)]
pub struct MessageBody {
    pub headers: Vec<Header>,
    pub body: Arc<Body>,
}

impl MessageBody {
    pub fn construct(data: &[u8]) -> Result<MessageBody, &'static str> {
        Self::construct_with(data, true)
    }

    /// Reads `data` as construct() does, but leaves the content as it is
    /// whatever its type
    pub fn construct_with_raw_content(data: &[u8]) -> Result<MessageBody, &'static str> {
        Self::construct_with(data, false)
    }

    fn construct_with(data: &[u8], parse_content: bool) -> Result<MessageBody, &'static str> {
        let mut headers = Vec::new();
        let mut i = 0;
        while i <= data.len() {
            if let Some(idx) = data[i..].index_of(b"\r\n") {
                if idx == 0 {
                    i = i + 2;
                    break;
                }
                // a line starting with whitespace folds the header onto it
                let mut end = i + idx;
                while data[end + 2..].starts_with(b" ") || data[end + 2..].starts_with(b"\t") {
                    if let Some(idx) = data[end + 2..].index_of(b"\r\n") {
                        end = end + 2 + idx;
                    } else {
                        break;
                    }
                }
                let mut iter = data[i..end].iter();
                if let Some(position) = iter.position(|c| *c == b':') {
                    headers.push(Header::new(
                        data[i..i + position].to_vec(),
                        syntax::trim(&unfold(iter.as_slice())).to_vec(),
                    ));
                } else {
                    return Err("malformed header");
                }
                i = end + 2;
            } else {
                break;
            }
        }

        let mut construct_flag: Option<i32> = None;
        let mut content_length: Option<usize> = None;
        let mut boundary: Option<Vec<u8>> = None;

        for header in &headers {
            if header.get_name().equals_bytes(b"Content-Length", true) {
                if let Ok(i) = header.get_value().to_int() {
                    content_length = Some(i);
                }
            } else if parse_content && header.get_name().equals_bytes(b"Content-Type", true) {
                let field = header.get_value().as_header_field();
                if let Some(content_type) = field.as_content_type() {
                    if content_type.major_type.equals_bytes(b"message", true)
                        && is_headers_and_body(content_type.sub_type)
                    {
                        construct_flag = Some(1);
                    } else if content_type.major_type.equals_bytes(b"multipart", true)
                        && !content_type.boundary.is_empty()
                    {
                        construct_flag = Some(2);
                        boundary = Some(content_type.boundary.to_vec());
                    } else {
                        construct_flag = Some(0);
                    }
                }
            }
        }

        // what carries the message frames the content, so a Content-Length
        // running past its end is not taken
        let mut content = &data[i..];
        if let Some(content_length) = content_length {
            if content_length <= content.len() {
                content = &content[..content_length];
            }
        }

        // content that does not read as its type is kept as it is
        let body = match (construct_flag, boundary) {
            (Some(1), _) => Body::construct_message(content).ok(),
            (Some(2), Some(boundary)) => Body::construct_multipart(content, &boundary).ok(),
            _ => None,
        };

        Ok(MessageBody {
            headers,
            body: Arc::new(body.unwrap_or_else(|| Body::construct_raw(content))),
        })
    }

    pub fn get_readers<'a>(
        &'a self,
        readers: &mut Vec<Box<dyn Read + Send + 'a>>,
    ) -> Result<(), BodySerializationError> {
        headers_get_readers(&self.headers, readers);

        readers.push(Box::new(&b"\r\n"[..]));
        readers.push(Box::new(self.body.reader()?));

        Ok(())
    }
}

/// `value` with the line breaks folding it taken out
fn unfold(value: &[u8]) -> Vec<u8> {
    let mut unfolded = Vec::with_capacity(value.len());
    let mut i = 0;
    while i < value.len() {
        if value[i..].starts_with(b"\r\n") {
            i = i + 2;
        } else {
            unfolded.push(value[i]);
            i = i + 1;
        }
    }
    unfolded
}

/// Whether content of type message/`sub_type` is itself headers and a body,
/// to be parsed as a MessageBody; message/imdn+xml, for one, is XML
fn is_headers_and_body(sub_type: &[u8]) -> bool {
    sub_type.equals_bytes(b"cpim", true)
        || sub_type.equals_bytes(b"rfc822", true)
        || sub_type.equals_bytes(b"global", true)
}

impl Clone for MessageBody {
    fn clone(&self) -> Self {
        let mut headers = Vec::new();
        for header in &self.headers {
            headers.push(header.clone());
        }
        MessageBody {
            headers,
            body: self.body.clone(),
        }
    }
}

impl Serializable for MessageBody {
    // fn serialize(&self) -> Vec<u8> {
    //     let mut data = Vec::with_capacity(self.estimated_size());
    //     data.extend(self.headers.serialize());
    //     data.extend(b"\r\n");
    //     data.extend(self.body.serialize());
    //     data
    // }

    fn estimated_size(&self) -> usize {
        let mut size = 0;
        size += self.headers.estimated_size();
        size += 2;
        size += self.body.estimated_size();
        size
    }
}
