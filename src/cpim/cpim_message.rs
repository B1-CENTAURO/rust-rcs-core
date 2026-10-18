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

use crate::ffi::log::platform_log;
use crate::internet::body::message_body::MessageBody;
use crate::internet::body::Body;
use crate::internet::header;
use crate::internet::header::Header;
use crate::internet::name_addr::AsNameAddr;
use crate::internet::syntax;
use crate::internet::uri::AsURI;
use crate::internet::uri::URI;

use crate::imdn;

use crate::util::raw_string::StrEq;

use super::cpim_header_value::CPIMHeaderValue;
use super::cpim_info::CPIMInfo;
use super::cpim_namespace::CPIMNamespace;

const LOG_TAG: &str = "cpim";

pub enum CPIMHeaders {
    Deflated(Vec<Header>),
    Inflated(Vec<Header>),
}

pub struct CPIMMessage {
    pub ns: CPIMNamespace,
    pub headers: CPIMHeaders,
    pub body: Body,
}

impl<'a> CPIMMessage {
    pub fn new(namespaces: &[(&[u8], &[u8])], headers: Vec<Header>, body: Body) -> CPIMMessage {
        let mut ns = CPIMNamespace::new();
        for (n, v) in namespaces {
            ns.register(n, v);
        }
        CPIMMessage {
            ns,
            headers: CPIMHeaders::Deflated(headers),
            body,
        }
    }

    pub fn try_from(body: &Body) -> Result<CPIMMessage, &'static str> {
        platform_log(LOG_TAG, "try decode");

        if let Body::Message(message_body) = body {
            let mut ns = CPIMNamespace::new();
            let mut headers: Vec<Header> = Vec::new();

            for h in &message_body.headers {
                if h.get_name() == b"NS" {
                    let value = h.get_value();
                    let mut iter = value.iter();
                    if let Some(start) = iter.position(|c| *c == b'<') {
                        if let Some(end) = iter.position(|c| *c == b'>') {
                            ns.register(
                                syntax::trim(&value[..start]),
                                syntax::trim(&value[start + 1..start + 1 + end]),
                            );
                            continue;
                        }
                    }
                    return Err("bad namespace");
                } else {
                    let (n, v) = ns.as_inflator()(&h);
                    headers.push(Header::new(n, syntax::trim(v).to_vec()));
                }
            }

            match &*message_body.body {
                Body::Raw(data) => {
                    // the content is handed on as it is, multipart or not
                    let inner_body = MessageBody::construct_with_raw_content(&data);
                    if let Ok(inner_body) = inner_body {
                        return Ok(CPIMMessage {
                            ns,
                            headers: CPIMHeaders::Inflated(headers),
                            body: Body::Message(inner_body),
                        });
                    }
                    return Err("bad format");
                }

                Body::Message(inner_body) => {
                    // strange to see inner body already constructed
                    return Ok(CPIMMessage {
                        ns,
                        headers: CPIMHeaders::Inflated(headers),
                        body: Body::Message(inner_body.clone()),
                    });
                }

                Body::Multipart(_) => {
                    return Err("bad format");
                }

                Body::Streamed(_) => {
                    return Err("impossible condition");
                }
            }
        }

        Err("bad format")
    }

    fn get_info_from_inflated_headers(
        &'a self,
        headers: Vec<(Vec<u8>, &'a [u8])>,
    ) -> Result<CPIMInfo, &'static str> {
        let mut from: Option<&[u8]> = None;
        let mut to: Option<&[u8]> = None;
        let mut date: Option<&[u8]> = None;

        let mut payload_type: Option<&[u8]> = None;
        let mut imdn_message_id: Option<&[u8]> = None;
        let mut disposition_notification: Option<&[u8]> = None;

        for (n, v) in headers {
            platform_log(
                LOG_TAG,
                format!("decoded CPIM header name {:?}", std::str::from_utf8(&n)),
            );
            platform_log(
                LOG_TAG,
                format!("decoded CPIM header value {:?}", std::str::from_utf8(v)),
            );

            // the first of each, without its parameters
            let v = CPIMHeaderValue::parse(v).value;
            if &n == b"From" {
                from.get_or_insert(v);
            } else if &n == b"To" {
                to.get_or_insert(v);
            } else if &n == b"DateTime" {
                date.get_or_insert(v);
            } else if &n == b"<http://www.openmobilealliance.org/cpm/>.Payload-Type" {
                payload_type.get_or_insert(v);
            } else if &n == b"<urn:ietf:params:imdn>.Message-ID" {
                imdn_message_id.get_or_insert(v);
            } else if &n == b"<urn:ietf:params:imdn>.Disposition-Notification" {
                disposition_notification.get_or_insert(v);
            }
        }

        if let (Some(imdn_message_id), Some(from), Some(to), Some(date)) =
            (imdn_message_id, from, to, date)
        {
            let mut from_uri: Option<URI> = None;
            let mut to_uri: Option<URI> = None;

            let from_addresses = from.as_name_addresses();

            if let Some(from_address) = from_addresses.first() {
                if let Some(uri_part) = &from_address.uri_part {
                    from_uri = uri_part.uri.as_standard_uri();
                }
            }

            let to_addresses = to.as_name_addresses();

            if let Some(to_address) = to_addresses.first() {
                if let Some(uri_part) = &to_address.uri_part {
                    to_uri = uri_part.uri.as_standard_uri();
                }
            }

            return Ok(CPIMInfo {
                imdn_message_id,
                from,
                to,
                date,
                from_uri,
                to_uri,
                payload_type,
                disposition_notification,
            });
        }

        Err("missing required headers")
    }

    /// The From, the first To, DateTime and the IMDN and CPM headers of an RCS
    /// message
    pub fn get_info(&self) -> Result<CPIMInfo, &'static str> {
        self.get_info_from_inflated_headers(self.inflated_headers())
    }

    /// The names and values of the headers, with namespace prefixes written
    /// out as CPIMNamespace::inflate() writes them
    fn inflated_headers(&self) -> Vec<(Vec<u8>, &[u8])> {
        match &self.headers {
            CPIMHeaders::Deflated(headers) => headers
                .iter()
                .map(|header| (self.ns.inflate(header.get_name()), header.get_value()))
                .collect(),

            CPIMHeaders::Inflated(headers) => headers
                .iter()
                .map(|header| (header.get_name().to_vec(), header.get_value()))
                .collect(),
        }
    }

    /// The values of each header named `name`, in order, such as every To, cc
    /// or Subject. A name in a namespace is written as
    /// CPIMNamespace::inflate() writes it: `<urn:ietf:params:imdn>.Message-ID`.
    pub fn get_values(&self, name: &[u8]) -> Vec<CPIMHeaderValue<'_>> {
        self.inflated_headers()
            .into_iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| CPIMHeaderValue::parse(v))
            .collect()
    }

    /// The names listed by Require headers (RFC 3862 section 3.5), written as
    /// get_values() takes them, that are not in `understood`. The sender
    /// requires each to be understood, so a message with any left is not to
    /// be taken as understood. NS and Require are understood here.
    pub fn get_unmet_requirements(&self, understood: &[&[u8]]) -> Vec<Vec<u8>> {
        let mut unmet: Vec<Vec<u8>> = Vec::new();
        for required in self.get_values(b"Require") {
            for name in required.value.split(|c| *c == b',') {
                let name = self.ns.inflate(syntax::trim(name));
                if !name.is_empty()
                    && name != b"NS"
                    && name != b"Require"
                    && !understood.contains(&&name[..])
                    && !unmet.contains(&name)
                {
                    unmet.push(name);
                }
            }
        }
        unmet
    }

    pub fn get_message_body(&'a self) -> Option<(Option<&'a [u8]>, &'a [u8], bool)> {
        match &self.body {
            Body::Raw(r) => Some((None, r, false)),
            Body::Message(m) => {
                if let Body::Raw(ref r) = *m.body {
                    let mut base64_encoded = false;
                    if let Some(h) = header::search(&m.headers, b"Content-Transfer-Encoding", true)
                    {
                        platform_log(
                            LOG_TAG,
                            format!(
                                "message body has a Content-Transfer-Encoding of {:?}",
                                std::str::from_utf8(h.get_value())
                            ),
                        );
                        let content_transfer_encoding = syntax::trim(h.get_value());
                        if content_transfer_encoding.equals_bytes(b"base64", false) {
                            base64_encoded = true;
                        }
                    }
                    if let Some(h) = header::search(&m.headers, b"Content-Type", true) {
                        Some((Some(syntax::trim(h.get_value())), &r, base64_encoded))
                    } else {
                        Some((None, &r, base64_encoded))
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn search_header(&self, name: &[u8]) -> Option<&[u8]> {
        match &self.headers {
            CPIMHeaders::Deflated(headers) => {
                for header in headers {
                    if header.get_name().equals_bytes(name, false) {
                        return Some(header.get_value());
                    }
                }
                None
            }
            CPIMHeaders::Inflated(headers) => {
                for header in headers {
                    if header.get_name().equals_bytes(name, false) {
                        return Some(header.get_value());
                    }
                }
                None
            }
        }
    }

    pub fn contains_imdn(&self) -> bool {
        let mut notification_checked = false;

        if let Some(content_disposition) = Self::search_header(self, b"Content-Disposition") {
            if content_disposition.equals_bytes(b"notification", true) {
                notification_checked = true;
            }
        }

        match &self.body {
            Body::Message(message) => {
                return imdn::message_contains_imdn(message, notification_checked);
            }

            Body::Multipart(multipart) => {
                for part in &multipart.parts {
                    if let Body::Message(message) = part.as_ref() {
                        if imdn::message_contains_imdn(message, notification_checked) {
                            return true;
                        }
                    }
                }
            }

            _ => {}
        }

        false
    }
}
