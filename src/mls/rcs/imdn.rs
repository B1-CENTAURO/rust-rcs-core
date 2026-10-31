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

//! MLS failure reasons of Negative-Delivery IMDNs (RCC.16 sections 6.2.5, 6.2.6, 7.7.2)

use quick_xml::events::Event;
use quick_xml::reader::Reader;

use crate::imdn::notification::{Imdn, Notification, Status};

use super::wire::ClientFailureReason;
use super::ServerFailureReason;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureReason {
    /// Rejected by the Conversation Focus
    Server(ServerFailureReason),
    /// Rejected by the receiving client
    Client(ClientFailureReason),
}

/// Failure reason carried by a `message/imdn+xml` body, if any
///
/// Section 7.7.2.3 places it in the `<failed>` status, while the text around
/// it speaks of `<delivery-notification>`; it is looked for anywhere.
pub fn failure_reason(imdn: &[u8]) -> Option<FailureReason> {
    let mut reader = Reader::from_reader(imdn);
    let mut buf = Vec::new();
    let mut container: Option<bool> = None; // Some(true) inside a server reason

    loop {
        let event = reader.read_event_into(&mut buf).ok()?;
        match event {
            Event::Start(ref e) | Event::Empty(ref e) => {
                let name = e.local_name();
                match container {
                    Some(true) => {
                        return ServerFailureReason::from_xml_name(name.as_ref())
                            .map(FailureReason::Server)
                    }
                    Some(false) => {
                        return ClientFailureReason::from_xml_name(name.as_ref())
                            .map(FailureReason::Client)
                    }
                    None if matches!(event, Event::Start(_)) => match name.as_ref() {
                        b"mls-server-failure-reason" => container = Some(true),
                        b"mls-client-failure-reason" => container = Some(false),
                        _ => {}
                    },
                    None => {}
                }
            }
            Event::End(ref e) if container.is_some() => {
                let name = e.local_name();
                if name.as_ref() == b"mls-server-failure-reason"
                    || name.as_ref() == b"mls-client-failure-reason"
                {
                    return None;
                }
            }
            Event::Eof => return None,
            _ => {}
        }
        buf.clear();
    }
}

/// `<status>` element of a client generated Negative-Delivery IMDN, as laid out
/// by the schema of section 7.7.2.3
pub fn failed_status(reason: ClientFailureReason) -> String {
    match reason.xml_name() {
        Some(name) => format!(
            "<status><failed><mls-client-failure-reason><{}/></mls-client-failure-reason></failed></status>",
            name
        ),
        None => "<status><failed/></status>".to_string(),
    }
}

/// A client generated Negative-Delivery IMDN telling that the message
/// `message_id`, of DateTime `datetime`, failed for `reason` (RCC.16 sections
/// 7.7.2.2, 7.7.2.3)
pub fn negative_delivery(message_id: &str, datetime: &str, reason: ClientFailureReason) -> String {
    let imdn = Imdn {
        message_id: String::from(message_id),
        datetime: String::from(datetime),
        recipient_uri: None,
        original_recipient_uri: None,
        notification: Notification::Delivery,
        status: Status::Failed,
    };
    // a failed delivery goes with a delivery notification
    let xml = imdn.to_xml().unwrap_or_default();
    xml.replacen("<status><failed/></status>", &failed_status(reason), 1)
}
