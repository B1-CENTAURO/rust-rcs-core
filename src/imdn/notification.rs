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

//! IMDN documents (RFC 5438 section 7.2), what the recipient of a message
//! says became of it, and the dispositions a message asks to be told of
//! (section 6.2)

use quick_xml::escape::escape;
use quick_xml::events::Event;
use quick_xml::reader::Reader;

use crate::util::raw_string::StrEq;

/// What a notification tells of
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notification {
    Delivery,
    Display,
    Processing,
}

impl Notification {
    fn element(&self) -> &'static str {
        match self {
            Notification::Delivery => "delivery-notification",
            Notification::Display => "display-notification",
            Notification::Processing => "processing-notification",
        }
    }

    fn from_element(name: &[u8]) -> Option<Notification> {
        match name {
            b"delivery-notification" => Some(Notification::Delivery),
            b"display-notification" => Some(Notification::Display),
            b"processing-notification" => Some(Notification::Processing),
            _ => None,
        }
    }
}

/// The status a notification gives
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Delivered,
    Displayed,
    Processed,
    Stored,
    Failed,
    Forbidden,
    Error,
}

impl Status {
    fn element(&self) -> &'static str {
        match self {
            Status::Delivered => "delivered",
            Status::Displayed => "displayed",
            Status::Processed => "processed",
            Status::Stored => "stored",
            Status::Failed => "failed",
            Status::Forbidden => "forbidden",
            Status::Error => "error",
        }
    }

    fn from_element(name: &[u8]) -> Option<Status> {
        match name {
            b"delivered" => Some(Status::Delivered),
            b"displayed" => Some(Status::Displayed),
            b"processed" => Some(Status::Processed),
            b"stored" => Some(Status::Stored),
            b"failed" => Some(Status::Failed),
            b"forbidden" => Some(Status::Forbidden),
            b"error" => Some(Status::Error),
            _ => None,
        }
    }

    /// Whether a notification of `notification` may give this status
    /// (sections 7.2.1.1 to 7.2.1.3)
    pub fn goes_with(&self, notification: Notification) -> bool {
        match (notification, self) {
            (_, Status::Forbidden) | (_, Status::Error) => true,
            (Notification::Delivery, Status::Delivered) => true,
            (Notification::Delivery, Status::Failed) => true,
            (Notification::Display, Status::Displayed) => true,
            (Notification::Processing, Status::Processed) => true,
            (Notification::Processing, Status::Stored) => true,
            _ => false,
        }
    }
}

/// An IMDN document
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Imdn {
    /// The imdn.Message-ID of the message told of
    pub message_id: String,
    /// The imdn.DateTime, or else the DateTime, of the message told of
    pub datetime: String,
    pub recipient_uri: Option<String>,
    pub original_recipient_uri: Option<String>,
    pub notification: Notification,
    pub status: Status,
}

impl Imdn {
    /// The document, unless its status does not go with its notification
    pub fn to_xml(&self) -> Option<String> {
        if !self.status.goes_with(self.notification) {
            return None;
        }

        let mut xml = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<imdn xmlns=\"urn:ietf:params:xml:ns:imdn\">",
        );
        xml += &format!("<message-id>{}</message-id>", escape(&self.message_id));
        xml += &format!("<datetime>{}</datetime>", escape(&self.datetime));
        if let Some(uri) = &self.recipient_uri {
            xml += &format!("<recipient-uri>{}</recipient-uri>", escape(uri));
        }
        if let Some(uri) = &self.original_recipient_uri {
            xml += &format!(
                "<original-recipient-uri>{}</original-recipient-uri>",
                escape(uri)
            );
        }
        xml += &format!(
            "<{0}><status><{1}/></status></{0}>",
            self.notification.element(),
            self.status.element()
        );
        xml += "</imdn>";
        Some(xml)
    }

    /// The document `xml` reads as, if a whole one
    pub fn from_xml(xml: &[u8]) -> Option<Imdn> {
        let mut reader = Reader::from_reader(xml);
        let mut buf = Vec::new();

        let mut message_id = None;
        let mut datetime = None;
        let mut recipient_uri = None;
        let mut original_recipient_uri = None;
        let mut notification = None;
        let mut status = None;

        // the element whose text is being read, and whether inside <status>
        let mut text_of: Option<Vec<u8>> = None;
        let mut in_status = false;

        loop {
            match reader.read_event_into(&mut buf).ok()? {
                Event::Start(ref e) | Event::Empty(ref e) => {
                    let name = e.local_name();
                    let name = name.as_ref();
                    if in_status {
                        if status.is_none() {
                            status = Status::from_element(name);
                        }
                    } else if let Some(n) = Notification::from_element(name) {
                        notification = Some(n);
                    } else if name == b"status" && notification.is_some() {
                        in_status = true;
                    } else {
                        text_of = Some(name.to_vec());
                    }
                }
                Event::Text(ref e) => {
                    if let Some(name) = &text_of {
                        let text = e.unescape().ok()?.trim().to_string();
                        match &name[..] {
                            b"message-id" => message_id = Some(text),
                            b"datetime" => datetime = Some(text),
                            b"recipient-uri" => recipient_uri = Some(text),
                            b"original-recipient-uri" => original_recipient_uri = Some(text),
                            _ => {}
                        }
                    }
                }
                Event::End(ref e) => {
                    if e.local_name().as_ref() == b"status" {
                        in_status = false;
                    }
                    text_of = None;
                }
                Event::Eof => break,
                _ => {}
            }
            buf.clear();
        }

        let notification = notification?;
        let status = status?;
        if !status.goes_with(notification) {
            return None;
        }

        Some(Imdn {
            message_id: message_id?,
            datetime: datetime?,
            recipient_uri,
            original_recipient_uri,
            notification,
            status,
        })
    }
}

/// The dispositions a message asks to be told of, by its
/// imdn.Disposition-Notification
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Dispositions {
    pub positive_delivery: bool,
    pub negative_delivery: bool,
    pub display: bool,
    pub processing: bool,
}

impl Dispositions {
    /// Those listed in `value`, as "positive-delivery, display"
    pub fn parse(value: &[u8]) -> Dispositions {
        let mut dispositions = Dispositions::default();
        for token in value.split(|c| *c == b',') {
            let token = crate::internet::syntax::trim(token);
            if token.equals_bytes(b"positive-delivery", true) {
                dispositions.positive_delivery = true;
            } else if token.equals_bytes(b"negative-delivery", true) {
                dispositions.negative_delivery = true;
            } else if token.equals_bytes(b"display", true) {
                dispositions.display = true;
            } else if token.equals_bytes(b"processing", true) {
                dispositions.processing = true;
            }
        }
        dispositions
    }

    /// Whether a notification of `notification` giving `status` was asked
    /// for, as it must be to be sent (section 7.2)
    pub fn ask_for(&self, notification: Notification, status: Status) -> bool {
        match notification {
            Notification::Delivery => match status {
                Status::Delivered => self.positive_delivery,
                _ => self.negative_delivery,
            },
            Notification::Display => self.display,
            Notification::Processing => self.processing,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Dispositions, Imdn, Notification, Status};

    fn delivered() -> Imdn {
        Imdn {
            message_id: String::from("34jk324j"),
            datetime: String::from("2008-04-04T12:16:49-07:00"),
            recipient_uri: Some(String::from("im:bob@example.com")),
            original_recipient_uri: None,
            notification: Notification::Delivery,
            status: Status::Delivered,
        }
    }

    #[test]
    fn a_notification_is_written_and_read_back() {
        for (notification, status) in [
            (Notification::Delivery, Status::Delivered),
            (Notification::Delivery, Status::Failed),
            (Notification::Display, Status::Displayed),
            (Notification::Display, Status::Forbidden),
            (Notification::Processing, Status::Stored),
        ] {
            let imdn = Imdn {
                notification,
                status,
                message_id: String::from("<a&b>"),
                ..delivered()
            };
            let xml = imdn.to_xml().unwrap();
            assert_eq!(Imdn::from_xml(xml.as_bytes()), Some(imdn), "{}", xml);
        }
    }

    #[test]
    fn a_notification_is_written_in_the_imdn_namespace_in_the_order_of_its_schema() {
        assert_eq!(
            delivered().to_xml().unwrap(),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<imdn xmlns=\"urn:ietf:params:xml:ns:imdn\">\
<message-id>34jk324j</message-id>\
<datetime>2008-04-04T12:16:49-07:00</datetime>\
<recipient-uri>im:bob@example.com</recipient-uri>\
<delivery-notification><status><delivered/></status></delivery-notification>\
</imdn>"
        );
    }

    #[test]
    fn a_status_that_does_not_go_with_its_notification_is_neither_written_nor_read() {
        let imdn = Imdn {
            notification: Notification::Display,
            status: Status::Delivered,
            ..delivered()
        };
        assert_eq!(imdn.to_xml(), None);
        assert_eq!(
            Imdn::from_xml(
                b"<imdn xmlns=\"urn:ietf:params:xml:ns:imdn\"><message-id>1</message-id>\
<datetime>2008-04-04T12:16:49-07:00</datetime>\
<display-notification><status><delivered/></status></display-notification></imdn>"
            ),
            None
        );
    }

    #[test]
    fn the_example_of_rfc_5438_is_read() {
        // section 7.2.1.1, its namespace prefixed
        let xml = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n\
<i:imdn xmlns:i=\"urn:ietf:params:xml:ns:imdn\">\r\n\
  <i:message-id>34jk324j</i:message-id>\r\n\
  <i:datetime>2008-04-04T12:16:49-07:00</i:datetime>\r\n\
  <i:recipient-uri>im:bob@example.com</i:recipient-uri>\r\n\
  <i:original-recipient-uri>im:bob@example.com</i:original-recipient-uri>\r\n\
  <i:delivery-notification>\r\n\
    <i:status>\r\n\
      <i:delivered/>\r\n\
    </i:status>\r\n\
  </i:delivery-notification>\r\n\
</i:imdn>";
        assert_eq!(
            Imdn::from_xml(xml),
            Some(Imdn {
                original_recipient_uri: Some(String::from("im:bob@example.com")),
                ..delivered()
            })
        );

        // and without what a notification needs
        assert_eq!(
            Imdn::from_xml(b"<imdn><message-id>1</message-id></imdn>"),
            None
        );
    }

    #[test]
    fn the_dispositions_asked_for_are_read_and_only_those_allowed() {
        let dispositions = Dispositions::parse(b"positive-delivery, Display");
        assert_eq!(
            dispositions,
            Dispositions {
                positive_delivery: true,
                display: true,
                ..Dispositions::default()
            }
        );
        assert!(dispositions.ask_for(Notification::Delivery, Status::Delivered));
        assert!(!dispositions.ask_for(Notification::Delivery, Status::Failed));
        assert!(dispositions.ask_for(Notification::Display, Status::Displayed));
        assert!(!dispositions.ask_for(Notification::Processing, Status::Stored));

        assert_eq!(Dispositions::parse(b""), Dispositions::default());
    }
}
