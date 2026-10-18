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

use std::sync::{Arc, Mutex};

use crate::ffi::log::platform_log;
use crate::sip::sip_message::build_message_data;
use crate::sip::SipTransport;

use crate::internet::header::{self, Header, HeaderSearch};
use crate::internet::header_field::AsHeaderField;
use crate::sip::sip_headers::cseq::AsCSeq;

use super::super::sip_message::SipMessage;
use super::super::sip_message::ACK;

use super::client_transaction::ClientTransactionCallbacks;

const LOG_TAG: &str = "sip_transaction";

enum State {
    None,
    Calling,
    Proceeding,
    Completed,
    Accepted,
    Terminated,
}

pub struct ICTransaction {
    state: Arc<Mutex<(State, Option<SipMessage>)>>,
    pub message: SipMessage,
    pub transport: Arc<SipTransport>,
    transport_function: Box<dyn Fn(&Arc<SipTransport>, Vec<u8>) -> bool + Send + Sync>,
    callbacks: Box<dyn ClientTransactionCallbacks + Send + Sync>,
}

impl ICTransaction {
    pub fn new<F, C>(
        message: SipMessage,
        transport: &Arc<SipTransport>,
        f: F,
        c: C,
    ) -> ICTransaction
    where
        F: Fn(&Arc<SipTransport>, Vec<u8>) -> bool + Send + Sync + 'static,
        C: ClientTransactionCallbacks + Send + Sync + 'static,
    {
        ICTransaction {
            state: Arc::new(Mutex::new((State::None, None))),
            message,
            transport: Arc::clone(&transport),
            transport_function: Box::new(f),
            callbacks: Box::new(c),
        }
    }

    fn perform_send(&self, message: &SipMessage) {
        let data = build_message_data(message);

        platform_log(
            LOG_TAG,
            format!("IC send message {}", String::from_utf8_lossy(&data)),
        );

        (self.transport_function)(&self.transport, data);
    }

    pub fn is_terminated(&self) -> bool {
        let guard = self.state.lock().unwrap();
        match guard.0 {
            State::Terminated => true,
            _ => false,
        }
    }

    pub fn start(&self) {
        let mut guard = self.state.lock().unwrap();
        match guard.0 {
            State::None => {
                guard.0 = State::Calling;
                self.perform_send(&self.message);
                // to-do: start timer_a for unreliable transport
            }
            _ => {}
        }
    }

    // Returns Ok('should restart timer_a') on success
    pub fn on_timer_a(&self) -> Result<bool, &'static str> {
        let guard = self.state.lock().unwrap();
        match guard.0 {
            State::Calling => {
                self.perform_send(&self.message);
                return Ok(true);
            }
            _ => {}
        }

        Err("Wrong state")
    }

    pub fn on_timer_b(&self) {
        let mut guard = self.state.lock().unwrap();
        match guard.0 {
            State::Calling => {
                guard.0 = State::Terminated;
                self.callbacks.on_transport_error();
            }
            _ => {}
        }
    }

    pub fn on_timer_d(&self) {
        let mut guard = self.state.lock().unwrap();
        match guard.0 {
            State::Completed => {
                guard.0 = State::Terminated;
            }
            _ => {}
        }
    }

    pub fn on_timer_m(&self) {
        let mut guard = self.state.lock().unwrap();
        match guard.0 {
            State::Accepted => {
                guard.0 = State::Terminated;
            }
            _ => {}
        }
    }

    /// Returns Ok(('should start timer_d', 'should start timer_m')) on success
    pub fn on_response(&self, resp_message: SipMessage) -> Result<(bool, bool), &'static str> {
        if let SipMessage::Response(resp_line, _, _) = &resp_message {
            if resp_line.status_code >= 100 && resp_line.status_code < 200 {
                let mut guard = self.state.lock().unwrap();
                match guard.0 {
                    State::Calling => {
                        guard.0 = State::Proceeding;
                        self.callbacks.on_provisional_response(resp_message);
                        return Ok((false, false));
                    }
                    _ => {}
                }
            } else if resp_line.status_code >= 200 && resp_line.status_code < 300 {
                let mut guard = self.state.lock().unwrap();
                match guard.0 {
                    State::Calling | State::Proceeding => {
                        guard.0 = State::Accepted;
                        self.callbacks.on_final_response(resp_message);
                        return Ok((false, true));
                    }
                    State::Accepted => {
                        self.callbacks.on_final_response(resp_message);
                        return Ok((false, false));
                    }
                    _ => {}
                }
            } else if resp_line.status_code >= 300 && resp_line.status_code < 700 {
                let mut guard = self.state.lock().unwrap();
                match guard.0 {
                    State::Calling | State::Proceeding => {
                        guard.0 = State::Completed;
                        // the transaction itself acknowledges a final
                        // response other than 2xx, and again for each
                        // retransmission of it (RFC 3261 section 17.1.1.3)
                        guard.1 = make_ack(&self.message, &resp_message);
                        if let Some(ack_message) = &guard.1 {
                            self.perform_send(ack_message);
                        }
                        self.callbacks.on_final_response(resp_message);
                        return Ok((true, false));
                    }
                    State::Completed => {
                        if let Some(ack_message) = &guard.1 {
                            self.perform_send(ack_message);
                        }
                        return Ok((false, false));
                    }
                    _ => {}
                }
            }
        }

        Err("Wrong state")
    }
}

/// The ACK to `response`, a final response other than 2xx to `invite`: its
/// Request-URI, Call-ID, From, top Via, Route and sequence number, with the To
/// of the response (RFC 3261 section 17.1.1.3)
fn make_ack(invite: &SipMessage, response: &SipMessage) -> Option<SipMessage> {
    let (req_line, req_headers) = match invite {
        SipMessage::Request(req_line, Some(req_headers), _) => (req_line, req_headers),
        _ => return None,
    };
    let resp_headers = response.headers()?;

    let via = header::search(req_headers, b"Via", true)?;
    let call_id = header::search(req_headers, b"Call-ID", true)?;
    let from = header::search(req_headers, b"From", true)?;
    let to = header::search(resp_headers, b"To", true)?;
    let cseq = header::search(req_headers, b"CSeq", true)?;
    let seq = cseq.get_value().as_header_field().as_cseq()?.seq;

    let mut ack = SipMessage::new_request(ACK, &req_line.uri);
    ack.add_header(Header::new(b"Via", via.get_value().to_vec()));
    ack.add_header(Header::new(b"Max-Forwards", b"70"));
    ack.add_header(Header::new(b"From", from.get_value().to_vec()));
    ack.add_header(Header::new(b"To", to.get_value().to_vec()));
    ack.add_header(Header::new(b"Call-ID", call_id.get_value().to_vec()));
    ack.add_header(Header::new(b"CSeq", format!("{} ACK", seq)));
    for route in HeaderSearch::new(req_headers, b"Route", true) {
        ack.add_header(Header::new(b"Route", route.get_value().to_vec()));
    }
    ack.add_header(Header::new(b"Content-Length", b"0"));
    Some(ack)
}
