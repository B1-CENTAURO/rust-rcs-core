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

extern crate rust_strict_sdp;

use rust_strict_sdp::Sdp;

use super::{MsrpDirection, MsrpFileInfo, MsrpInfo, MsrpInterfaceType, MsrpSetupMethod};

pub trait AsMsrpInfo<'a> {
    type Target;
    fn as_msrp_info(&self) -> Option<Self::Target>;
}

impl<'a> AsMsrpInfo<'a> for Sdp<'a> {
    type Target = MsrpInfo<'a>;
    fn as_msrp_info(&self) -> Option<Self::Target> {
        for media in &self.medias {
            if media.media_type.eq_ignore_ascii_case(b"message")
                && (media.protocol.eq_ignore_ascii_case(b"TCP/MSRP")
                    || media.protocol.eq_ignore_ascii_case(b"TCP/TLS/MSRP"))
            {
                // a c= line of the media overrides the one of the session
                let connection = if media.connection.is_some() {
                    &media.connection
                } else {
                    &self.connection
                };

                if let Some(connection) = connection {
                    if connection.network_type == b"IN" {
                        let interface_type = if connection.address_type == b"IP4" {
                            MsrpInterfaceType::IPv4
                        } else if connection.address_type == b"IP6" {
                            MsrpInterfaceType::IPv6
                        } else {
                            return None;
                        };

                        let mut inactive = false;
                        let mut cema = false;
                        let mut direction = MsrpDirection::SendReceive; // RFC 4566 section 6
                        let mut setup_method = MsrpSetupMethod::Passive;

                        let mut path: &[u8] = &[];
                        let mut accept_types: &[u8] = &[];
                        let mut accept_wrapped_types: &[u8] = &[];

                        let mut file_selector: &[u8] = &[];
                        let mut file_transfer_id: &[u8] = &[];
                        let mut file_range: &[u8] = &[];
                        let mut file_icon: &[u8] = &[];
                        let mut file_disposition: &[u8] = &[];

                        // the media's attributes come last, overriding the session's
                        for attribute in self.attributes.iter().chain(media.attributes.iter()) {
                            if attribute.eq_ignore_ascii_case(b"inactive") {
                                inactive = true;
                            } else if attribute.eq_ignore_ascii_case(b"sendonly") {
                                inactive = false;
                                direction = MsrpDirection::SendOnly;
                            } else if attribute.eq_ignore_ascii_case(b"recvonly") {
                                inactive = false;
                                direction = MsrpDirection::ReceiveOnly;
                            } else if attribute.eq_ignore_ascii_case(b"msrp-cema") {
                                cema = true;
                            } else if attribute.eq_ignore_ascii_case(b"sendrecv") {
                                inactive = false;
                                direction = MsrpDirection::SendReceive;
                            } else {
                                // a=<attribute>:<value>
                                if let Some(idx) = attribute.iter().position(|c| *c == b':') {
                                    let attr_name = &attribute[..idx];
                                    let attr_value = &attribute[idx + 1..];

                                    if attr_name.eq_ignore_ascii_case(b"path") {
                                        path = attr_value;
                                    } else if attr_name.eq_ignore_ascii_case(b"setup") {
                                        if attr_value.eq_ignore_ascii_case(b"active") {
                                            setup_method = MsrpSetupMethod::Active;
                                        }
                                    } else if attr_name.eq_ignore_ascii_case(b"accept-types") {
                                        accept_types = attr_value;
                                    } else if attr_name
                                        .eq_ignore_ascii_case(b"accept-wrapped-types")
                                    {
                                        accept_wrapped_types = attr_value;
                                    } else if attr_name.eq_ignore_ascii_case(b"file-selector") {
                                        file_selector = attr_value;
                                    } else if attr_name.eq_ignore_ascii_case(b"file-transfer-id") {
                                        file_transfer_id = attr_value;
                                    } else if attr_name.eq_ignore_ascii_case(b"file-range") {
                                        file_range = attr_value;
                                    } else if attr_name.eq_ignore_ascii_case(b"file-icon") {
                                        file_icon = attr_value;
                                    } else if attr_name.eq_ignore_ascii_case(b"file-disposition") {
                                        file_disposition = attr_value;
                                    }
                                }
                            }
                        }

                        if path.len() > 0 && accept_types.len() > 0 {
                            return Some(MsrpInfo {
                                protocol: media.protocol,
                                address: connection.connection_address,
                                interface_type,
                                port: media.port,
                                path,
                                accept_types,
                                accept_wrapped_types: if accept_wrapped_types.len() > 0 {
                                    Some(accept_wrapped_types)
                                } else {
                                    None
                                },
                                inactive,
                                cema,
                                direction,
                                setup_method,
                                file_info: if file_selector.len() > 0 && file_transfer_id.len() > 0
                                {
                                    Some(MsrpFileInfo {
                                        file_selector,
                                        file_transfer_id,
                                        file_range: if file_range.len() > 0 {
                                            Some(file_range)
                                        } else {
                                            None
                                        },
                                        file_icon: if file_icon.len() > 0 {
                                            Some(file_icon)
                                        } else {
                                            None
                                        },
                                        file_disposition: if file_disposition.len() > 0 {
                                            Some(file_disposition)
                                        } else {
                                            None
                                        },
                                    })
                                } else {
                                    None
                                },
                            });
                        }
                    }
                }
            }
        }

        None
    }
}
