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

pub mod msrp_info_reader;
pub mod msrp_info_writer;

use std::net::IpAddr;

pub enum MsrpInterfaceType {
    IPv4,
    IPv6,
}

pub enum MsrpDirection {
    SendOnly,
    ReceiveOnly,
    SendReceive,
}

pub enum MsrpSetupMethod {
    Passive,
    Active,
}

pub struct MsrpInfo<'a> {
    pub protocol: &'a [u8],
    pub address: &'a [u8],
    pub interface_type: MsrpInterfaceType,
    pub port: u16,
    pub path: &'a [u8],
    pub inactive: bool,
    pub direction: MsrpDirection,
    pub setup_method: MsrpSetupMethod,
    pub accept_types: &'a [u8],
    pub accept_wrapped_types: Option<&'a [u8]>,
    pub cema: bool, // a=msrp-cema, RFC 6714

    pub file_info: Option<MsrpFileInfo<'a>>,
}

impl<'a> MsrpInfo<'a> {
    /// Where to connect to the endpoint this SDP describes, `local_cema`
    /// saying whether this endpoint's own SDP for the session carries
    /// a=msrp-cema. An endpoint that does CEMA connects to the c= address and
    /// m= port, which a media anchoring middlebox may have rewritten, whether
    /// or not this SDP carries a=msrp-cema (RFC 6714 sections 4.2 and 4.3);
    /// one that does not connects to the first URI of a=path, the first hop,
    /// as in RFC 4975.
    ///
    /// Before that, a CEMA answerer rejects an offer without a=msrp-cema
    /// whose c= and m= do not match a=path, and a CEMA offerer that would be
    /// passive offers again without CEMA when the answer has no a=msrp-cema
    /// and they do not match; see `connection_matches_path`.
    pub fn connection_address(&self, local_cema: bool) -> Option<(&'a [u8], u16)> {
        if local_cema {
            return Some((self.address, self.port));
        }

        let uri = self
            .path
            .split(|c| *c == b' ')
            .find(|uri| !uri.is_empty())?;
        uri_host_port(uri)
    }

    /// Whether the c= address and m= port are those of a URI in a=path, as
    /// RFC 6714 section 4.4 compares them: when they are not, a middlebox has
    /// rewritten them. `None` when telling takes DNS, a domain name on either
    /// side that is not the same name on both.
    pub fn connection_matches_path(&self) -> Option<bool> {
        let address = ip_address(self.address);
        let mut needs_dns = false;

        for uri in self
            .path
            .split(|c| *c == b' ')
            .filter(|uri| !uri.is_empty())
        {
            if let Some((host, port)) = uri_host_port(uri) {
                if port != self.port {
                    continue;
                }

                match (address, ip_address(host)) {
                    (Some(address), Some(host)) => {
                        if address == host {
                            return Some(true);
                        }
                    }

                    _ => {
                        if host.eq_ignore_ascii_case(self.address) {
                            return Some(true);
                        }
                        needs_dns = true;
                    }
                }
            }
        }

        if needs_dns {
            None
        } else {
            Some(false)
        }
    }
}

// msrp[s]://[userinfo@]host:port[/session-id];transport
fn uri_host_port(uri: &[u8]) -> Option<(&[u8], u16)> {
    let idx = uri.windows(3).position(|w| w == b"://")?;
    let rest = &uri[idx + 3..];
    let end = rest
        .iter()
        .position(|c| *c == b'/' || *c == b';')
        .unwrap_or(rest.len());
    let authority = &rest[..end];
    let authority = match authority.iter().rposition(|c| *c == b'@') {
        Some(idx) => &authority[idx + 1..],
        None => authority,
    };

    let (host, port) = if authority.first() == Some(&b'[') {
        let idx = authority.iter().position(|c| *c == b']')?;
        (&authority[1..idx], authority[idx + 1..].strip_prefix(b":")?)
    } else {
        let idx = authority.iter().rposition(|c| *c == b':')?;
        (&authority[..idx], &authority[idx + 1..])
    };

    let port = std::str::from_utf8(port).ok()?.parse().ok()?;
    Some((host, port))
}

// compared as values, so any IPv6 spelling matches (RFC 5952)
fn ip_address(address: &[u8]) -> Option<IpAddr> {
    std::str::from_utf8(address).ok()?.parse().ok()
}

pub struct MsrpFileInfo<'a> {
    pub file_selector: &'a [u8],
    pub file_transfer_id: &'a [u8],
    pub file_range: Option<&'a [u8]>,
    pub file_icon: Option<&'a [u8]>,
    pub file_disposition: Option<&'a [u8]>,
}
