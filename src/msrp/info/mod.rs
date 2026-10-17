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
    /// Where to connect to the endpoint this SDP describes. With CEMA (RFC
    /// 6714) that is the c= address and m= port, which a media anchoring
    /// intermediary may have rewritten, otherwise the authority of the first
    /// URI in a=path, the first hop, as in RFC 4975.
    pub fn connection_address(&self) -> Option<(&'a [u8], u16)> {
        if self.cema {
            return Some((self.address, self.port));
        }

        // msrp[s]://[userinfo@]host:port[/session-id];transport
        let uri = self
            .path
            .split(|c| *c == b' ')
            .find(|uri| !uri.is_empty())?;
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
}

pub struct MsrpFileInfo<'a> {
    pub file_selector: &'a [u8],
    pub file_transfer_id: &'a [u8],
    pub file_range: Option<&'a [u8]>,
    pub file_icon: Option<&'a [u8]>,
    pub file_disposition: Option<&'a [u8]>,
}
