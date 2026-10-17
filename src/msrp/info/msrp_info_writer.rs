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

use std::borrow::Cow;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{MsrpDirection, MsrpInfo, MsrpInterfaceType, MsrpSetupMethod};

// seconds from 1900 to 1970
const NTP_UNIX_OFFSET: u64 = 2208988800;

impl From<MsrpInfo<'_>> for String {
    fn from(msrp_info: MsrpInfo<'_>) -> Self {
        let address_type = match msrp_info.interface_type {
            MsrpInterfaceType::IPv4 => "IP4",
            MsrpInterfaceType::IPv6 => "IP6",
        };

        let address = String::from_utf8_lossy(msrp_info.address);
        let protocol = String::from_utf8_lossy(msrp_info.protocol);

        let path = String::from_utf8_lossy(msrp_info.path);

        let accept_types = String::from_utf8_lossy(msrp_info.accept_types);
        let accept_wrapped_types = match msrp_info.accept_wrapped_types {
            Some(accept_wrapped_types) => String::from_utf8_lossy(accept_wrapped_types),
            None => Cow::Borrowed("*"),
        };

        // RFC 4566 suggests an NTP timestamp for the session id and version
        let ntp_time = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs() + NTP_UNIX_OFFSET,
            Err(_) => NTP_UNIX_OFFSET,
        };

        let mut sdp = format!(
            "v=0\r\n\
             o=- {} {} IN {} {}\r\n\
             s=-\r\n\
             c=IN {} {}\r\n\
             t=0 0\r\n\
             m=message {} {} *\r\n\
             a={}\r\n\
             a=path:{}\r\n\
             a=setup:{}\r\n\
             a=connection:new\r\n\
             a=accept-types:{}\r\n\
             a=accept-wrapped-types:{}\r\n",
            ntp_time,
            ntp_time,
            address_type,
            address,
            address_type,
            address,
            msrp_info.port,
            protocol,
            if msrp_info.inactive {
                "inactive"
            } else {
                match msrp_info.direction {
                    MsrpDirection::SendOnly => "sendonly",
                    MsrpDirection::ReceiveOnly => "recvonly",
                    MsrpDirection::SendReceive => "sendrecv",
                }
            },
            path,
            match msrp_info.setup_method {
                MsrpSetupMethod::Passive => "passive",
                MsrpSetupMethod::Active => "active",
            },
            accept_types,
            accept_wrapped_types
        );

        if msrp_info.cema {
            sdp.push_str("a=msrp-cema\r\n");
        }

        // RFC 5547
        if let Some(file_info) = msrp_info.file_info {
            for (name, value) in [
                ("file-selector", Some(file_info.file_selector)),
                ("file-transfer-id", Some(file_info.file_transfer_id)),
                ("file-disposition", file_info.file_disposition),
                ("file-range", file_info.file_range),
                ("file-icon", file_info.file_icon),
            ] {
                if let Some(value) = value {
                    sdp.push_str(&format!(
                        "a={}:{}\r\n",
                        name,
                        String::from_utf8_lossy(value)
                    ));
                }
            }
        }

        sdp
    }
}
