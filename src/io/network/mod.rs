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

#[cfg(all(feature = "android", target_os = "android"))]
pub mod android_socket;
#[cfg(all(feature = "ohos", all(target_os = "linux", target_env = "ohos")))]
pub mod ohos_socket;
pub mod stream;

/// `address` and `port` as a SIP host and port, an IPv6 address in brackets
/// (RFC 3261 section 25.1)
pub fn host_port(address: &str, port: u16) -> String {
    if address.contains(':') && !address.starts_with('[') {
        format!("[{}]:{}", address, port)
    } else {
        format!("{}:{}", address, port)
    }
}

#[cfg(test)]
mod tests {
    use super::host_port;

    #[test]
    fn an_ipv6_address_is_bracketed() {
        assert_eq!(host_port("192.0.2.10", 5060), "192.0.2.10:5060");
        assert_eq!(host_port("2001:db8::10", 5060), "[2001:db8::10]:5060");
        assert_eq!(host_port("[2001:db8::10]", 5060), "[2001:db8::10]:5060");
    }
}
