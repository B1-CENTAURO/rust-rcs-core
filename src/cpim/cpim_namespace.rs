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
use std::collections::BTreeMap;

use crate::internet::header::Header;

pub struct CPIMNamespace {
    registered_namespaces: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl<'r> CPIMNamespace {
    pub fn new() -> CPIMNamespace {
        CPIMNamespace {
            registered_namespaces: BTreeMap::new(),
        }
    }

    pub fn register(&mut self, n: &[u8], v: &[u8]) {
        let n = n.to_vec();
        let v = v.to_vec();
        self.registered_namespaces.insert(n, v);
    }

    /// `name` with its namespace prefix, if registered, written out as the
    /// namespace URI: `imdn.Message-ID` as `<urn:ietf:params:imdn>.Message-ID`
    pub fn inflate(&self, name: &[u8]) -> Vec<u8> {
        let mut iter = name.iter();
        if let Some(position) = iter.position(|c| *c == b'.') {
            for (k, v) in &self.registered_namespaces {
                if &name[..position] == k {
                    let mut inflated = b"<".to_vec();
                    inflated.extend(v);
                    inflated.extend(b">.");
                    inflated.extend(iter);
                    return inflated;
                }
            }
        }

        name.to_vec()
    }

    pub fn as_inflator(&'r self) -> Box<dyn Fn(&Header) -> (Vec<u8>, &[u8]) + 'r> {
        Box::new(|header| (self.inflate(header.get_name()), header.get_value()))
    }

    pub fn as_deflator(&'r self) -> Box<dyn Fn(&Header) -> (Option<Header>, Cow<Header>) + 'r> {
        Box::new(|header| {
            for (k, v) in &self.registered_namespaces {
                if header.get_name().starts_with(k) {
                    if k.len() < header.get_name().len() {
                        if header.get_name()[k.len()] == b'.' {
                            let mut ns = k.clone();
                            ns.extend(b"<");
                            ns.extend_from_slice(header.get_name());
                            ns.extend(b">");
                            let h1 = Header::new(b"NS", ns);
                            let mut deflated = v.clone();
                            if k.len() == 0 {
                                deflated.extend(b".");
                                deflated.extend_from_slice(header.get_name());
                            } else {
                                deflated.extend_from_slice(&header.get_name()[..k.len()]);
                            }
                            let h2 = Header::new(deflated, header.get_value().to_vec());
                            return (Some(h1), Cow::Owned(h2));
                        }
                    }
                }
            }

            (None, Cow::Borrowed(header))
        })
    }
}
