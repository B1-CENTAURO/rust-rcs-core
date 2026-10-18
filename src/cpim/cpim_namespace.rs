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
use crate::internet::syntax;

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

    /// `name` as inflate() writes it with the namespace URI, if registered
    /// with a prefix, written with the prefix: `<urn:ietf:params:imdn>.Message-ID`
    /// as `imdn.Message-ID`
    pub fn deflate(&self, name: &[u8]) -> Vec<u8> {
        if let Some((prefix, local_name)) = self.deflation(name) {
            [prefix, b".", local_name].concat()
        } else {
            name.to_vec()
        }
    }

    /// The prefix and name within the namespace of `name` as inflate() writes it
    fn deflation<'a>(&'a self, name: &'a [u8]) -> Option<(&'a [u8], &'a [u8])> {
        let end = name
            .strip_prefix(b"<")?
            .windows(2)
            .position(|w| w == b">.")?
            + 1;
        let uri = &name[1..end];
        self.registered_namespaces
            .iter()
            .find(|(k, v)| !k.is_empty() && *v == uri)
            .map(|(k, _)| (&k[..], &name[end + 2..]))
    }

    /// The namespace URI registered for `prefix`
    pub fn uri(&self, prefix: &[u8]) -> Option<&[u8]> {
        self.registered_namespaces.get(prefix).map(|v| &v[..])
    }

    /// The prefix and namespace URI an NS header's value declares, the prefix
    /// empty for a default namespace
    pub fn parse_declaration(value: &[u8]) -> Option<(&[u8], &[u8])> {
        let start = value.iter().position(|c| *c == b'<')?;
        let end = start + 1 + value[start + 1..].iter().position(|c| *c == b'>')?;
        Some((
            syntax::trim(&value[..start]),
            syntax::trim(&value[start + 1..end]),
        ))
    }

    /// A deflator, taking a header named as inflate() names it to the header
    /// named as deflate() names it and the NS header declaring the prefix:
    /// `imdn.Message-ID` and `NS: imdn <urn:ietf:params:imdn>`
    pub fn as_deflator(&'r self) -> Box<dyn Fn(&Header) -> (Option<Header>, Cow<Header>) + 'r> {
        Box::new(|header| match self.deflation(header.get_name()) {
            Some((prefix, local_name)) => {
                let uri = &self.registered_namespaces[prefix];
                (
                    Some(Header::new(b"NS", [prefix, b" <", uri, b">"].concat())),
                    Cow::Owned(Header::new(
                        [prefix, b".", local_name].concat(),
                        header.get_value().to_vec(),
                    )),
                )
            }
            None => (None, Cow::Borrowed(header)),
        })
    }
}
