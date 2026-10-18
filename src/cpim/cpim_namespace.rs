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

/// The namespace of the core headers, From, To, NS and the others of RFC 3862
/// section 4
pub const CORE_NAMESPACE: &[u8] = b"urn:ietf:params:cpim-headers:";

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

    /// `name` with its namespace written out as the namespace URI:
    /// `imdn.Message-ID` as `<urn:ietf:params:imdn>.Message-ID`. A name with
    /// no prefix is in the default namespace, registered with an empty prefix,
    /// if any (RFC 3862 section 3.4). A name in the core namespace is written
    /// without one, as is NS, taken to declare namespaces whatever the default.
    pub fn inflate(&self, name: &[u8]) -> Vec<u8> {
        if name == b"NS" {
            return name.to_vec();
        }

        let (prefix, local_name) = match name.iter().position(|c| *c == b'.') {
            Some(position) => (&name[..position], &name[position + 1..]),
            None => (&name[..0], name),
        };

        match self.registered_namespaces.get(prefix) {
            Some(uri) if &uri[..] != CORE_NAMESPACE => [b"<", &uri[..], b">.", local_name].concat(),
            Some(_) => local_name.to_vec(),
            None => name.to_vec(),
        }
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
        let (uri, local_name) = Self::split_inflated(name)?;
        self.registered_namespaces
            .iter()
            .find(|(k, v)| !k.is_empty() && *v == uri)
            .map(|(k, _)| (&k[..], local_name))
    }

    /// The namespace URI and the name within the namespace of `name` as
    /// inflate() writes it
    pub(crate) fn split_inflated(name: &[u8]) -> Option<(&[u8], &[u8])> {
        let end = name
            .strip_prefix(b"<")?
            .windows(2)
            .position(|w| w == b">.")?
            + 1;
        Some((&name[1..end], &name[end + 2..]))
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
