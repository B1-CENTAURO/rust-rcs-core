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

/// A CPIM header value and the parameters before it, as in
/// `Subject:;lang=fr Objet de message` (RFC 3862 section 3.3)
pub struct CPIMHeaderValue<'a> {
    /// The parameters, as name and value, a quoted value with its quotes
    pub parameters: Vec<(&'a [u8], &'a [u8])>,

    /// The value, its escapes not decoded; see unescape()
    pub value: &'a [u8],
}

impl<'a> CPIMHeaderValue<'a> {
    /// Splits what follows a header's colon into its parameters and value
    pub fn parse(data: &'a [u8]) -> CPIMHeaderValue<'a> {
        let mut parameters = Vec::new();
        let mut rest = data;

        while rest.starts_with(b";") {
            // a parameter runs to the next ";" or space outside of quotes
            let mut i = 1;
            let mut quoted = false;
            while i < rest.len() {
                match rest[i] {
                    b'"' => quoted = !quoted,
                    b'\\' if quoted => i = i + 1,
                    b';' | b' ' if !quoted => break,
                    _ => {}
                }
                i = i + 1;
            }
            let i = i.min(rest.len());

            let parameter = &rest[1..i];
            match parameter.iter().position(|c| *c == b'=') {
                Some(position) => {
                    parameters.push((&parameter[..position], &parameter[position + 1..]))
                }
                None => parameters.push((parameter, &parameter[parameter.len()..])),
            }

            rest = &rest[i..];
        }

        CPIMHeaderValue {
            parameters,
            value: rest.strip_prefix(b" ").unwrap_or(rest),
        }
    }

    /// The language of the value, from its lang parameter
    pub fn lang(&self) -> Option<&'a [u8]> {
        self.parameters
            .iter()
            .find(|(name, _)| *name == b"lang")
            .map(|(_, value)| *value)
    }
}

/// `value` with the escapes of RFC 3862 section 2.3 decoded, for text such as
/// a Subject. A structured value, such as a From with a quoted name, is to be
/// parsed before its text is decoded.
pub fn unescape(value: &[u8]) -> Cow<'_, [u8]> {
    if !value.contains(&b'\\') {
        return Cow::Borrowed(value);
    }

    let mut unescaped = Vec::with_capacity(value.len());
    let mut i = 0;
    while i < value.len() {
        if value[i] != b'\\' {
            unescaped.push(value[i]);
            i = i + 1;
            continue;
        }

        // a backslash ending the value is ignored
        if i + 1 == value.len() {
            break;
        }

        match value[i + 1] {
            b'b' => unescaped.push(0x08),
            b't' => unescaped.push(b'\t'),
            b'n' => unescaped.push(b'\n'),
            b'r' => unescaped.push(b'\r'),
            b'u' if hex4(&value[i + 2..]).is_some() => {
                let mut code = hex4(&value[i + 2..]).unwrap();
                let mut length = 6;
                // a surrogate pair, as Java escapes a character past U+FFFF
                if (0xd800..0xdc00).contains(&code) && value[i + 6..].starts_with(b"\\u") {
                    if let Some(low) = hex4(&value[i + 8..]) {
                        if (0xdc00..0xe000).contains(&low) {
                            code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
                            length = 12;
                        }
                    }
                }
                let c = char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER);
                unescaped.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
                i = i + length;
                continue;
            }
            // \\, \", \' and any escape not known: the character escaped
            c => unescaped.push(c),
        }
        i = i + 2;
    }

    Cow::Owned(unescaped)
}

/// The number written by the four hexadecimal digits `data` starts with
fn hex4(data: &[u8]) -> Option<u32> {
    let digits = data.get(..4)?;
    if digits.iter().all(u8::is_ascii_hexdigit) {
        u32::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()
    } else {
        None
    }
}
