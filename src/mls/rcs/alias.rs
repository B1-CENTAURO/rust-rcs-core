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

//! User aliases encrypted for a group, which SIP URIs carry in their
//! `encrypted-alias` parameter in place of the display name RCC.07 has
//! them in (RCC.16 section 9.1.5, RCC.07 section 2.5.3.3)

use base64::alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::Engine as _;
use openmls::prelude::*;

use super::super::client::MlsClient;
use super::super::conversation::{IncomingMessage, MlsConversation};
use super::super::{ErrorKind, Result};
use super::SIP_URI_PARAMETER_ENCRYPTED_ALIAS;
use crate::internet::parameter::ParameterParser;

/// Base64 URL encoding, without the padding a URI parameter could not carry
/// unescaped (RFC 4648 section 5, RFC 3261 section 25.1)
const URL_SAFE: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// As URL_SAFE, in the standard alphabet, which RCC.16's own example is in
const STANDARD: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// The value of the `encrypted-alias` parameter among `uri_parameters`, the
/// parameters of a SIP URI after its first semicolon, as a name-addr gives
/// them; None if there is none, or it is empty
pub fn encrypted_alias(uri_parameters: &[u8]) -> Option<&[u8]> {
    ParameterParser::new(uri_parameters, b';', false)
        .find(|parameter| {
            parameter
                .name
                .eq_ignore_ascii_case(SIP_URI_PARAMETER_ENCRYPTED_ALIAS)
        })
        .and_then(|parameter| parameter.value)
        .filter(|value| !value.is_empty())
}

impl MlsConversation {
    /// `alias` encrypted for the group, in its current epoch: a
    /// PrivateMessage of it, padded as PADME prescribes, Base64 URL encoded,
    /// for the `encrypted-alias` parameter of a SIP URI (RCC.16 section 9.1.5)
    ///
    /// It takes a generation of the client's keys, as a message does. One
    /// made while a Commit of the client is pending is in the epoch before
    /// it, which those the Commit adds cannot decrypt.
    pub fn encrypt_alias(&mut self, client: &MlsClient, alias: &str) -> Result<String> {
        let message = self.encrypt(client, alias.as_bytes())?;
        Ok(URL_SAFE.encode(message))
    }

    /// The alias the `encrypted-alias` parameter `encoded` carries, decrypted
    /// in the group (RCC.16 section 9.1.5), with the credential of the member
    /// who encrypted it
    ///
    /// `encoded` may be in either Base64 alphabet, padded or not. It is
    /// refused as BadFormat if it is not Base64, or its alias not UTF-8, and
    /// as UnexpectedMessage if it is not an application message. Like any
    /// application message, it decrypts once, in an epoch the group still has
    /// the secrets of.
    pub fn decrypt_alias(
        &mut self,
        client: &MlsClient,
        encoded: &[u8],
    ) -> Result<(Credential, String)> {
        let message = URL_SAFE
            .decode(encoded)
            .or_else(|_| STANDARD.decode(encoded))
            .map_err(|_| ErrorKind::BadFormat)?;
        let message = self.decode(&message)?;
        if message.content_type() != ContentType::Application {
            return Err(ErrorKind::UnexpectedMessage);
        }
        match self.process_protocol_message(client, message)? {
            IncomingMessage::Application { sender, data, .. } => {
                let alias = String::from_utf8(data).map_err(|_| ErrorKind::BadFormat)?;
                Ok((sender, alias))
            }
            _ => Err(ErrorKind::UnexpectedMessage),
        }
    }
}
