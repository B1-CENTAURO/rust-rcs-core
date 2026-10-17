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

//! Binary structures of RCC.16, in the TLS presentation language with the
//! variable length vectors of RFC 9420 (RCC.16 section 7.3)

use openmls::prelude::{Ciphersuite, MlsMessageIn};
use openmls_traits::crypto::OpenMlsCrypto;
use tls_codec::{
    Deserialize, DeserializeBytes, Serialize, TlsDeserialize, TlsSerialize, TlsSize, VLByteSlice,
    VLBytes,
};

use super::super::{fail, ErrorKind, Result};

/// Version tag shared by all RCC.16 structures; only v1 is defined
#[derive(Clone, Copy, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u16)]
pub enum Version {
    V1 = 1,
}

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    value
        .tls_serialize_detached()
        .map_err(fail("TLS encoding", ErrorKind::BadFormat))
}

pub fn decode<T: Deserialize>(bytes: &[u8]) -> Result<T> {
    T::tls_deserialize_exact(bytes).map_err(fail("TLS decoding", ErrorKind::BadFormat))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u16)]
pub enum SecretPayloadType {
    Application = 1,
    /// A Re-Sent Message after a Fail to Decrypt (RCC.16 section 10.3)
    Hpke1To1Message = 2,
}

/// Plaintext of an encrypted message (RCC.16 section 7.5.1.1)
#[derive(Clone, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct SecretPayload {
    version: Version,
    pub payload_type: SecretPayloadType,
    /// The CPIM message, without its unencrypted headers
    pub payload: VLBytes,
}

impl SecretPayload {
    pub fn new(payload_type: SecretPayloadType, payload: Vec<u8>) -> SecretPayload {
        SecretPayload {
            version: Version::V1,
            payload_type,
            payload: payload.into(),
        }
    }
}

/// authenticated_data of encrypted messages (RCC.16 section 7.5.3.2)
#[derive(Clone, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct AuthenticatedData {
    version: Version,
    /// IMDN Message-ID of the enclosing CPIM message
    pub message_id: VLBytes,
    pub original_message_id: VLBytes,
    pub era_id: u32,
}

impl AuthenticatedData {
    pub fn new(message_id: &[u8], original_message_id: &[u8], era_id: u32) -> AuthenticatedData {
        AuthenticatedData {
            version: Version::V1,
            message_id: message_id.into(),
            original_message_id: original_message_id.into(),
            era_id,
        }
    }
}

/// Inner content of a Re-Sent Message (RCC.16 section 7.5.4)
#[derive(Clone, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct ResentMessage {
    pub original_message: VLBytes,
    pub padding: VLBytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u16)]
pub enum DeliveryNotificationStatus {
    Delivered = 1,
    Failed = 2,
    Forbidden = 3,
    Error = 4,
}

/// Why a client rejected a message, as carried in the `<mls-client-failure-reason>`
/// of a Negative-Delivery IMDN (RCC.16 sections 6.2.6, 7.6.3.2)
#[derive(Clone, Copy, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u16)]
pub enum ClientFailureReason {
    Unset = 0,
    MessageFromNonMember = 1,
    InvalidCredential = 2,
    InvalidCommit = 3,
    FailureToDecrypt = 4,
    CommitInPrivateMessage = 5,
}

const CLIENT_FAILURE_REASONS: [(ClientFailureReason, &str); 5] = [
    (
        ClientFailureReason::MessageFromNonMember,
        "message-from-non-member",
    ),
    (ClientFailureReason::InvalidCredential, "invalid-credential"),
    (ClientFailureReason::InvalidCommit, "invalid-commit"),
    (ClientFailureReason::FailureToDecrypt, "failed-to-decrypt"),
    (
        ClientFailureReason::CommitInPrivateMessage,
        "commit-in-privatemessage",
    ),
];

impl ClientFailureReason {
    /// Name of the XML element inside `<mls-client-failure-reason>`; None for Unset
    pub fn xml_name(&self) -> Option<&'static str> {
        CLIENT_FAILURE_REASONS
            .iter()
            .find(|(reason, _)| reason == self)
            .map(|(_, name)| *name)
    }

    pub fn from_xml_name(name: &[u8]) -> Option<ClientFailureReason> {
        CLIENT_FAILURE_REASONS
            .iter()
            .find(|(_, n)| n.as_bytes() == name)
            .map(|(reason, _)| *reason)
    }
}

/// Signed content of Positive- and Negative-Delivery IMDNs (RCC.16 section 7.6.3.2)
#[derive(Clone, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct VerifiableDeliveryImdn {
    version: Version,
    pub delivery_notification_status: DeliveryNotificationStatus,
    pub message_id: VLBytes,
    pub mls_client_failure_reason: ClientFailureReason,
}

impl VerifiableDeliveryImdn {
    pub fn new(
        status: DeliveryNotificationStatus,
        message_id: &[u8],
        failure_reason: ClientFailureReason,
    ) -> VerifiableDeliveryImdn {
        VerifiableDeliveryImdn {
            version: Version::V1,
            delivery_notification_status: status,
            message_id: message_id.into(),
            mls_client_failure_reason: failure_reason,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u16)]
pub enum DisplayNotificationStatus {
    Displayed = 1,
    Forbidden = 2,
    Error = 3,
}

/// Signed content of Display IMDNs (RCC.16 section 7.6.3.3)
#[derive(Clone, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct VerifiableDisplayImdn {
    version: Version,
    pub display_notification_status: DisplayNotificationStatus,
    pub message_id: VLBytes,
}

impl VerifiableDisplayImdn {
    pub fn new(status: DisplayNotificationStatus, message_id: &[u8]) -> VerifiableDisplayImdn {
        VerifiableDisplayImdn {
            version: Version::V1,
            display_notification_status: status,
            message_id: message_id.into(),
        }
    }
}

/// Signed content of Group RCS Video Chat signalling (RCC.16 section 7.6.3.4)
#[derive(Clone, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct VerifiableVideoChatMessage {
    version: Version,
    /// VideoChatMessage protocol buffer
    pub video_chat_message: VLBytes,
    pub message_id: VLBytes,
}

impl VerifiableVideoChatMessage {
    pub fn new(video_chat_message: &[u8], message_id: &[u8]) -> VerifiableVideoChatMessage {
        VerifiableVideoChatMessage {
            version: Version::V1,
            video_chat_message: video_chat_message.into(),
            message_id: message_id.into(),
        }
    }
}

/// Encodes a ProposalList or CommitList (RCC.16 section 7.9.1) of complete MlsMessages
pub fn encode_message_list(messages: &[&[u8]]) -> Result<Vec<u8>> {
    encode(&VLBytes::new(messages.concat()))
}

/// Splits a ProposalList or CommitList into its MlsMessages
pub fn decode_message_list(list: &[u8]) -> Result<Vec<Vec<u8>>> {
    let content: VLBytes = decode(list)?;

    let mut messages = Vec::new();
    let mut rest = content.as_slice();
    while !rest.is_empty() {
        let (_, remainder) = MlsMessageIn::tls_deserialize_bytes(rest)
            .map_err(fail("message list decoding", ErrorKind::BadFormat))?;
        let (message, remainder_start) = rest.split_at(rest.len() - remainder.len());
        messages.push(message.to_vec());
        rest = remainder_start;
    }

    Ok(messages)
}

#[derive(TlsSerialize, TlsSize)]
struct HashContent<'a> {
    label: VLByteSlice<'a>,
    value: VLByteSlice<'a>,
}

/// Commitment to a value (RCC.16 Annex C.1), hashed as the group's Cipher Suite prescribes
pub fn commitment(
    crypto: &impl OpenMlsCrypto,
    ciphersuite: Ciphersuite,
    label: &[u8],
    value: &[u8],
) -> Result<Vec<u8>> {
    let content = encode(&HashContent {
        label: VLByteSlice(label),
        value: VLByteSlice(value),
    })?;

    crypto
        .hash(ciphersuite.hash_algorithm(), &content)
        .map_err(fail("commitment hashing", ErrorKind::Crypto))
}
