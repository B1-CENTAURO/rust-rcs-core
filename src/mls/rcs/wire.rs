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

/// Type of a SecretPayload; 3 is deprecated and not to be reused
#[derive(Clone, Copy, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u16)]
pub enum SecretPayloadType {
    /// A CPIM message
    Application = 1,
    /// A Re-Sent Message after a Fail to Decrypt (RCC.16 section 10.3)
    Hpke1To1Message = 2,
    /// Keys of the group icon and subject, and the continuity token (RCC.16
    /// section 7.13.4)
    GroupMetadataKeys = 4,
}

/// Plaintext of an encrypted message (RCC.16 section 7.5.1.1)
#[derive(Clone, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct SecretPayload {
    version: Version,
    pub payload_type: SecretPayloadType,
    /// Generation of the key encrypting the PrivateMessage this is the content of
    pub key_generation: u32,
    /// The CPIM message, without its unencrypted headers, or what
    /// `payload_type` says
    pub payload: VLBytes,
}

impl SecretPayload {
    pub fn new(
        payload_type: SecretPayloadType,
        key_generation: u32,
        payload: Vec<u8>,
    ) -> SecretPayload {
        SecretPayload {
            version: Version::V1,
            payload_type,
            key_generation,
            payload: payload.into(),
        }
    }
}

/// Content signed or authenticated next to a message (RCC.16 sections 7.5.3.2,
/// 7.5.3.3)
///
/// RCC.16 v4.0 leaves out the code points of VerifiableDerivedContentType; these
/// are numbered in the order of the select.
#[derive(Clone, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u16)]
pub enum VerifiableDerivedContent {
    #[tls_codec(discriminant = 0)]
    None,
    #[tls_codec(discriminant = 1)]
    DeliveryImdn(VerifiableDeliveryImdn),
    #[tls_codec(discriminant = 2)]
    DisplayImdn(VerifiableDisplayImdn),
    #[tls_codec(discriminant = 3)]
    ResentMessage(VerifiableResentMessage),
}

/// authenticated_data of encrypted and signed messages (RCC.16 section 7.5.3.2)
#[derive(Clone, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct AuthenticatedData {
    version: Version,
    /// IMDN Message-ID of the enclosing CPIM message
    pub message_id: VLBytes,
    /// Message-ID of the Original Message of a Re-Sent Message, or empty
    pub original_message_id: VLBytes,
    pub era_id: u32,
    pub verifiable_derived_content: VerifiableDerivedContent,
}

impl AuthenticatedData {
    pub fn new(
        message_id: &[u8],
        original_message_id: &[u8],
        era_id: u32,
        verifiable_derived_content: VerifiableDerivedContent,
    ) -> AuthenticatedData {
        AuthenticatedData {
            version: Version::V1,
            message_id: message_id.into(),
            original_message_id: original_message_id.into(),
            era_id,
            verifiable_derived_content,
        }
    }
}

/// Inner content of a Re-Sent Message (RCC.16 section 7.5.4)
#[derive(Clone, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct ResentMessage {
    pub original_message: VLBytes,
    pub padding: VLBytes,
}

/// HPKE encryption of a ResentMessage to one client (RCC.16 Annex C.4.1)
#[derive(Clone, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct HpkeInnerEncapsulatedKeyAndCiphertext {
    pub receiver_leaf_index: u32,
    pub encapsulated_key: VLBytes,
    pub ciphertext: VLBytes,
    /// hmac_key followed by hmac_tag, the HMAC of the Original Message (RCC.16
    /// Annex C.4.3)
    pub original_message_hmac: VLBytes,
}

/// RCC.16 v4.0 only lists delivered and error; failed and forbidden keep their
/// v3.0 values, as Negative-Delivery IMDNs need failed
#[derive(Clone, Copy, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u16)]
pub enum DeliveryNotificationStatus {
    Delivered = 1,
    Failed = 2,
    Forbidden = 3,
    Error = 4,
}

/// Why a client rejected a message, as carried in the `<mls-client-failure-reason>`
/// of a Negative-Delivery IMDN (RCC.16 sections 6.2.7, 7.6.3.2, 7.7.2.3)
///
/// RCC.16 v4.0 leaves 4 out of the enum while keeping `<failed-to-decrypt>` in
/// the XML schema; it keeps its v3.0 value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u16)]
pub enum ClientFailureReason {
    Unset = 0,
    MessageFromNonMember = 1,
    InvalidCredential = 2,
    InvalidCommit = 3,
    FailureToDecrypt = 4,
    CommitInPrivateMessage = 5,
    InnerResentMessageFailureToDecrypt = 6,
    CommitProcessedInEnhancedSelfHeal = 7,
    CommitProcessedInSelfHeal = 8,
    CommitFailedThenEraAdvancement = 9,
    ControlMessageFailedDueToDowngrade = 10,
    ProposalProcessedInEnhancedSelfHeal = 11,
    ProposalProcessedInSelfHeal = 12,
    ControlMessageFailed = 13,
}

/// XML names of the schema in section 7.7.2.3, then the other spellings found
/// in RCC.16 v4.0, only recognised
const CLIENT_FAILURE_REASONS: [(ClientFailureReason, &str); 15] = [
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
    (
        ClientFailureReason::InnerResentMessageFailureToDecrypt,
        "inner-resent-message-failed-to-decrypt",
    ),
    (
        ClientFailureReason::CommitProcessedInEnhancedSelfHeal,
        "commit-processed-in-enhanced-self-heal",
    ),
    (
        ClientFailureReason::CommitProcessedInSelfHeal,
        "commit-processed-in-self-heal",
    ),
    (
        ClientFailureReason::CommitFailedThenEraAdvancement,
        "commit-failed-then-era-advancement",
    ),
    (
        ClientFailureReason::ControlMessageFailedDueToDowngrade,
        "control-message-failed-due-to-downgrade",
    ),
    (
        ClientFailureReason::ProposalProcessedInEnhancedSelfHeal,
        "proposal-processed-in-enhanced-self-heal",
    ),
    (
        ClientFailureReason::ProposalProcessedInSelfHeal,
        "proposal-processed-in-self-heal",
    ),
    (
        ClientFailureReason::ControlMessageFailed,
        "control-message-failed",
    ),
    // sections 6.2.7 and 10.2
    (
        ClientFailureReason::InnerResentMessageFailureToDecrypt,
        "inner-resent-message-decrypt",
    ),
    (
        ClientFailureReason::InnerResentMessageFailureToDecrypt,
        "hpke-fail-to-decrypt",
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

/// Signed content of Positive- and Negative-Delivery IMDNs (RCC.16 section 7.5.3.2)
///
/// Section 7.6.3.2 still shows the v3.0 layout with a single message_id; this
/// follows the AuthenticatedData of section 7.5.3.2 and its illustration.
#[derive(Clone, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct VerifiableDeliveryImdn {
    version: Version,
    pub delivery_notification_status: DeliveryNotificationStatus,
    /// Message-ID of the message the IMDN is for, the `<imdn><message-id>`
    pub content_message_id: VLBytes,
    /// Message-ID of the Original Message when that one was re-sent, or empty
    pub original_content_message_id: VLBytes,
    pub mls_client_failure_reason: ClientFailureReason,
}

impl VerifiableDeliveryImdn {
    pub fn new(
        status: DeliveryNotificationStatus,
        content_message_id: &[u8],
        original_content_message_id: &[u8],
        failure_reason: ClientFailureReason,
    ) -> VerifiableDeliveryImdn {
        VerifiableDeliveryImdn {
            version: Version::V1,
            delivery_notification_status: status,
            content_message_id: content_message_id.into(),
            original_content_message_id: original_content_message_id.into(),
            mls_client_failure_reason: failure_reason,
        }
    }
}

/// RCC.16 v4.0 only lists displayed and error; forbidden keeps its v3.0 value
#[derive(Clone, Copy, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u16)]
pub enum DisplayNotificationStatus {
    Displayed = 1,
    Forbidden = 2,
    Error = 3,
}

/// Signed content of Display IMDNs (RCC.16 section 7.5.3.2)
#[derive(Clone, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct VerifiableDisplayImdn {
    version: Version,
    pub display_notification_status: DisplayNotificationStatus,
    pub content_message_id: VLBytes,
    pub original_content_message_id: VLBytes,
}

impl VerifiableDisplayImdn {
    pub fn new(
        status: DisplayNotificationStatus,
        content_message_id: &[u8],
        original_content_message_id: &[u8],
    ) -> VerifiableDisplayImdn {
        VerifiableDisplayImdn {
            version: Version::V1,
            display_notification_status: status,
            content_message_id: content_message_id.into(),
            original_content_message_id: original_content_message_id.into(),
        }
    }
}

/// Authenticated content of Re-Sent Messages (RCC.16 section 7.5.3.2)
#[derive(Clone, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct VerifiableResentMessage {
    version: Version,
    pub original_content_message_id: VLBytes,
}

impl VerifiableResentMessage {
    pub fn new(original_content_message_id: &[u8]) -> VerifiableResentMessage {
        VerifiableResentMessage {
            version: Version::V1,
            original_content_message_id: original_content_message_id.into(),
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
