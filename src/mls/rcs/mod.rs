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

//! How MLS is applied within RCS, following GSMA PRD RCC.16 (v4.0) and the
//! E2EE parts of GSMA PRD RCC.07 (v15.0)
//!
//! The interface between a client and its Home KDS is vendor specific
//! (RCC.16 section 5.1), so fetching and uploading KeyPackages is left to the caller.

pub mod certificate;
pub mod era;
pub mod file;
pub mod heal;
pub mod imdn;
pub mod key_update;
pub mod messaging;
pub mod metadata;
pub mod proto;
pub mod resend;
pub mod wire;

#[cfg(test)]
mod certificate_tests;
#[cfg(test)]
mod tests;

pub use certificate::{
    credential_tel_uris, participant_keys, same_tel_uri, x509_credential, CertificateError,
    ClientCertificate, ClientIdentity, ParticipantKey, RcsCredentialValidator,
};
pub use messaging::{DecryptedMessage, ResentFailure};
pub use wire::{ClientFailureReason, SecretPayloadType, VerifiableDerivedContent};

use crate::internet::parameter::Parameter;
use crate::internet::syntax;
use crate::util::raw_string::StrEq;

/// MIME types (RCC.16 sections 7.1, 7.8)
pub const CONTENT_TYPE_MLS: &[u8] = b"message/mls";
pub const CONTENT_TYPE_MLS_RCS_CLIENT: &[u8] = b"message/mls-rcs-client";
pub const CONTENT_TYPE_MLS_RCS_SERVER: &[u8] = b"message/mls-rcs-server";
pub const CONTENT_TYPE_MLS_RCS_FILE_INFO: &[u8] = b"message/mls-rcs-file-info";
pub const CONTENT_TYPE_MLS_FT: &[u8] = b"message/mls-ft";

/// Name of encrypted files on the HTTP Content Server (RCC.16 section 9.1.2.1)
pub const ENCRYPTED_FILE_NAME: &str = "encrypted_file";
/// FileMetadata.file_name for the keys of an encrypted group icon and subject
/// (RCC.16 sections 9.7.1.4, 9.7.1.5)
pub const GROUP_ICON_FILE_NAME: &str = "group_icon";
pub const GROUP_SUBJECT_FILE_NAME: &str = "group_subject";

/// CPIM namespace of the MLS headers (RCC.16 section 7.2)
///
/// The example in that section spells it with a trailing slash; both forms are
/// recognised when parsing.
pub const CPIM_NAMESPACE: &[u8] = b"http://www.gsma.com/rcs/mls";
pub const CPIM_NAMESPACE_PREFIX: &[u8] = b"mls";

pub const CPIM_HEADER_EPOCH_AUTHENTICATOR: &[u8] = b"Epoch-Authenticator";
pub const CPIM_HEADER_DERIVED_CONTENT_SIGNATURE: &[u8] = b"MLS-Derived-Content-Signature";
pub const CPIM_HEADER_ORIGINAL_MESSAGE_ID: &[u8] = b"Original-Message-ID";
pub const CPIM_HEADER_ERA_ID: &[u8] = b"Era-ID";

/// SIP header carrying the Conversation Focus token (RCC.16 section 6.1.3)
pub const SIP_HEADER_MLS_OPAQUE_TOKEN: &[u8] = b"MLS-Opaque-Token";
/// SIP headers in the 200 OK of the Conversation Focus (RCC.16 section 8.2.1)
pub const SIP_HEADER_MLS_EPOCH: &[u8] = b"MLS-Epoch";
pub const SIP_HEADER_MLS_ERA: &[u8] = b"MLS-Era";
/// Info-Packages for retrieving the GroupInfo with SIP INFO (RCC.16 sections 6.3.1, 6.3.2)
pub const INFO_PACKAGE_MLS_GROUP_INFO_PULL: &[u8] = b"MLS-Group-Info-Pull";
pub const INFO_PACKAGE_MLS_ENHANCED_GROUP_INFO_PULL: &[u8] = b"MLS-Enhanced-Group-Info-Pull";
/// Content-Type of the EpochIdentifier in an MLS-Enhanced-Group-Info-Pull
/// request (RCC.16 section 7.10.2)
pub const CONTENT_TYPE_MLS_RCS: &[u8] = b"message/mls-rcs";
/// Text of the SIP Warning header (warn-code 399) by which a server announces
/// that no Negative-Delivery IMDN follows its error response (RCC.16 section 7.2.6)
pub const SIP_WARNING_NON_MLS_ERROR: &[u8] = b"451 Non-MLS error";
/// SIP URI parameter carrying an encrypted user alias (RCC.16 section 9.1.5)
pub const SIP_URI_PARAMETER_ENCRYPTED_ALIAS: &[u8] = b"encrypted-alias";

/// Capability indications (RCC.07 tables 3 and 10)
pub const FEATURE_TAG_MLS_VERSION: &[u8] = b"+g.gsma.rcs.mls.mls-version";
pub const FEATURE_TAG_MLS_KDS: &[u8] = b"+g.gsma.rcs.mls.mls-kds";
/// Value of FEATURE_TAG_MLS_VERSION for this version of RCC.16
pub const MLS_VERSION_V1: &[u8] = b"v1";

/// HTTP GET parameters of the configuration request (RCC.07 section 2.3.2.2)
pub const ACS_PARAMETER_PARTICIPANT_PUBLIC_KEY: &str = "participant_public_key";
pub const ACS_PARAMETER_PARTICIPANT_KEY_SIGNED_NONCE: &str = "participant_key_signed_nonce";
pub const ACS_PARAMETER_HOME_KDS: &str = "home_kds";
/// Configuration parameter holding the ACS Signed Encryption Identity Proof
pub const ACS_CONFIG_SIGNED_ENCRYPTION_IDENTITY_PROOF: &str = "signedEncryptionIdentityProof";

/// GroupContext and GroupInfo extensions (RCC.16 section 7.11)
pub const EXTENSION_ERA: u16 = 0xF001;
pub const EXTENSION_END_MLS: u16 = 0xF002;
pub const EXTENSION_ICON_KEY: u16 = 0xF003;
pub const EXTENSION_ICON_COMMITMENT: u16 = 0xF004;
pub const EXTENSION_SUBJECT_KEY: u16 = 0xF005;
pub const EXTENSION_SUBJECT_COMMITMENT: u16 = 0xF006;
pub const EXTENSION_GROUP_METADATA_KEYS_REQUESTED: u16 = 0xF007;
pub const EXTENSION_CONTINUITY_TOKEN: u16 = 0xF010;
pub const EXTENSION_CONTINUITY_TOKEN_COMMITMENT: u16 = 0xF011;
pub const EXTENSIONS: [u16; 9] = [
    EXTENSION_ERA,
    EXTENSION_END_MLS,
    EXTENSION_ICON_KEY,
    EXTENSION_ICON_COMMITMENT,
    EXTENSION_SUBJECT_KEY,
    EXTENSION_SUBJECT_COMMITMENT,
    EXTENSION_GROUP_METADATA_KEYS_REQUESTED,
    EXTENSION_CONTINUITY_TOKEN,
    EXTENSION_CONTINUITY_TOKEN_COMMITMENT,
];
/// extension_data of the group_metadata_keys_requested GroupContext extension
pub const GROUP_METADATA_KEYS_REQUESTED: &[u8] = b"group_metadata_keys_requested";
/// Extension and proposal types reserved for future use, which clients accept
/// and carry forward (RCC.16 section 7.11.11)
pub const RESERVED_FOR_FUTURE_USE: std::ops::RangeInclusive<u16> = 0xF012..=0xF030;

/// Proposal types (RCC.16 section 7.11); 0xF001 is void since v4.0
pub const PROPOSAL_END_MLS: u16 = 0xF001;
pub const PROPOSAL_RCS_SIGNATURE: u16 = 0xF002;
pub const PROPOSAL_SELF_REMOVE: u16 = 0xF003;
pub const PROPOSAL_SERVER_REMOVE: u16 = 0xF004;
pub const PROPOSALS: [u16; 4] = [
    PROPOSAL_END_MLS,
    PROPOSAL_RCS_SIGNATURE,
    PROPOSAL_SELF_REMOVE,
    PROPOSAL_SERVER_REMOVE,
];

/// How long the secrets of past epochs are kept before being deleted (RCC.16
/// section 6.1.1)
pub const PAST_EPOCH_RETENTION: std::time::Duration = std::time::Duration::from_secs(30 * 86400);

const UNENCRYPTED_CPIM_HEADERS: [&[u8]; 13] = [
    b"To",
    b"From",
    b"DateTime",
    b"Require",
    b"<urn:ietf:params:imdn>.Message-ID",
    b"<urn:ietf:params:imdn>.Disposition-Notification",
    b"<urn:ietf:params:imdn>.Original-To",
    b"<urn:ietf:params:imdn>.IMDN-Record-Route",
    b"<urn:ietf:params:imdn>.IMDN-Route",
    b"<http://www.gsma.com/rcs>.advised-action",
    b"<http://www.gsma.com/rcs>.source",
    // only for Group Chats
    b"<http://www.gsma.com/rcs>.User-Profile-Config-Data",
    b"<http://www.gsma.com/rcs/mls>.Epoch-Authenticator",
];

/// Whether a CPIM header stays outside of the encrypted payload (RCC.16 section 7.5.7)
///
/// `inflated_name` is the header name with its namespace resolved, as produced
/// by `CPIMNamespace::as_inflator()`, e.g. `<urn:ietf:params:imdn>.Message-ID`.
pub fn is_unencrypted_cpim_header(inflated_name: &[u8]) -> bool {
    let name = match inflated_name.strip_prefix(b"<http://www.gsma.com/rcs/mls/>.") {
        Some(name) => [b"<http://www.gsma.com/rcs/mls>.", name].concat(),
        None => inflated_name.to_vec(),
    };

    UNENCRYPTED_CPIM_HEADERS
        .iter()
        .any(|h| h.equals_bytes(&name, true))
}

/// E2EE capability of a contact, from the feature tags of its Contact header
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsCapability {
    /// Version of RCC.16 supported, e.g. `v1`
    pub version: Vec<u8>,
    /// Vendor ID of the contact's Home KDS
    pub home_kds: Option<u32>,
}

impl MlsCapability {
    pub fn from_parameters<'a, I>(parameters: I) -> Option<MlsCapability>
    where
        I: IntoIterator<Item = Parameter<'a>>,
    {
        let mut version = None;
        let mut home_kds = None;

        for parameter in parameters {
            let value = parameter.value.map(syntax::unquote);
            if parameter.name.equals_bytes(FEATURE_TAG_MLS_VERSION, true) {
                version = value.map(|v| v.to_vec());
            } else if parameter.name.equals_bytes(FEATURE_TAG_MLS_KDS, true) {
                home_kds = value
                    .and_then(|v| std::str::from_utf8(v).ok())
                    .and_then(|v| v.trim().parse().ok());
            }
        }

        version.map(|version| MlsCapability { version, home_kds })
    }

    /// Feature tags to advertise this capability
    pub fn feature_tags(&self) -> Vec<String> {
        let mut tags = vec![format!(
            "{}=\"{}\"",
            String::from_utf8_lossy(FEATURE_TAG_MLS_VERSION),
            String::from_utf8_lossy(&self.version)
        )];
        if let Some(home_kds) = self.home_kds {
            tags.push(format!(
                "{}=\"{}\"",
                String::from_utf8_lossy(FEATURE_TAG_MLS_KDS),
                home_kds
            ));
        }
        tags
    }
}

/// Why the Conversation Focus rejected a Commit, Proposal or Message, as found in
/// the `<mls-server-failure-reason>` of a Negative-Delivery IMDN (RCC.16 sections
/// 6.2.5, 7.7.2.3)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerFailureReason {
    IncorrectEra,
    IncorrectEpoch,
    IncorrectEpochAuthenticator,
    ExpiredCredential,
    MismatchedRcsGroupState,
    UnparsableCommit,
    MismatchedConfirmationTag,
    PendingProposal,
    TransientError,
    EncryptionNotAvailable,
    InvalidCommit,
    InvalidInput,
    MlsGroupHasEndMls,
    MlsGroupNotFound,
    EraAdvancementQuotaReached,
    EpochAdvancementQuotaReached,
    MissingMlsControlMessage,
}

const SERVER_FAILURE_REASONS: [(ServerFailureReason, &str); 17] = [
    (ServerFailureReason::IncorrectEra, "incorrect-era"),
    (ServerFailureReason::IncorrectEpoch, "incorrect-epoch"),
    (
        ServerFailureReason::IncorrectEpochAuthenticator,
        "incorrect-epoch-authenticator",
    ),
    (ServerFailureReason::ExpiredCredential, "expired-credential"),
    (
        ServerFailureReason::MismatchedRcsGroupState,
        "mismatched-rcs-group-state",
    ),
    (ServerFailureReason::UnparsableCommit, "unparsable-commit"),
    (
        ServerFailureReason::MismatchedConfirmationTag,
        "mismatched-confirmation-tag",
    ),
    (ServerFailureReason::PendingProposal, "pending-proposal"),
    (ServerFailureReason::TransientError, "transient-error"),
    (
        ServerFailureReason::EncryptionNotAvailable,
        "encryption-not-available",
    ),
    (ServerFailureReason::InvalidCommit, "invalid-commit"),
    (ServerFailureReason::InvalidInput, "invalid-input"),
    (
        ServerFailureReason::MlsGroupHasEndMls,
        "mls-group-has-end-mls",
    ),
    (ServerFailureReason::MlsGroupNotFound, "mls-group-not-found"),
    (
        ServerFailureReason::EraAdvancementQuotaReached,
        "era-advancement-quota-reached",
    ),
    (
        ServerFailureReason::EpochAdvancementQuotaReached,
        "epoch-advancement-quota-reached",
    ),
    (
        ServerFailureReason::MissingMlsControlMessage,
        "missing-mls-control-message",
    ),
];

impl ServerFailureReason {
    /// Name of the XML element inside `<mls-server-failure-reason>`
    pub fn xml_name(&self) -> &'static str {
        SERVER_FAILURE_REASONS
            .iter()
            .find(|(reason, _)| reason == self)
            .map(|(_, name)| *name)
            .unwrap_or_default()
    }

    pub fn from_xml_name(name: &[u8]) -> Option<ServerFailureReason> {
        SERVER_FAILURE_REASONS
            .iter()
            .find(|(_, n)| n.as_bytes() == name)
            .map(|(reason, _)| *reason)
    }
}
