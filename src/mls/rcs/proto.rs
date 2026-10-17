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

//! Protocol Buffer messages of RCC.16 (sections 7.8.1, 7.9.1, 7.10 and 7.11.2)

use prost::Message;

use super::super::{fail, ErrorKind, Result};

pub fn encode<M: Message>(message: &M) -> Vec<u8> {
    message.encode_to_vec()
}

pub fn decode<M: Message + Default>(bytes: &[u8]) -> Result<M> {
    M::decode(bytes).map_err(fail("protobuf decoding", ErrorKind::BadFormat))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum Algorithm {
    Unspecified = 0,
    Aes256CtrHmacSha256256tag = 1,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct FileEncryptionInfo {
    #[prost(bytes = "vec", tag = "1")]
    pub key_material: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub initialization_vector: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub hmac_tag: Vec<u8>,
    #[prost(enumeration = "Algorithm", tag = "4")]
    pub algorithm: i32,
    /// Dropped from the message by RCC.16 v4.0 while Annex C.3 still checks it;
    /// kept for files from v3.0 clients, 0 when absent. Declared as `fixedint32`
    /// in v3.0, which is taken to mean `fixed32`.
    #[prost(fixed32, tag = "5")]
    pub file_length_hint: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct FileMetadata {
    #[prost(string, tag = "1")]
    pub file_name: String,
    #[prost(string, tag = "2")]
    pub content_type: String,
    #[prost(message, optional, tag = "3")]
    pub encryption_info: Option<FileEncryptionInfo>,
}

/// Body of `message/mls-rcs-file-info` payloads
#[derive(Clone, PartialEq, prost::Message)]
pub struct FileInfo {
    #[prost(message, optional, tag = "1")]
    pub file: Option<FileMetadata>,
    #[prost(message, optional, tag = "2")]
    pub thumbnail: Option<FileMetadata>,
    #[prost(message, optional, tag = "3")]
    pub subject: Option<FileMetadata>,
    #[prost(message, optional, tag = "4")]
    pub icon: Option<FileMetadata>,
}

/// Keys of the encrypted group icon and subject, and the continuity token, in a
/// group_metadata_keys SecretPayload (RCC.16 section 7.13.4)
///
/// RCC.16 v4.0 cuts the definition off after these two fields.
#[derive(Clone, PartialEq, prost::Message)]
pub struct GroupMetadataKeys {
    #[prost(bytes = "vec", tag = "1")]
    pub continuity_token: Vec<u8>,
    /// FileInfo with the icon and subject fields set
    #[prost(message, optional, tag = "2")]
    pub group_subject_icon_keys: Option<FileInfo>,
}

/// Commit that adds Clients or starts an Era, with its Welcome
#[derive(Clone, PartialEq, prost::Message)]
pub struct WelcomeCommitBundle {
    /// CommitList TLS structure
    #[prost(bytes = "vec", tag = "1")]
    pub commit_list: Vec<u8>,
    /// MlsMessage holding a Welcome
    #[prost(bytes = "vec", tag = "2")]
    pub welcome: Vec<u8>,
    /// MlsMessage holding the GroupInfo after the Commit
    #[prost(bytes = "vec", tag = "3")]
    pub group_info: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub epoch_authenticator: Vec<u8>,
    /// Only for the first Commit of an Era
    #[prost(bytes = "vec", tag = "5")]
    pub ratchet_tree: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct CommitBundle {
    /// CommitList TLS structure
    #[prost(bytes = "vec", tag = "1")]
    pub commit_list: Vec<u8>,
    /// MlsMessage holding a PrivateMessage delivered together with the Commit
    #[prost(bytes = "vec", tag = "2")]
    pub private_message: Vec<u8>,
    /// MlsMessage holding the GroupInfo after the Commit
    #[prost(bytes = "vec", tag = "3")]
    pub group_info: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub epoch_authenticator: Vec<u8>,
}

/// Commit accepted and forwarded by the Conversation Focus
#[derive(Clone, PartialEq, prost::Message)]
pub struct ServerCommitBundle {
    /// CommitList TLS structure
    #[prost(bytes = "vec", tag = "1")]
    pub commit_list: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub welcome: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub private_message: Vec<u8>,
    /// Ratchet tree for the members joining through `welcome`
    #[prost(bytes = "vec", tag = "4")]
    pub ratchet_tree: Vec<u8>,
}

/// Acknowledgement of a `message/mls-rcs-client` the Conversation Focus accepted
#[derive(Clone, PartialEq, prost::Message)]
pub struct AcceptedMlsRcsMessage {
    /// Message-ID of the CPIM message that carried it
    #[prost(string, tag = "1")]
    pub message_id: String,
    /// Epoch the accepted message was sent in
    #[prost(message, optional, tag = "2")]
    pub previous_epoch_identifier: Option<EpochIdentifier>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct EpochIdentifier {
    #[prost(uint32, tag = "1")]
    pub era_id: u32,
    #[prost(uint64, tag = "2")]
    pub epoch_id: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub epoch_authenticator: Vec<u8>,
}

/// State kept by the Conversation Focus, used for self-healing
#[derive(Clone, PartialEq, prost::Message)]
pub struct MlsGroupInfo {
    /// MlsMessage holding the latest GroupInfo
    #[prost(bytes = "vec", tag = "1")]
    pub group_info: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub ratchet_tree: Vec<u8>,
    /// ProposalList TLS structure of accepted, not yet committed Proposals
    #[prost(bytes = "vec", tag = "3")]
    pub pending_proposals: Vec<u8>,
}

/// Control messages the Conversation Focus accepted in one epoch
#[derive(Clone, PartialEq, prost::Message)]
pub struct EpochControlMessages {
    #[prost(string, tag = "1")]
    pub rcs_message_id: String,
    #[prost(message, optional, tag = "2")]
    pub server_mls_rcs_message: Option<ServerMlsRcsMessage>,
}

/// Response to an MLS-Enhanced-Group-Info-Pull INFO request (RCC.16 section 7.10.5)
#[derive(Clone, PartialEq, prost::Message)]
pub struct MlsEnhancedGroupInfo {
    #[prost(message, optional, tag = "2")]
    pub latest_epoch_identifier: Option<EpochIdentifier>,
    #[prost(message, optional, tag = "3")]
    pub mls_group_info: Option<MlsGroupInfo>,
    /// Control messages committed since the epoch given in the request
    #[prost(message, repeated, tag = "4")]
    pub committed_control_messages: Vec<EpochControlMessages>,
    /// Epoch reached after applying `committed_control_messages`
    #[prost(message, optional, tag = "5")]
    pub paginated_epoch_identifier: Option<EpochIdentifier>,
}

/// Body of `message/mls-rcs-server`
#[derive(Clone, PartialEq, prost::Message)]
pub struct ServerMlsRcsMessage {
    #[prost(oneof = "server_mls_rcs_message::Payload", tags = "1, 2, 3, 4")]
    pub payload: Option<server_mls_rcs_message::Payload>,
}

pub mod server_mls_rcs_message {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Payload {
        /// ProposalList TLS structure
        #[prost(bytes, tag = "1")]
        ProposalList(Vec<u8>),
        #[prost(message, tag = "2")]
        ServerCommitBundle(super::ServerCommitBundle),
        #[prost(message, tag = "3")]
        MlsGroupInfo(super::MlsGroupInfo),
        #[prost(message, tag = "4")]
        AcceptedMlsRcsMessage(super::AcceptedMlsRcsMessage),
    }
}

/// Body of `message/mls-rcs-client`
#[derive(Clone, PartialEq, prost::Message)]
pub struct ClientMlsRcsMessage {
    #[prost(oneof = "client_mls_rcs_message::Payload", tags = "1, 2, 3")]
    pub payload: Option<client_mls_rcs_message::Payload>,
}

pub mod client_mls_rcs_message {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Payload {
        /// ProposalList TLS structure
        #[prost(bytes, tag = "1")]
        ProposalList(Vec<u8>),
        #[prost(message, tag = "2")]
        WelcomeCommitBundle(super::WelcomeCommitBundle),
        #[prost(message, tag = "3")]
        CommitBundle(super::CommitBundle),
    }
}

/// Why a client moved a conversation to unencrypted (RCC.16 section 7.11.2.2)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum EndMlsReason {
    Unset = 0,
    ServerFailureEncryptionNotAvailable = 1,
    ClientFailureEncryptionNotAvailable = 2,
    GroupMemberFailsCapabilitiesCheck = 3,
    UntrustedRootOnOtherGroupMember = 4,
    ContinuityTokenMismatch = 5,
    ContinuityTokenNotReceived = 6,
    PersistentRefreshFailure = 7,
    CannotFetchKeypackages = 8,
    InternalClientError = 9,
    OutgoingCommitFailed = 10,
    ServerFailureEraAdvancementQuotaReached = 11,
}

/// extension_data of the end_mls GroupContext extension
#[derive(Clone, PartialEq, prost::Message)]
pub struct EndMlsMetadata {
    #[prost(enumeration = "EndMlsReason", tag = "1")]
    pub downgrade_reason: i32,
}
