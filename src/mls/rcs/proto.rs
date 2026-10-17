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

//! Protocol Buffer messages of RCC.16 (sections 7.8.1 and 7.9.1)

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
    /// Declared as `fixedint32` in RCC.16, which is taken to mean `fixed32`
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

/// Body of `message/mls-rcs-server`
#[derive(Clone, PartialEq, prost::Message)]
pub struct ServerMlsRcsMessage {
    #[prost(oneof = "server_mls_rcs_message::Payload", tags = "1, 2, 3")]
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
