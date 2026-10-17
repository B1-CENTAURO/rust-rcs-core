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

//! Encrypted group icon and subject, the continuity token, and recovering their
//! keys (RCC.16 sections 7.11.3 to 7.11.12, 7.13.4, 8.3.1, 9.7.1, 10.5)
//!
//! The keys and the token of a group are kept by group id next to the state of
//! the group, and outlive it, from one Era to the next, until
//! `MlsClient::forget_group_metadata()`.
//!
//! The extension_data of the icon_key and subject_key extensions is a FileInfo
//! with the icon or subject field set, as for the keys sent in a
//! group_metadata_keys SecretPayload; section 9.7.1.1.2 has a bare FileMetadata
//! for icon_key, which is accepted as well.

use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::{Ciphersuite, Extension, MlsMessageBodyIn, MlsMessageIn, UnknownExtension};
use openmls_traits::{random::OpenMlsRand, OpenMlsProvider};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize, VLByteSlice, VLBytes};

use super::super::client::MlsClient;
use super::super::conversation::{CommitExtras, CommitOutput, IncomingMessage, MlsConversation};
use super::super::{fail, ErrorKind, Result};
use super::file::{self, EncryptedFile};
use super::proto::{self, FileInfo, FileMetadata, GroupMetadataKeys};
use super::wire::{self, AuthenticatedData, SecretPayload, SecretPayloadType};
use super::{
    EXTENSION_CONTINUITY_TOKEN, EXTENSION_CONTINUITY_TOKEN_COMMITMENT,
    EXTENSION_GROUP_METADATA_KEYS_REQUESTED, EXTENSION_ICON_COMMITMENT, EXTENSION_ICON_KEY,
    EXTENSION_SUBJECT_COMMITMENT, EXTENSION_SUBJECT_KEY, GROUP_ICON_FILE_NAME,
    GROUP_METADATA_KEYS_REQUESTED, GROUP_SUBJECT_FILE_NAME,
};

/// Content-Type of the FileMetadata of an encrypted subject (RCC.16 section 9.7.1.2.3)
pub const SUBJECT_CONTENT_TYPE: &str = "text/plain;charset=utf-8";
/// target-type and data-type values of the CPM group data requests setting or
/// deleting the encrypted subject and icon (RCC.16 section 7.13.1)
pub const TARGET_ENCRYPTED_SUBJECT: &str = "encrypted-subject";
pub const TARGET_ENCRYPTED_ICON: &str = "encrypted-icon";
/// Length of a new continuity token (RCC.16 section 8.3.1.1)
pub const CONTINUITY_TOKEN_LENGTH: usize = 32;

const TOKEN_COMMITMENT_LABEL: &[u8] = b"Continuity Token GroupInfo Commitment";

#[derive(TlsSerialize, TlsSize)]
struct TokenCommitment<'a> {
    continuity_token: VLByteSlice<'a>,
    epoch_authenticator: VLByteSlice<'a>,
}

/// Commitment to the continuity token at an epoch, the extension_data of
/// continuity_token_commitment (RCC.16 section 7.11.12.2)
///
/// RefHash as RFC 9420 defines it, with the label as given, which is laid out
/// as the Commitment of Annex C.1.
pub fn token_commitment(
    client: &MlsClient,
    ciphersuite: Ciphersuite,
    continuity_token: &[u8],
    epoch_authenticator: &[u8],
) -> Result<Vec<u8>> {
    let value = wire::encode(&TokenCommitment {
        continuity_token: VLByteSlice(continuity_token),
        epoch_authenticator: VLByteSlice(epoch_authenticator),
    })?;
    wire::commitment(
        client.provider().crypto(),
        ciphersuite,
        TOKEN_COMMITMENT_LABEL,
        &value,
    )
}

/// Commitment to the key of an icon or subject, by the hmac_tag of its
/// encryption (RCC.16 sections 9.7.1.1.1, 9.7.1.2.1)
fn key_commitment(
    client: &MlsClient,
    ciphersuite: Ciphersuite,
    label: &str,
    key: &FileMetadata,
) -> Result<Vec<u8>> {
    let encryption_info = key.encryption_info.as_ref().ok_or(ErrorKind::BadFormat)?;
    wire::commitment(
        client.provider().crypto(),
        ciphersuite,
        label.as_bytes(),
        &encryption_info.hmac_tag,
    )
}

/// The two kinds of keys, as kept and committed to
#[derive(Clone, Copy)]
enum Kind {
    Icon,
    Subject,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Icon => GROUP_ICON_FILE_NAME,
            Kind::Subject => GROUP_SUBJECT_FILE_NAME,
        }
    }

    fn commitment_extension(self) -> u16 {
        match self {
            Kind::Icon => EXTENSION_ICON_COMMITMENT,
            Kind::Subject => EXTENSION_SUBJECT_COMMITMENT,
        }
    }

    fn key_extension(self) -> u16 {
        match self {
            Kind::Icon => EXTENSION_ICON_KEY,
            Kind::Subject => EXTENSION_SUBJECT_KEY,
        }
    }

    fn get(self, keys: &FileInfo) -> Option<&FileMetadata> {
        match self {
            Kind::Icon => keys.icon.as_ref(),
            Kind::Subject => keys.subject.as_ref(),
        }
    }

    fn set(self, keys: &mut FileInfo, key: Option<FileMetadata>) {
        match self {
            Kind::Icon => keys.icon = key,
            Kind::Subject => keys.subject = key,
        }
    }

    fn of(self, metadata: &GroupMetadataKeys) -> Option<&FileMetadata> {
        metadata
            .group_subject_icon_keys
            .as_ref()
            .and_then(|keys| self.get(keys))
    }

    fn set_in(self, metadata: &mut GroupMetadataKeys, key: Option<FileMetadata>) {
        let keys = metadata
            .group_subject_icon_keys
            .get_or_insert_with(FileInfo::default);
        self.set(keys, key);
        if keys.icon.is_none() && keys.subject.is_none() {
            metadata.group_subject_icon_keys = None;
        }
    }
}

fn metadata_key(group_id: &[u8]) -> Vec<u8> {
    [&b"RcsGroupMetadata"[..], group_id].concat()
}

/// Group metadata kept for `group_id`, empty when there is none
pub(crate) fn load(client: &MlsClient, group_id: &[u8]) -> Result<GroupMetadataKeys> {
    match client.provider().read_value(&metadata_key(group_id))? {
        Some(value) => proto::decode(&value),
        None => Ok(GroupMetadataKeys::default()),
    }
}

pub(crate) fn store(client: &MlsClient, group_id: &[u8], keys: &GroupMetadataKeys) -> Result<()> {
    client
        .provider()
        .write_value(metadata_key(group_id), proto::encode(keys))
}

pub(crate) fn forget(client: &MlsClient, group_id: &[u8]) -> Result<()> {
    client.provider().remove_value(&metadata_key(group_id))
}

/// Starts a group or Era off with a continuity token (RCC.16 section 8.1),
/// a new one unless there is one already; returns the token
pub(crate) fn ensure_continuity_token(client: &MlsClient, group_id: &[u8]) -> Result<Vec<u8>> {
    let mut keys = load(client, group_id)?;
    if keys.continuity_token.is_empty() {
        keys.continuity_token = new_continuity_token(client)?;
        store(client, group_id, &keys)?;
    }
    Ok(keys.continuity_token)
}

pub(crate) fn new_continuity_token(client: &MlsClient) -> Result<Vec<u8>> {
    client
        .provider()
        .rand()
        .random_vec(CONTINUITY_TOKEN_LENGTH)
        .map_err(fail("continuity token generation", ErrorKind::Crypto))
}

/// Commitments to the icon and subject keys kept for `group_id`, for the
/// GroupContext of a new group or Era (RCC.16 section 9.7.1.3)
pub(crate) fn initial_context_extensions(
    client: &MlsClient,
    group_id: &[u8],
) -> Result<Vec<Extension>> {
    let keys = load(client, group_id)?;
    let mut extensions = Vec::new();
    for kind in [Kind::Icon, Kind::Subject] {
        if let Some(key) = kind.of(&keys) {
            extensions.push(Extension::Unknown(
                kind.commitment_extension(),
                UnknownExtension(key_commitment(
                    client,
                    client.ciphersuite(),
                    kind.label(),
                    key,
                )?),
            ));
        }
    }
    Ok(extensions)
}

/// Contents of the GroupInfo inside a Welcome: the keys matching the commitments
/// of the group, and the continuity token (RCC.16 section 9.7.1.3)
pub(crate) fn welcome_extensions(
    conversation: &MlsConversation,
    client: &MlsClient,
    keys: Option<&GroupMetadataKeys>,
) -> Result<Vec<Extension>> {
    let stored;
    let keys = match keys {
        Some(keys) => keys,
        None => {
            stored = load(client, conversation.group_id())?;
            &stored
        }
    };

    let mut extensions = Vec::new();
    for kind in [Kind::Icon, Kind::Subject] {
        if let Some(key) = kind.of(keys) {
            if conversation.key_matches(client, kind, Some(key))? == Some(true) {
                let mut file_info = FileInfo::default();
                kind.set(&mut file_info, Some(key.clone()));
                extensions.push(Extension::Unknown(
                    kind.key_extension(),
                    UnknownExtension(proto::encode(&file_info)),
                ));
            }
        }
    }
    if !keys.continuity_token.is_empty() {
        extensions.push(Extension::Unknown(
            EXTENSION_CONTINUITY_TOKEN,
            UnknownExtension(keys.continuity_token.clone()),
        ));
    }
    Ok(extensions)
}

/// Extensions of the GroupInfo for the Conversation Focus, made by `client` in
/// the epoch `conversation` is in (RCC.16 section 7.11.12.2)
pub(crate) fn group_info_extensions(
    conversation: &MlsConversation,
    client: &MlsClient,
    keys: &GroupMetadataKeys,
) -> Result<Vec<Extension>> {
    if keys.continuity_token.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![Extension::Unknown(
        EXTENSION_CONTINUITY_TOKEN_COMMITMENT,
        UnknownExtension(token_commitment(
            client,
            conversation.mls_ciphersuite(),
            &keys.continuity_token,
            conversation.epoch_authenticator(),
        )?),
    )])
}

/// Keeps what the GroupInfo of a Welcome brought: the keys matching the
/// commitments of the group, and the continuity token, which replaces the one
/// kept so far
pub(crate) fn receive_welcome(
    conversation: &MlsConversation,
    client: &MlsClient,
    welcome_extensions: &[(u16, Vec<u8>)],
) -> Result<()> {
    let mut keys = load(client, conversation.group_id())?;

    for (extension_type, data) in welcome_extensions {
        if *extension_type == EXTENSION_CONTINUITY_TOKEN {
            keys.continuity_token = data.clone();
        }
        for kind in [Kind::Icon, Kind::Subject] {
            if *extension_type == kind.key_extension() {
                if let Some(key) = read_key(kind, data) {
                    if conversation.key_matches(client, kind, Some(&key))? == Some(true) {
                        kind.set_in(&mut keys, Some(key));
                    }
                }
            }
        }
    }

    store(client, conversation.group_id(), &keys)?;
    drop_stale_keys(conversation, client)
}

/// The key of `kind` in an icon_key or subject_key extension
fn read_key(kind: Kind, data: &[u8]) -> Option<FileMetadata> {
    if let Ok(file_info) = proto::decode::<FileInfo>(data) {
        if let Some(key) = kind.get(&file_info) {
            return Some(key.clone());
        }
    }
    proto::decode::<FileMetadata>(data)
        .ok()
        .filter(|key| key.encryption_info.is_some())
}

/// Forgets the keys the group no longer commits to: the icon or subject was
/// deleted or changed (RCC.16 sections 9.7.1.6, 9.7.1.7)
pub(crate) fn drop_stale_keys(conversation: &MlsConversation, client: &MlsClient) -> Result<()> {
    let mut keys = load(client, conversation.group_id())?;
    let mut changed = false;
    for kind in [Kind::Icon, Kind::Subject] {
        if let Some(key) = kind.of(&keys) {
            if conversation.key_matches(client, kind, Some(key))? != Some(true) {
                kind.set_in(&mut keys, None);
                changed = true;
            }
        }
    }
    if changed {
        store(client, conversation.group_id(), &keys)?;
    }
    Ok(())
}

/// Takes in group metadata keys delivered with a Commit (RCC.16 sections
/// 9.7.1.4, 9.7.1.5, 10.5.4); other messages are left as they are
///
/// The Message-ID bound to the PrivateMessage is not checked: the one of the
/// CPIM message the Conversation Focus delivers the bundle in is not known here.
pub(crate) fn receive_bundled(
    conversation: &mut MlsConversation,
    client: &MlsClient,
    message: IncomingMessage,
) -> Result<IncomingMessage> {
    let IncomingMessage::Application {
        sender,
        data,
        authenticated_data,
        ..
    } = &message
    else {
        return Ok(message);
    };

    let secret_payload: SecretPayload = wire::decode(data)?;
    if secret_payload.payload_type != SecretPayloadType::GroupMetadataKeys {
        return Ok(message);
    }
    let authenticated_data: AuthenticatedData = wire::decode(authenticated_data)?;
    if Some(authenticated_data.era_id) != conversation.era() {
        return Err(ErrorKind::Rejected);
    }
    let received: GroupMetadataKeys = proto::decode(secret_payload.payload.as_slice())?;
    let sender = sender.clone();

    let mut keys = load(client, conversation.group_id())?;
    let mut icon = false;
    let mut subject = false;
    for (kind, kept) in [(Kind::Icon, &mut icon), (Kind::Subject, &mut subject)] {
        if let Some(key) = kind.of(&received) {
            if conversation.key_matches(client, kind, Some(key))? == Some(true) {
                kind.set_in(&mut keys, Some(key.clone()));
                *kept = true;
            }
        }
    }

    let continuity_token_matches = if received.continuity_token.is_empty() {
        None
    } else if keys.continuity_token.is_empty() {
        keys.continuity_token = received.continuity_token;
        Some(true)
    } else {
        Some(keys.continuity_token == received.continuity_token)
    };

    store(client, conversation.group_id(), &keys)?;

    Ok(IncomingMessage::GroupMetadataKeys {
        sender,
        icon,
        subject,
        continuity_token_matches,
    })
}

#[derive(TlsSerialize, TlsDeserialize, TlsSize)]
pub(crate) struct PendingEpoch {
    /// Of the epoch the pending Commit leads to
    pub epoch_authenticator: VLBytes,
    /// Key generations already used in that epoch
    pub used_generations: u32,
    /// GroupMetadataKeys once the Commit is applied, if they change
    pub metadata: Option<VLBytes>,
}

fn pending_epoch_key(group_id: &[u8]) -> Vec<u8> {
    [&b"RcsPendingEpoch"[..], group_id].concat()
}

/// What a pending Commit of this client entails beyond the state OpenMLS keeps
pub(crate) fn set_pending_epoch(
    client: &MlsClient,
    group_id: &[u8],
    epoch_authenticator: &[u8],
    used_generations: u32,
    metadata: Option<&GroupMetadataKeys>,
) -> Result<()> {
    let pending = PendingEpoch {
        epoch_authenticator: epoch_authenticator.into(),
        used_generations,
        metadata: metadata.map(|keys| proto::encode(keys).into()),
    };
    client
        .provider()
        .write_value(pending_epoch_key(group_id), wire::encode(&pending)?)
}

pub(crate) fn take_pending_epoch(
    client: &MlsClient,
    group_id: &[u8],
) -> Result<Option<PendingEpoch>> {
    let key = pending_epoch_key(group_id);
    let pending = match client.provider().read_value(&key)? {
        Some(value) => Some(
            PendingEpoch::tls_deserialize_exact(value.as_slice())
                .map_err(fail("pending epoch decoding", ErrorKind::Storage))?,
        ),
        None => None,
    };
    client.provider().remove_value(&key)?;
    Ok(pending)
}

impl MlsConversation {
    /// Keys of the icon and subject and the continuity token this client keeps
    /// for the group
    pub fn group_metadata(&self, client: &MlsClient) -> Result<GroupMetadataKeys> {
        load(client, self.group_id())
    }

    /// Whether `key` is the one the group commits to, None when the group has no
    /// commitment of that kind
    fn key_matches(
        &self,
        client: &MlsClient,
        kind: Kind,
        key: Option<&FileMetadata>,
    ) -> Result<Option<bool>> {
        let Some(commitment) = self.context_extension(kind.commitment_extension()) else {
            return Ok(None);
        };
        Ok(Some(match key {
            Some(key) => {
                key_commitment(client, self.mls_ciphersuite(), kind.label(), key)? == commitment
            }
            None => false,
        }))
    }

    fn context_extension(&self, extension_type: u16) -> Option<Vec<u8>> {
        self.group
            .extensions()
            .iter()
            .find_map(|extension| match extension {
                Extension::Unknown(t, UnknownExtension(data)) if *t == extension_type => {
                    Some(data.clone())
                }
                _ => None,
            })
    }

    /// Whether this client keeps the keys of every encrypted icon and subject the
    /// group has (RCC.16 section 10.5.1); otherwise it may ask for them with
    /// `request_group_metadata_keys()`
    pub fn group_metadata_in_sync(&self, client: &MlsClient) -> Result<bool> {
        let keys = load(client, self.group_id())?;
        for kind in [Kind::Icon, Kind::Subject] {
            if self.key_matches(client, kind, kind.of(&keys))? == Some(false) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Whether another client asked for the group metadata keys (RCC.16 section
    /// 10.5.3), to be answered with `send_group_metadata_keys()`
    pub fn group_metadata_keys_requested(&self) -> bool {
        self.context_extension(EXTENSION_GROUP_METADATA_KEYS_REQUESTED)
            .is_some()
    }

    /// Encrypts a new group icon and commits to it (RCC.16 section 9.7.1.4)
    ///
    /// The encrypted icon is for the HTTP Content Server; the Commit goes in a
    /// multipart CPIM message with Message-ID `message_id`, next to the CPM group
    /// data request setting `TARGET_ENCRYPTED_ICON`.
    pub fn set_group_icon(
        &mut self,
        client: &MlsClient,
        icon: &[u8],
        content_type: &str,
        message_id: &[u8],
    ) -> Result<(CommitOutput, EncryptedFile)> {
        self.set_key(client, Kind::Icon, icon, content_type, message_id)
    }

    /// Encrypts a new group subject and commits to it (RCC.16 section 9.7.1.5)
    ///
    /// The encrypted subject goes Base64 encoded in the CPM group data request
    /// setting `TARGET_ENCRYPTED_SUBJECT`, next to the Commit, in a multipart CPIM
    /// message with Message-ID `message_id`.
    pub fn set_group_subject(
        &mut self,
        client: &MlsClient,
        subject: &str,
        message_id: &[u8],
    ) -> Result<(CommitOutput, EncryptedFile)> {
        self.set_key(
            client,
            Kind::Subject,
            subject.as_bytes(),
            SUBJECT_CONTENT_TYPE,
            message_id,
        )
    }

    fn set_key(
        &mut self,
        client: &MlsClient,
        kind: Kind,
        content: &[u8],
        content_type: &str,
        message_id: &[u8],
    ) -> Result<(CommitOutput, EncryptedFile)> {
        let encrypted = file::encrypt_file(content, kind.label())?;
        let key = FileMetadata {
            file_name: kind.label().to_string(),
            content_type: content_type.to_string(),
            encryption_info: Some(encrypted.encryption_info.clone()),
        };
        let commitment = key_commitment(client, self.mls_ciphersuite(), kind.label(), &key)?;

        let mut keys = load(client, self.group_id())?;
        kind.set_in(&mut keys, Some(key.clone()));

        let mut file_info = FileInfo::default();
        kind.set(&mut file_info, Some(key));
        let sent = GroupMetadataKeys {
            continuity_token: Vec::new(),
            group_subject_icon_keys: Some(file_info),
        };

        let output = self.update_context_extensions(
            client,
            |extensions| {
                remove_extension(extensions, kind.commitment_extension());
                extensions.push(Extension::Unknown(
                    kind.commitment_extension(),
                    UnknownExtension(commitment),
                ));
            },
            CommitExtras {
                bundled: Some((proto::encode(&sent), message_id.to_vec())),
                metadata: Some(keys),
            },
        )?;
        Ok((output, encrypted))
    }

    /// Deletes the encrypted group icon (RCC.16 section 9.7.1.6)
    ///
    /// The Commit goes next to the CPM group data request deleting
    /// `TARGET_ENCRYPTED_ICON`.
    pub fn delete_group_icon(&mut self, client: &MlsClient) -> Result<CommitOutput> {
        self.delete_key(client, Kind::Icon)
    }

    /// Deletes the encrypted group subject (RCC.16 section 9.7.1.7)
    pub fn delete_group_subject(&mut self, client: &MlsClient) -> Result<CommitOutput> {
        self.delete_key(client, Kind::Subject)
    }

    fn delete_key(&mut self, client: &MlsClient, kind: Kind) -> Result<CommitOutput> {
        if self
            .context_extension(kind.commitment_extension())
            .is_none()
        {
            return Err(ErrorKind::InvalidState);
        }

        let mut keys = load(client, self.group_id())?;
        kind.set_in(&mut keys, None);

        self.update_context_extensions(
            client,
            |extensions| {
                remove_extension(extensions, kind.commitment_extension());
                remove_extension(extensions, EXTENSION_GROUP_METADATA_KEYS_REQUESTED);
            },
            CommitExtras {
                bundled: None,
                metadata: Some(keys),
            },
        )
    }

    /// Asks the other clients for the group metadata keys this client misses
    /// (RCC.16 section 10.5.2)
    pub fn request_group_metadata_keys(&mut self, client: &MlsClient) -> Result<CommitOutput> {
        if self.group_metadata_keys_requested() {
            return Err(ErrorKind::InvalidState);
        }

        self.update_context_extensions(
            client,
            |extensions| {
                extensions.push(Extension::Unknown(
                    EXTENSION_GROUP_METADATA_KEYS_REQUESTED,
                    UnknownExtension(GROUP_METADATA_KEYS_REQUESTED.to_vec()),
                ))
            },
            CommitExtras::default(),
        )
    }

    /// Answers a request for the group metadata keys with the keys of the icon
    /// and subject and the continuity token (RCC.16 section 10.5.3)
    ///
    /// Fails with InvalidState when there was no request, or when this client
    /// misses keys itself. The Commit goes in a CPIM message with Message-ID
    /// `message_id`.
    pub fn send_group_metadata_keys(
        &mut self,
        client: &MlsClient,
        message_id: &[u8],
    ) -> Result<CommitOutput> {
        if !self.group_metadata_keys_requested() || !self.group_metadata_in_sync(client)? {
            return Err(ErrorKind::InvalidState);
        }

        let keys = load(client, self.group_id())?;
        let mut sent = GroupMetadataKeys {
            continuity_token: keys.continuity_token.clone(),
            group_subject_icon_keys: None,
        };
        for kind in [Kind::Icon, Kind::Subject] {
            if self.key_matches(client, kind, kind.of(&keys))? == Some(true) {
                kind.set_in(&mut sent, kind.of(&keys).cloned());
            }
        }

        let bundled = (sent != GroupMetadataKeys::default())
            .then(|| (proto::encode(&sent), message_id.to_vec()));

        self.update_context_extensions(
            client,
            |extensions| remove_extension(extensions, EXTENSION_GROUP_METADATA_KEYS_REQUESTED),
            CommitExtras {
                bundled,
                metadata: None,
            },
        )
    }
}

impl MlsClient {
    /// Keys of the icon and subject and the continuity token kept for the group
    /// `group_id`, which outlive its Eras
    pub fn group_metadata(&self, group_id: &[u8]) -> Result<GroupMetadataKeys> {
        load(self, group_id)
    }

    /// Replaces the continuity token of the group `group_id` with a new one, for
    /// the next Era, when continuity with the previous one cannot be established
    /// (RCC.16 section 8.3.1.2)
    pub fn renew_continuity_token(&self, group_id: &[u8]) -> Result<Vec<u8>> {
        let mut keys = load(self, group_id)?;
        keys.continuity_token = new_continuity_token(self)?;
        store(self, group_id, &keys)?;
        Ok(keys.continuity_token)
    }

    /// Erases the keys and continuity token kept for the group `group_id`
    pub fn forget_group_metadata(&self, group_id: &[u8]) -> Result<()> {
        forget(self, group_id)
    }

    /// Whether the continuity token kept for the group is the one a GroupInfo
    /// from the Conversation Focus commits to, at the epoch with
    /// `epoch_authenticator` (RCC.16 sections 8.3.1.2, 10.1.1, 10.5.1)
    ///
    /// None when the GroupInfo carries no commitment or no token is kept.
    pub fn continuity_token_matches(
        &self,
        group_info: &[u8],
        epoch_authenticator: &[u8],
    ) -> Result<Option<bool>> {
        let message = MlsMessageIn::tls_deserialize_exact(group_info)
            .map_err(fail("GroupInfo decoding", ErrorKind::BadFormat))?;
        let group_info = match message.extract() {
            MlsMessageBodyIn::GroupInfo(group_info) => group_info,
            _ => return Err(ErrorKind::UnexpectedMessage),
        };

        let Some(commitment) =
            group_info
                .extensions()
                .iter()
                .find_map(|extension| match extension {
                    Extension::Unknown(EXTENSION_CONTINUITY_TOKEN_COMMITMENT, data) => {
                        Some(data.0.clone())
                    }
                    _ => None,
                })
        else {
            return Ok(None);
        };

        let keys = load(self, group_info.group_id().as_slice())?;
        if keys.continuity_token.is_empty() {
            return Ok(None);
        }
        let expected = token_commitment(
            self,
            self.ciphersuite(),
            &keys.continuity_token,
            epoch_authenticator,
        )?;
        Ok(Some(expected == commitment))
    }
}

fn remove_extension(extensions: &mut Vec<Extension>, extension_type: u16) {
    extensions
        .retain(|extension| !matches!(extension, Extension::Unknown(t, _) if *t == extension_type));
}
