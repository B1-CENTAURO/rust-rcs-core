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

use std::time::Duration;

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;

use super::client::{CredentialValidator, MlsClient};
use super::rcs::proto::{client_mls_rcs_message, server_mls_rcs_message};
use super::rcs::{self, file, proto, wire};
use super::{fail, ErrorKind, Result};

/// What kind of MLS message some received bytes hold, for routing them
pub enum MessageKind {
    /// Handshake or application message for the group with this id
    Group(Vec<u8>),
    Welcome,
    KeyPackage,
    GroupInfo,
}

pub fn inspect(message: &[u8]) -> Result<MessageKind> {
    let message = MlsMessageIn::tls_deserialize_exact(message)
        .map_err(fail("message decoding", ErrorKind::BadFormat))?;

    match message.extract() {
        MlsMessageBodyIn::PublicMessage(m) => Ok(MessageKind::Group(m.group_id().to_vec())),
        MlsMessageBodyIn::PrivateMessage(m) => Ok(MessageKind::Group(m.group_id().to_vec())),
        MlsMessageBodyIn::Welcome(_) => Ok(MessageKind::Welcome),
        MlsMessageBodyIn::KeyPackage(_) => Ok(MessageKind::KeyPackage),
        MlsMessageBodyIn::GroupInfo(_) => Ok(MessageKind::GroupInfo),
        #[allow(unreachable_patterns)]
        _ => Err(ErrorKind::UnexpectedMessage),
    }
}

/// Messages to send out after creating a Commit
///
/// The Commit only takes effect locally once the Conversation Focus accepted it
/// or delivered it back, or once `merge_pending_commit()` is called.
pub struct CommitOutput {
    /// For all members of the group, as it was before the Commit
    pub commit: Vec<u8>,
    /// For the members being added, if any; without the ratchet tree, which the
    /// Conversation Focus sends along (RCC.16 sections 7.9.2, 7.9.3)
    pub welcome: Option<Vec<u8>>,
    /// MlsMessage holding the GroupInfo of the new epoch
    pub group_info: Vec<u8>,
    pub epoch_authenticator: Vec<u8>,
    /// Ratchet tree of the new epoch, for the members joining through `welcome`
    ///
    /// Only the first Commit of an Era hands it to the Conversation Focus, which
    /// reconstructs it from later Commits (RCC.16 sections 7.9.2, 7.9.3).
    pub ratchet_tree: Option<Vec<u8>>,
    pub(crate) first_in_era: bool,
}

impl CommitOutput {
    /// `message/mls-rcs-client` body for the Conversation Focus (RCC.16 section 7.9.2)
    ///
    /// `private_message` is delivered together with a Commit without Welcome,
    /// carrying the keys of a changed group subject or icon.
    pub fn to_client_message(&self, private_message: Option<&[u8]>) -> Result<Vec<u8>> {
        let commit_list = wire::encode_message_list(&[&self.commit])?;

        let payload = match &self.welcome {
            Some(welcome) => {
                client_mls_rcs_message::Payload::WelcomeCommitBundle(proto::WelcomeCommitBundle {
                    commit_list,
                    welcome: welcome.clone(),
                    group_info: self.group_info.clone(),
                    epoch_authenticator: self.epoch_authenticator.clone(),
                    ratchet_tree: match self.first_in_era {
                        true => self.ratchet_tree.clone().unwrap_or_default(),
                        false => Vec::new(),
                    },
                })
            }
            None => client_mls_rcs_message::Payload::CommitBundle(proto::CommitBundle {
                commit_list,
                private_message: private_message.unwrap_or_default().to_vec(),
                group_info: self.group_info.clone(),
                epoch_authenticator: self.epoch_authenticator.clone(),
            }),
        };

        Ok(proto::encode(&proto::ClientMlsRcsMessage {
            payload: Some(payload),
        }))
    }
}

pub enum IncomingMessage {
    Application {
        sender: Credential,
        /// Leaf of the sending client in the ratchet tree
        sender_leaf_index: u32,
        data: Vec<u8>,
        authenticated_data: Vec<u8>,
    },
    /// A proposal, kept until a Commit covers it
    Proposal { sender: Credential },
    /// A Commit, already applied: the group is now in a new epoch
    ///
    /// This includes Commits of this client the Conversation Focus accepted or
    /// delivered back.
    Commit {
        sender: Credential,
        added: Vec<Credential>,
        removed: Vec<Credential>,
        /// This client was removed and can no longer use the group
        self_removed: bool,
    },
    /// A message sent by this client itself, delivered back to it, which needs no
    /// further handling
    Own,
}

/// Local state of one MLS group
///
/// Every method taking an `MlsClient` must be given the client that created or
/// joined the group.
pub struct MlsConversation {
    pub(crate) group: MlsGroup,
    /// Commit of this client already applied, to be recognised when the
    /// Conversation Focus delivers it back
    pub(crate) applied_commit: Option<Vec<u8>>,
    /// Pending Commit of this client, as sent
    pending_commit: Option<Vec<u8>>,
}

impl MlsConversation {
    pub(crate) fn new(group: MlsGroup) -> MlsConversation {
        MlsConversation {
            group,
            applied_commit: None,
            pending_commit: None,
        }
    }

    pub fn group_id(&self) -> &[u8] {
        self.group.group_id().as_slice()
    }

    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    /// Era of the group (RCC.16 section 7.11.1)
    pub fn era(&self) -> Option<u32> {
        self.group
            .extensions()
            .iter()
            .find_map(|extension| match extension {
                Extension::Unknown(rcs::EXTENSION_ERA, UnknownExtension(data)) => {
                    data.as_slice().try_into().ok().map(u32::from_be_bytes)
                }
                _ => None,
            })
    }

    /// Epoch authenticator of the current epoch, for the Epoch-Authenticator CPIM
    /// header (RCC.16 section 7.5.5)
    pub fn epoch_authenticator(&self) -> &[u8] {
        self.group.epoch_authenticator().as_slice()
    }

    /// Whether the conversation was moved to unencrypted (RCC.16 section 11.2)
    pub fn is_encryption_ended(&self) -> bool {
        self.group.extensions().iter().any(is_end_mls)
    }

    /// Why the conversation was moved to unencrypted, if it was (RCC.16 section
    /// 7.11.2.2); Unset when the end_mls extension gives no reason
    pub fn encryption_ended_reason(&self) -> Option<proto::EndMlsReason> {
        self.group
            .extensions()
            .iter()
            .find_map(|extension| match extension {
                Extension::Unknown(rcs::EXTENSION_END_MLS, UnknownExtension(data)) => Some(
                    proto::decode::<proto::EndMlsMetadata>(data)
                        .ok()
                        .and_then(|metadata| {
                            proto::EndMlsReason::try_from(metadata.downgrade_reason).ok()
                        })
                        .unwrap_or(proto::EndMlsReason::Unset),
                ),
                _ => None,
            })
    }

    /// TLS encoded ratchet tree of the current epoch, which the Conversation Focus
    /// keeps for joiners and for self-healing (RCC.16 sections 7.9.3, 7.10.1)
    pub fn ratchet_tree(&self) -> Result<Vec<u8>> {
        self.group
            .export_ratchet_tree()
            .tls_serialize_detached()
            .map_err(fail("ratchet tree encoding", ErrorKind::BadFormat))
    }

    /// Identifies the current epoch, as in an MLS-Enhanced-Group-Info-Pull
    /// request (RCC.16 section 7.10.2)
    pub fn epoch_identifier(&self) -> proto::EpochIdentifier {
        proto::EpochIdentifier {
            era_id: self.era().unwrap_or_default(),
            epoch_id: self.epoch(),
            epoch_authenticator: self.epoch_authenticator().to_vec(),
        }
    }

    /// False once this client has been removed from the group
    pub fn is_active(&self) -> bool {
        self.group.is_active()
    }

    pub fn members(&self) -> Vec<Credential> {
        self.group
            .members()
            .map(|member| member.credential)
            .collect()
    }

    pub fn has_pending_commit(&self) -> bool {
        self.group.pending_commit().is_some()
    }

    /// Escape hatch for using OpenMLS directly; nothing done through it is
    /// checked by the CredentialValidator
    pub fn mls_group(&mut self) -> &mut MlsGroup {
        &mut self.group
    }

    /// Adds the owners of `key_packages`, each an MLSMessage holding a KeyPackage
    ///
    /// RCC.16 requires adding all Clients of a Participant (section 5.3).
    pub fn add_members(
        &mut self,
        client: &MlsClient,
        key_packages: &[&[u8]],
    ) -> Result<CommitOutput> {
        let mut validated = Vec::with_capacity(key_packages.len());
        for key_package in key_packages {
            validated.push(self.read_key_package(client, key_package)?);
        }

        let builder = self.group.commit_builder().propose_adds(validated);
        let bundle = stage_commit(client, builder)?;
        self.commit_output(client, bundle)
    }

    /// Removes every Client of the members holding one of `credentials`
    pub fn remove_members(
        &mut self,
        client: &MlsClient,
        credentials: &[Credential],
    ) -> Result<CommitOutput> {
        let mut leaf_indices = Vec::new();
        for credential in credentials {
            let before = leaf_indices.len();
            for member in self.group.members() {
                if &member.credential == credential {
                    leaf_indices.push(member.index);
                }
            }
            if leaf_indices.len() == before {
                return Err(ErrorKind::UnknownMember);
            }
        }

        let builder = self.group.commit_builder().propose_removals(leaf_indices);
        let bundle = stage_commit(client, builder)?;
        self.commit_output(client, bundle)
    }

    /// Replaces this client's own key material, for post-compromise security
    /// (RCC.16 section 9.5.2)
    pub fn update_keys(&mut self, client: &MlsClient) -> Result<CommitOutput> {
        let builder = self.group.commit_builder().force_self_update(true);
        let bundle = stage_commit(client, builder)?;
        self.commit_output(client, bundle)
    }

    /// Commits the proposals received so far
    pub fn commit_pending_proposals(&mut self, client: &MlsClient) -> Result<CommitOutput> {
        let builder = self.group.commit_builder();
        let bundle = stage_commit(client, builder)?;

        if let Some(staged_commit) = self.group.pending_commit() {
            if !proposals_valid(client.validator(), staged_commit) {
                self.discard_pending_commit(client)?;
                return Err(ErrorKind::InvalidCredential);
            }
        }

        self.commit_output(client, bundle)
    }

    /// Moves the conversation to unencrypted for `reason` (RCC.16 section 11.2),
    /// or with None back to encrypted (section 11.1.2), by committing the
    /// addition or removal of the end_mls extension
    pub fn set_encryption_ended(
        &mut self,
        client: &MlsClient,
        reason: Option<proto::EndMlsReason>,
    ) -> Result<CommitOutput> {
        let current = self.group.extensions();
        let mut extensions: Vec<Extension> = current
            .iter()
            .filter(|extension| {
                !is_end_mls(extension) && !matches!(extension, Extension::RequiredCapabilities(_))
            })
            .cloned()
            .collect();
        if let Some(reason) = reason {
            let metadata = proto::EndMlsMetadata {
                downgrade_reason: reason as i32,
            };
            extensions.push(Extension::Unknown(
                rcs::EXTENSION_END_MLS,
                UnknownExtension(proto::encode(&metadata)),
            ));
        }

        // OpenMLS only accepts GroupContext extensions of types every member is
        // required to support
        let required = current.required_capabilities();
        let mut extension_types = required
            .map(|r| r.extension_types().to_vec())
            .unwrap_or_default();
        for extension_type in extensions.iter().map(|e| e.extension_type()) {
            if matches!(extension_type, ExtensionType::Unknown(_))
                && !extension_types.contains(&extension_type)
            {
                extension_types.push(extension_type);
            }
        }
        extensions.push(Extension::RequiredCapabilities(
            RequiredCapabilitiesExtension::new(
                &extension_types,
                required.map(|r| r.proposal_types()).unwrap_or_default(),
                required.map(|r| r.credential_types()).unwrap_or_default(),
            ),
        ));

        let extensions = Extensions::from_vec(extensions)
            .map_err(fail("end_mls extension", ErrorKind::InvalidState))?;

        let builder = self
            .group
            .commit_builder()
            .propose_group_context_extensions(extensions)
            .map_err(fail("updating extensions", ErrorKind::InvalidState))?;
        let bundle = stage_commit(client, builder)?;
        self.commit_output(client, bundle)
    }

    /// Applies the Commit last created by this client
    pub fn merge_pending_commit(&mut self, client: &MlsClient) -> Result<()> {
        self.group
            .merge_pending_commit(client.provider())
            .map_err(fail("merging own Commit", ErrorKind::InvalidState))?;
        self.applied_commit = self.pending_commit.take();
        Ok(())
    }

    /// Drops the Commit last created by this client, e.g. because the
    /// Conversation Focus rejected it
    pub fn discard_pending_commit(&mut self, client: &MlsClient) -> Result<()> {
        self.pending_commit = None;
        self.group
            .clear_pending_commit(client.provider().storage())
            .map_err(fail("discarding own Commit", ErrorKind::Storage))
    }

    /// Proposes to remove this client; another member has to commit it
    pub fn leave(&mut self, client: &MlsClient) -> Result<Vec<u8>> {
        self.group
            .leave_group(client.provider(), client.signer())
            .map_err(fail("leaving group", ErrorKind::InvalidState))?
            .to_bytes()
            .map_err(fail("proposal encoding", ErrorKind::BadFormat))
    }

    /// Encrypts application data for the group, in its current epoch
    pub fn encrypt(&mut self, client: &MlsClient, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_with_aad(client, plaintext, Vec::new())
    }

    pub(crate) fn encrypt_with_aad(
        &mut self,
        client: &MlsClient,
        plaintext: &[u8],
        authenticated_data: Vec<u8>,
    ) -> Result<Vec<u8>> {
        // padding as PADME prescribes (RCC.16 section 9.1.1), estimated from the
        // plaintext alone: the signature next to it only shifts the result at
        // the boundaries of PADME's ranges
        let padding_size = file::padme_block(plaintext.len() as u64) as usize;
        self.group
            .set_configuration(
                client.provider().storage(),
                &client.join_config(padding_size),
            )
            .map_err(fail("setting padding", ErrorKind::Storage))?;

        self.group.set_aad(authenticated_data);

        let key_generation = self.key_generation(client)?;
        let message = self
            .group
            .create_message(client.provider(), client.signer(), plaintext)
            .map_err(fail("encrypting message", ErrorKind::InvalidState))?;
        self.set_key_generation(client, key_generation + 1)?;

        message
            .to_bytes()
            .map_err(fail("message encoding", ErrorKind::BadFormat))
    }

    /// Generation of the key the next message of this client gets encrypted with
    ///
    /// OpenMLS does not tell, so the messages this client encrypted in the current
    /// epoch are counted, in storage next to the group.
    pub(crate) fn key_generation(&self, client: &MlsClient) -> Result<u32> {
        let values = client
            .provider()
            .storage()
            .values
            .read()
            .map_err(|_| ErrorKind::Storage)?;

        let counted = values
            .get(&key_generation_key(self.group_id()))
            .and_then(|value| value.strip_prefix(self.epoch_authenticator()))
            .and_then(|count| count.try_into().ok())
            .map(u32::from_be_bytes);
        Ok(counted.unwrap_or(0))
    }

    fn set_key_generation(&self, client: &MlsClient, key_generation: u32) -> Result<()> {
        let mut values = client
            .provider()
            .storage()
            .values
            .write()
            .map_err(|_| ErrorKind::Storage)?;

        let value = [
            self.epoch_authenticator(),
            &key_generation.to_be_bytes()[..],
        ]
        .concat();
        values.insert(key_generation_key(self.group_id()), value);
        Ok(())
    }

    /// Handles a handshake or application message sent to the group
    ///
    /// Commits are validated and applied right away; a Commit introducing a
    /// credential the validator refuses is rejected as a whole. Handshake
    /// messages have to be PublicMessages (RCC.16 section 6.2.6).
    pub fn process(&mut self, client: &MlsClient, message: &[u8]) -> Result<IncomingMessage> {
        if self.applied_commit.as_deref() == Some(message) {
            self.applied_commit = None;
            return Ok(IncomingMessage::Own);
        }

        let message = self.decode(message)?;
        self.process_protocol_message(client, message)
    }

    /// Handles a `message/mls-rcs-server` body received over MSRP
    pub fn process_server_message(
        &mut self,
        client: &MlsClient,
        body: &[u8],
    ) -> Result<Vec<IncomingMessage>> {
        let message: proto::ServerMlsRcsMessage = proto::decode(body)?;

        match message.payload {
            Some(server_mls_rcs_message::Payload::ProposalList(list)) => {
                self.process_message_list(client, &list)
            }
            Some(server_mls_rcs_message::Payload::ServerCommitBundle(bundle)) => {
                self.process_commit_bundle(client, &bundle)
            }
            Some(server_mls_rcs_message::Payload::AcceptedMlsRcsMessage(accepted)) => {
                self.process_accepted(client, &accepted).map(|m| vec![m])
            }
            _ => Err(ErrorKind::UnexpectedMessage),
        }
    }

    /// Applies the pending Commit of this client once the Conversation Focus
    /// accepted it (RCC.16 section 6.2.4); should the Commit still be delivered
    /// back later, it is recognised as Own
    ///
    /// Without a pending Commit, what was accepted needs no handling. Having a
    /// ProposalList accepted while a Commit of the same epoch is pending is not
    /// told apart, as the Message-ID of each is unknown here.
    pub fn process_accepted(
        &mut self,
        client: &MlsClient,
        accepted: &proto::AcceptedMlsRcsMessage,
    ) -> Result<IncomingMessage> {
        let Some(staged_commit) = self.group.pending_commit() else {
            return Ok(IncomingMessage::Own);
        };

        let accepted_epoch = accepted
            .previous_epoch_identifier
            .as_ref()
            .ok_or(ErrorKind::BadFormat)?;
        if accepted_epoch != &self.epoch_identifier() {
            return Err(ErrorKind::UnexpectedMessage);
        }

        let (added, removed) = self.membership_changes(staged_commit);
        self.merge_pending_commit(client)?;

        Ok(IncomingMessage::Commit {
            sender: client.credential().clone(),
            added,
            removed,
            self_removed: false,
        })
    }

    /// Handles a Commit forwarded by the Conversation Focus (RCC.16 section 7.9.3)
    ///
    /// A Welcome in the bundle is for the members being added, which join with
    /// `MlsClient::join_conversation()` instead.
    pub fn process_commit_bundle(
        &mut self,
        client: &MlsClient,
        bundle: &proto::ServerCommitBundle,
    ) -> Result<Vec<IncomingMessage>> {
        let mut processed = self.process_message_list(client, &bundle.commit_list)?;
        if !bundle.private_message.is_empty() {
            processed.push(self.process(client, &bundle.private_message)?);
        }
        Ok(processed)
    }

    /// Handles each MlsMessage of a ProposalList or CommitList
    pub fn process_message_list(
        &mut self,
        client: &MlsClient,
        list: &[u8],
    ) -> Result<Vec<IncomingMessage>> {
        wire::decode_message_list(list)?
            .iter()
            .map(|message| self.process(client, message))
            .collect()
    }

    pub(crate) fn decode(&self, message: &[u8]) -> Result<ProtocolMessage> {
        let message = MlsMessageIn::tls_deserialize_exact(message)
            .map_err(fail("message decoding", ErrorKind::BadFormat))?
            .try_into_protocol_message()
            .map_err(fail("message decoding", ErrorKind::UnexpectedMessage))?;

        if message.group_id() != self.group.group_id() {
            return Err(ErrorKind::UnexpectedMessage);
        }

        if message.wire_format() == WireFormat::PrivateMessage && message.is_handshake_message() {
            return Err(ErrorKind::Rejected);
        }

        Ok(message)
    }

    pub(crate) fn process_protocol_message(
        &mut self,
        client: &MlsClient,
        message: ProtocolMessage,
    ) -> Result<IncomingMessage> {
        let processed = self
            .group
            .process_message(client.provider(), message)
            .map_err(fail("message processing", ErrorKind::Rejected))?;

        let sender = processed.credential().clone();
        let sender_index = match processed.sender() {
            Sender::Member(index) => Some(*index),
            _ => None,
        };
        let committer = sender_index.and_then(|index| self.group.member_at(index));
        let authenticated_data = processed.aad().to_vec();

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(application_message) => {
                Ok(IncomingMessage::Application {
                    sender,
                    sender_leaf_index: sender_index.ok_or(ErrorKind::UnexpectedMessage)?.u32(),
                    data: application_message.into_bytes(),
                    authenticated_data,
                })
            }

            ProcessedMessageContent::ProposalMessage(proposal) => {
                // refused here, it never ends up in a Commit of this client
                if !proposal_valid(client.validator(), proposal.proposal()) {
                    return Err(ErrorKind::InvalidCredential);
                }
                self.group
                    .store_pending_proposal(client.provider().storage(), *proposal)
                    .map_err(fail("storing proposal", ErrorKind::Storage))?;
                Ok(IncomingMessage::Proposal { sender })
            }

            ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                Err(ErrorKind::UnexpectedMessage)
            }

            ProcessedMessageContent::OwnPrivateMessage => Ok(IncomingMessage::Own),

            ProcessedMessageContent::OwnPendingCommit => {
                let staged_commit = self.group.pending_commit().ok_or(ErrorKind::Rejected)?;
                let (added, removed) = self.membership_changes(staged_commit);

                self.merge_pending_commit(client)?;
                self.applied_commit = None;

                Ok(IncomingMessage::Commit {
                    sender: client.credential().clone(),
                    added,
                    removed,
                    self_removed: false,
                })
            }

            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                let replaced = committer.or_else(|| {
                    staged_commit
                        .remove_proposals()
                        .find_map(|p| self.group.member_at(p.remove_proposal().removed()))
                });
                if !commit_credentials_valid(client.validator(), &staged_commit, replaced.as_ref())
                {
                    return Err(ErrorKind::InvalidCredential);
                }

                let (added, removed) = self.membership_changes(&staged_commit);
                let self_removed = staged_commit.self_removed();

                self.group
                    .merge_staged_commit(client.provider(), *staged_commit)
                    .map_err(fail("merging Commit", ErrorKind::Storage))?;

                Ok(IncomingMessage::Commit {
                    sender,
                    added,
                    removed,
                    self_removed,
                })
            }
        }
    }

    /// Drops the secrets of past epochs that are older than `age`, see
    /// `rcs::PAST_EPOCH_RETENTION`
    pub fn prune_past_epochs(&mut self, client: &MlsClient, age: Duration) -> Result<()> {
        self.group
            .delete_past_epoch_secrets(
                client.provider(),
                PastEpochDeletion::older_than_duration(age),
            )
            .map_err(fail("pruning past epochs", ErrorKind::Storage))
    }

    /// Derives a secret from the current epoch (RFC 9420, Section 8.5)
    pub fn export_secret(
        &self,
        client: &MlsClient,
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>> {
        self.group
            .export_secret(client.provider().crypto(), label, context, length)
            .map_err(fail("exporting secret", ErrorKind::InvalidState))
    }

    /// Erases the group from local state
    pub fn delete(mut self, client: &MlsClient) -> Result<()> {
        client
            .provider()
            .storage()
            .values
            .write()
            .map_err(|_| ErrorKind::Storage)?
            .remove(&key_generation_key(self.group_id()));

        self.group
            .delete(client.provider().storage())
            .map_err(fail("deleting group", ErrorKind::Storage))
    }

    /// Collects what the Conversation Focus needs next to a Commit of this client
    fn commit_output(
        &mut self,
        client: &MlsClient,
        bundle: CommitMessageBundle,
    ) -> Result<CommitOutput> {
        let staged_commit = self.group.pending_commit().ok_or(ErrorKind::InvalidState)?;
        let first_in_era = self.epoch() == 0;
        let (commit, welcome, group_info) = bundle.into_messages();

        let epoch_authenticator = staged_commit
            .epoch_authenticator()
            .ok_or(ErrorKind::InvalidState)?
            .as_slice()
            .to_vec();

        let ratchet_tree = if first_in_era || welcome.is_some() {
            let ratchet_tree = staged_commit
                .export_ratchet_tree(client.provider().crypto(), self.group.export_ratchet_tree())
                .map_err(fail("ratchet tree export", ErrorKind::InvalidState))?
                .ok_or(ErrorKind::InvalidState)?;
            Some(
                ratchet_tree
                    .tls_serialize_detached()
                    .map_err(fail("ratchet tree encoding", ErrorKind::BadFormat))?,
            )
        } else {
            None
        };

        let group_info = group_info
            .ok_or(ErrorKind::InvalidState)?
            .to_bytes()
            .map_err(fail("GroupInfo encoding", ErrorKind::BadFormat))?;

        let commit = commit
            .to_bytes()
            .map_err(fail("Commit encoding", ErrorKind::BadFormat))?;
        self.pending_commit = Some(commit.clone());

        let welcome = match welcome {
            Some(welcome) => Some(
                welcome
                    .to_bytes()
                    .map_err(fail("Welcome encoding", ErrorKind::BadFormat))?,
            ),
            None => None,
        };

        Ok(CommitOutput {
            commit,
            welcome,
            group_info,
            epoch_authenticator,
            ratchet_tree,
            first_in_era,
        })
    }

    /// Credentials added and removed by a Commit, looked up before merging it,
    /// while the removed leaves are still in the tree
    fn membership_changes(
        &self,
        staged_commit: &StagedCommit,
    ) -> (Vec<Credential>, Vec<Credential>) {
        let added = staged_commit
            .add_proposals()
            .map(|p| {
                p.add_proposal()
                    .key_package()
                    .leaf_node()
                    .credential()
                    .clone()
            })
            .collect();

        let removed = staged_commit
            .remove_proposals()
            .filter_map(|p| self.group.member(p.remove_proposal().removed()).cloned())
            .collect();

        (added, removed)
    }

    fn read_key_package(&self, client: &MlsClient, key_package: &[u8]) -> Result<KeyPackage> {
        let message = MlsMessageIn::tls_deserialize_exact(key_package)
            .map_err(fail("KeyPackage decoding", ErrorKind::BadFormat))?;

        let key_package = match message.extract() {
            MlsMessageBodyIn::KeyPackage(key_package) => key_package,
            _ => return Err(ErrorKind::UnexpectedMessage),
        };

        let key_package = key_package
            .validate(client.provider().crypto(), ProtocolVersion::Mls10)
            .map_err(fail("KeyPackage validation", ErrorKind::Rejected))?;

        if key_package.ciphersuite() != self.group.ciphersuite() {
            return Err(ErrorKind::Rejected);
        }

        let leaf_node = key_package.leaf_node();
        if !client
            .validator()
            .validate_addition(leaf_node.credential(), leaf_node.signature_key().as_slice())
        {
            return Err(ErrorKind::InvalidCredential);
        }

        Ok(key_package)
    }
}

/// Storage key of the count behind `MlsConversation::key_generation()`, apart
/// from the keys OpenMLS uses, which start with a label of its own
fn key_generation_key(group_id: &[u8]) -> Vec<u8> {
    [&b"RcsKeyGeneration"[..], group_id].concat()
}

/// Stages the Commit `builder` prepares, with the GroupInfo the Conversation
/// Focus stores; the ratchet tree goes next to the Welcome instead of in it
/// (RCC.16 section 7.9.2)
fn stage_commit(
    client: &MlsClient,
    builder: CommitBuilder<'_, Initial>,
) -> Result<CommitMessageBundle> {
    builder
        .load_psks(client.provider().storage())
        .map_err(fail("loading PSKs", ErrorKind::Storage))?
        .create_group_info(true)
        .build(
            client.provider().rand(),
            client.provider().crypto(),
            client.signer(),
            |_| true,
        )
        .map_err(fail("creating Commit", ErrorKind::InvalidState))?
        .stage_commit(client.provider())
        .map_err(fail("staging Commit", ErrorKind::InvalidState))
}

fn is_end_mls(extension: &Extension) -> bool {
    matches!(extension, Extension::Unknown(rcs::EXTENSION_END_MLS, _))
}

/// Runs every credential a Commit of another client introduces through the
/// validator, mirroring `StagedCommit::credentials_to_verify()` but keeping the
/// signature keys at hand, as well as the credential of the committer
///
/// `replaced` is the leaf the Commit's UpdatePath takes the place of: the
/// committer's own, or for a resync External Commit the one it removes.
fn commit_credentials_valid(
    validator: &dyn CredentialValidator,
    staged_commit: &StagedCommit,
    replaced: Option<&Member>,
) -> bool {
    let path_valid = match (staged_commit.update_path_leaf_node(), replaced) {
        (Some(leaf_node), Some(old)) => validator.validate_replacement(
            &old.credential,
            leaf_node.credential(),
            leaf_node.signature_key().as_slice(),
        ),
        (Some(leaf_node), None) => leaf_node_valid(validator, leaf_node),
        // Commits signed with credentials no longer valid are refused (RCC.16 Annex A.4.1)
        (None, Some(committer)) => {
            validator.validate(&committer.credential, &committer.signature_key)
        }
        (None, None) => true,
    };

    path_valid && proposals_valid(validator, staged_commit)
}

/// OpenMLS does not expose the keys of external senders, so a Commit introducing
/// any is refused; groups created here never use them.
fn proposals_valid(validator: &dyn CredentialValidator, staged_commit: &StagedCommit) -> bool {
    staged_commit
        .queued_proposals()
        .all(|queued_proposal| proposal_valid(validator, queued_proposal.proposal()))
}

fn proposal_valid(validator: &dyn CredentialValidator, proposal: &Proposal) -> bool {
    match proposal {
        Proposal::Add(add_proposal) => {
            leaf_node_valid(validator, add_proposal.key_package().leaf_node())
        }
        Proposal::Update(update_proposal) => {
            leaf_node_valid(validator, update_proposal.leaf_node())
        }
        Proposal::GroupContextExtensions(proposal) => proposal
            .extensions()
            .iter()
            .all(|extension| !matches!(extension, Extension::ExternalSenders(_))),
        _ => true,
    }
}

fn leaf_node_valid(validator: &dyn CredentialValidator, leaf_node: &LeafNode) -> bool {
    validator.validate(leaf_node.credential(), leaf_node.signature_key().as_slice())
}
