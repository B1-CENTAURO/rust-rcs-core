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

use openmls::messages::group_info::GroupInfo;
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
/// The Commit only takes effect locally once it comes back from the Conversation
/// Focus, or once `merge_pending_commit()` is called.
pub struct CommitOutput {
    /// For all members of the group, as it was before the Commit
    pub commit: Vec<u8>,
    /// For the members being added, if any
    pub welcome: Option<Vec<u8>>,
    /// MlsMessage holding the GroupInfo of the new epoch
    pub group_info: Vec<u8>,
    pub epoch_authenticator: Vec<u8>,
    /// Ratchet tree of the new epoch, only for the first Commit of an Era
    pub ratchet_tree: Option<Vec<u8>>,
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
                    ratchet_tree: self.ratchet_tree.clone().unwrap_or_default(),
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
    /// This includes Commits of this client coming back from the Conversation Focus.
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
    /// External Commit of this client already applied, to be recognised when the
    /// Conversation Focus delivers it back
    pub(crate) applied_commit: Option<Vec<u8>>,
}

impl MlsConversation {
    pub(crate) fn new(group: MlsGroup) -> MlsConversation {
        MlsConversation {
            group,
            applied_commit: None,
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

        let first_in_era = self.epoch() == 0;
        let (commit, welcome, group_info) = self
            .group
            .add_members(client.provider(), client.signer(), &validated)
            .map_err(fail("adding members", ErrorKind::InvalidState))?;

        self.commit_output(client, commit, Some(welcome), group_info, first_in_era)
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

        let first_in_era = self.epoch() == 0;
        let (commit, welcome, group_info) = self
            .group
            .remove_members(client.provider(), client.signer(), &leaf_indices)
            .map_err(fail("removing members", ErrorKind::InvalidState))?;

        self.commit_output(client, commit, welcome, group_info, first_in_era)
    }

    /// Replaces this client's own key material, for post-compromise security
    /// (RCC.16 section 9.5.2)
    pub fn update_keys(&mut self, client: &MlsClient) -> Result<CommitOutput> {
        let first_in_era = self.epoch() == 0;
        let bundle = self
            .group
            .self_update(
                client.provider(),
                client.signer(),
                LeafNodeParameters::default(),
            )
            .map_err(fail("updating own keys", ErrorKind::InvalidState))?;

        let welcome = bundle.to_welcome_msg();
        let (commit, _, group_info) = bundle.into_contents();

        self.commit_output(client, commit, welcome, group_info, first_in_era)
    }

    /// Commits the proposals received so far
    pub fn commit_pending_proposals(&mut self, client: &MlsClient) -> Result<CommitOutput> {
        let first_in_era = self.epoch() == 0;
        let (commit, welcome, group_info) = self
            .group
            .commit_to_pending_proposals(client.provider(), client.signer())
            .map_err(fail("committing proposals", ErrorKind::InvalidState))?;

        if let Some(staged_commit) = self.group.pending_commit() {
            if !proposals_valid(client.validator(), staged_commit) {
                self.discard_pending_commit(client)?;
                return Err(ErrorKind::InvalidCredential);
            }
        }

        self.commit_output(client, commit, welcome, group_info, first_in_era)
    }

    /// Moves the conversation to unencrypted (RCC.16 section 11.2), or back, by
    /// committing the addition or removal of the end_mls extension
    pub fn set_encryption_ended(
        &mut self,
        client: &MlsClient,
        ended: bool,
    ) -> Result<CommitOutput> {
        let current = self.group.extensions();
        let mut extensions: Vec<Extension> = current
            .iter()
            .filter(|extension| {
                !is_end_mls(extension) && !matches!(extension, Extension::RequiredCapabilities(_))
            })
            .cloned()
            .collect();
        if ended {
            extensions.push(Extension::Unknown(
                rcs::EXTENSION_END_MLS,
                UnknownExtension(rcs::END_MLS_EXTENSION_DATA.to_vec()),
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

        let first_in_era = self.epoch() == 0;
        let (commit, welcome, group_info) = self
            .group
            .update_group_context_extensions(client.provider(), extensions, client.signer())
            .map_err(fail("updating extensions", ErrorKind::InvalidState))?;

        self.commit_output(client, commit, welcome, group_info, first_in_era)
    }

    /// Applies the Commit last created by this client
    pub fn merge_pending_commit(&mut self, client: &MlsClient) -> Result<()> {
        self.group
            .merge_pending_commit(client.provider())
            .map_err(fail("merging own Commit", ErrorKind::InvalidState))
    }

    /// Drops the Commit last created by this client, e.g. because the
    /// Conversation Focus rejected it
    pub fn discard_pending_commit(&mut self, client: &MlsClient) -> Result<()> {
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

        self.group
            .create_message(client.provider(), client.signer(), plaintext)
            .map_err(fail("encrypting message", ErrorKind::InvalidState))?
            .to_bytes()
            .map_err(fail("message encoding", ErrorKind::BadFormat))
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
            _ => Err(ErrorKind::UnexpectedMessage),
        }
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
        self.group
            .delete(client.provider().storage())
            .map_err(fail("deleting group", ErrorKind::Storage))
    }

    /// Collects what the Conversation Focus needs next to a Commit of this client
    pub(crate) fn commit_output(
        &self,
        client: &MlsClient,
        commit: MlsMessageOut,
        welcome: Option<MlsMessageOut>,
        group_info: Option<GroupInfo>,
        first_in_era: bool,
    ) -> Result<CommitOutput> {
        let staged_commit = self.group.pending_commit().ok_or(ErrorKind::InvalidState)?;

        let epoch_authenticator = staged_commit
            .epoch_authenticator()
            .ok_or(ErrorKind::InvalidState)?
            .as_slice()
            .to_vec();

        let ratchet_tree = if first_in_era {
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

        let group_info = MlsMessageOut::from(group_info.ok_or(ErrorKind::InvalidState)?)
            .to_bytes()
            .map_err(fail("GroupInfo encoding", ErrorKind::BadFormat))?;

        let commit = commit
            .to_bytes()
            .map_err(fail("Commit encoding", ErrorKind::BadFormat))?;

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
