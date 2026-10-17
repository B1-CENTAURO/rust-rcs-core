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

use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;

use super::client::{CredentialValidator, MlsClient};
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
/// The Commit only takes effect locally once `merge_pending_commit()` is called,
/// which should happen after it has been delivered.
pub struct CommitOutput {
    /// For all members of the group, as it was before the Commit
    pub commit: Vec<u8>,
    /// For the members being added, if any
    pub welcome: Option<Vec<u8>>,
}

pub enum IncomingMessage {
    Application {
        sender: Credential,
        data: Vec<u8>,
    },
    /// A proposal, kept until a Commit covers it
    Proposal {
        sender: Credential,
    },
    /// A Commit, already applied: the group is now in a new epoch
    Commit {
        sender: Credential,
        added: Vec<Credential>,
        removed: Vec<Credential>,
        /// This client was removed and can no longer use the group
        self_removed: bool,
    },
    /// A message sent by this client itself, delivered back to it; own Commits
    /// still have to be applied through `merge_pending_commit()`
    Own,
}

/// Local state of one MLS group
///
/// Every method taking an `MlsClient` must be given the client that created or
/// joined the group.
pub struct MlsConversation {
    group: MlsGroup,
}

impl MlsConversation {
    pub(crate) fn new(group: MlsGroup) -> MlsConversation {
        MlsConversation { group }
    }

    pub fn group_id(&self) -> &[u8] {
        self.group.group_id().as_slice()
    }

    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
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
    pub fn add_members(
        &mut self,
        client: &MlsClient,
        key_packages: &[&[u8]],
    ) -> Result<CommitOutput> {
        let mut validated = Vec::with_capacity(key_packages.len());
        for key_package in key_packages {
            validated.push(self.read_key_package(client, key_package)?);
        }

        let (commit, welcome, _) = self
            .group
            .add_members(client.provider(), client.signer(), &validated)
            .map_err(fail("adding members", ErrorKind::InvalidState))?;

        commit_output(commit, Some(welcome))
    }

    /// Removes every device of the members holding one of `credentials`
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

        let (commit, welcome, _) = self
            .group
            .remove_members(client.provider(), client.signer(), &leaf_indices)
            .map_err(fail("removing members", ErrorKind::InvalidState))?;

        commit_output(commit, welcome)
    }

    /// Replaces this client's own key material, for post-compromise security
    pub fn update_keys(&mut self, client: &MlsClient) -> Result<CommitOutput> {
        let bundle = self
            .group
            .self_update(
                client.provider(),
                client.signer(),
                LeafNodeParameters::default(),
            )
            .map_err(fail("updating own keys", ErrorKind::InvalidState))?;

        let welcome = bundle.to_welcome_msg();
        let (commit, _, _) = bundle.into_contents();

        commit_output(commit, welcome)
    }

    /// Commits the proposals received so far
    pub fn commit_pending_proposals(&mut self, client: &MlsClient) -> Result<CommitOutput> {
        let (commit, welcome, _) = self
            .group
            .commit_to_pending_proposals(client.provider(), client.signer())
            .map_err(fail("committing proposals", ErrorKind::InvalidState))?;

        if let Some(staged_commit) = self.group.pending_commit() {
            if !commit_credentials_valid(client.validator(), staged_commit) {
                self.discard_pending_commit(client)?;
                return Err(ErrorKind::InvalidCredential);
            }
        }

        commit_output(commit, welcome)
    }

    /// Applies the Commit last created by this client
    pub fn merge_pending_commit(&mut self, client: &MlsClient) -> Result<()> {
        self.group
            .merge_pending_commit(client.provider())
            .map_err(fail("merging own Commit", ErrorKind::InvalidState))
    }

    /// Drops the Commit last created by this client, e.g. because another
    /// member's Commit for the same epoch was delivered first
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
        self.group
            .create_message(client.provider(), client.signer(), plaintext)
            .map_err(fail("encrypting message", ErrorKind::InvalidState))?
            .to_bytes()
            .map_err(fail("message encoding", ErrorKind::BadFormat))
    }

    /// Handles a handshake or application message sent to the group
    ///
    /// Commits are validated and applied right away; a Commit introducing a
    /// credential the validator refuses is rejected as a whole.
    pub fn process(&mut self, client: &MlsClient, message: &[u8]) -> Result<IncomingMessage> {
        let message = MlsMessageIn::tls_deserialize_exact(message)
            .map_err(fail("message decoding", ErrorKind::BadFormat))?
            .try_into_protocol_message()
            .map_err(fail("message decoding", ErrorKind::UnexpectedMessage))?;

        if message.group_id() != self.group.group_id() {
            return Err(ErrorKind::UnexpectedMessage);
        }

        let processed = self
            .group
            .process_message(client.provider(), message)
            .map_err(fail("message processing", ErrorKind::Rejected))?;

        let sender = processed.credential().clone();

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(application_message) => {
                Ok(IncomingMessage::Application {
                    sender,
                    data: application_message.into_bytes(),
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

            ProcessedMessageContent::OwnPendingCommit
            | ProcessedMessageContent::OwnPrivateMessage => Ok(IncomingMessage::Own),

            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                if !commit_credentials_valid(client.validator(), &staged_commit) {
                    return Err(ErrorKind::InvalidCredential);
                }

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

                // looked up before merging, while the removed leaves are still in the tree
                let removed = staged_commit
                    .remove_proposals()
                    .filter_map(|p| self.group.member(p.remove_proposal().removed()).cloned())
                    .collect();

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

    /// Derives a secret from the current epoch (RFC 9420, Section 8.5), e.g. to
    /// protect content sent outside of MLS messages
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
            .validate(leaf_node.credential(), leaf_node.signature_key().as_slice())
        {
            return Err(ErrorKind::InvalidCredential);
        }

        Ok(key_package)
    }
}

fn commit_output(commit: MlsMessageOut, welcome: Option<MlsMessageOut>) -> Result<CommitOutput> {
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

    Ok(CommitOutput { commit, welcome })
}

/// Runs every credential a Commit introduces through the validator, mirroring
/// `StagedCommit::credentials_to_verify()` but keeping the signature keys at hand
///
/// OpenMLS does not expose the keys of external senders, so a Commit introducing
/// any is refused; groups created here never use them.
fn commit_credentials_valid(
    validator: &dyn CredentialValidator,
    staged_commit: &StagedCommit,
) -> bool {
    if let Some(leaf_node) = staged_commit.update_path_leaf_node() {
        if !leaf_node_valid(validator, leaf_node) {
            return false;
        }
    }

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
