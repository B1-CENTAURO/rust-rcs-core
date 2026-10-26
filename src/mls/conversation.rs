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
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::OpenMlsProvider;

use super::client::{CredentialValidator, MlsClient};
use super::rcs::proto::{client_mls_rcs_message, server_mls_rcs_message};
use super::rcs::wire::{AuthenticatedData, SecretPayloadType, VerifiableDerivedContent};
use super::rcs::{self, file, metadata, proto, wire};
use super::{fail, ErrorKind, Result};

/// What a KeyPackage tells of the Client it is from
#[derive(Clone, Debug, PartialEq)]
pub struct KeyPackageInfo {
    pub ciphersuite: Ciphersuite,
    pub credential: Credential,
    pub signature_key: Vec<u8>,
}

/// Reads a KeyPackage, once its signature and lifetime are checked (RFC 9420,
/// Section 10.1), for its credential to be checked against the Participant it
/// was asked of the KDS for (RCC.16 section A.4.1.2) before it is added
pub fn key_package_info(key_package: &[u8]) -> Result<KeyPackageInfo> {
    let key_package = validated_key_package(&RustCrypto::default(), key_package)?;
    let leaf_node = key_package.leaf_node();
    Ok(KeyPackageInfo {
        ciphersuite: key_package.ciphersuite(),
        credential: leaf_node.credential().clone(),
        signature_key: leaf_node.signature_key().as_slice().to_vec(),
    })
}

/// A KeyPackage, its signature and lifetime checked
fn validated_key_package(crypto: &impl OpenMlsCrypto, key_package: &[u8]) -> Result<KeyPackage> {
    let message = MlsMessageIn::tls_deserialize_exact(key_package)
        .map_err(fail("KeyPackage decoding", ErrorKind::BadFormat))?;

    let key_package = match message.extract() {
        MlsMessageBodyIn::KeyPackage(key_package) => key_package,
        _ => return Err(ErrorKind::UnexpectedMessage),
    };

    key_package
        .validate(crypto, ProtocolVersion::Mls10)
        .map_err(fail("KeyPackage validation", ErrorKind::Rejected))
}

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
    /// PrivateMessage of the new epoch bundled with the Commit, carrying group
    /// metadata keys (RCC.16 section 7.9.2)
    pub private_message: Option<Vec<u8>>,
    /// Ratchet tree of the new epoch, for the members joining through `welcome`
    ///
    /// Only the first Commit of an Era hands it to the Conversation Focus, which
    /// reconstructs it from later Commits (RCC.16 sections 7.9.2, 7.9.3).
    pub ratchet_tree: Option<Vec<u8>>,
    pub(crate) first_in_era: bool,
}

impl CommitOutput {
    /// `message/mls-rcs-client` body for the Conversation Focus (RCC.16 section 7.9.2)
    pub fn to_client_message(&self) -> Result<Vec<u8>> {
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
                private_message: self.private_message.clone().unwrap_or_default(),
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
    /// Keys of the group icon and subject, or the continuity token, delivered with
    /// a Commit (RCC.16 sections 9.7.1.4, 9.7.1.5, 10.5.4)
    ///
    /// The keys matching the commitments of the group are kept.
    GroupMetadataKeys {
        sender: Credential,
        /// A key of the icon was received and kept
        icon: bool,
        /// A key of the subject was received and kept
        subject: bool,
        /// None without continuity token; Some(false) when it differs from the one
        /// kept by this client, which RCC.16 lets the client end encryption for
        continuity_token_matches: Option<bool>,
    },
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
    /// A Commit or Proposal handled before, e.g. through enhanced self-healing,
    /// delivered again; it needs no further handling, and counts as delivered
    /// (RCC.16 section 10.1.2)
    Duplicate,
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

    pub(crate) fn mls_ciphersuite(&self) -> Ciphersuite {
        self.group.ciphersuite()
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

        self.commit(
            client,
            |builder| Ok(builder.propose_adds(validated)),
            CommitExtras::default(),
        )
    }

    /// Removes every Client of the members holding one of `credentials`
    pub fn remove_members(
        &mut self,
        client: &MlsClient,
        credentials: &[Credential],
    ) -> Result<CommitOutput> {
        let leaf_indices = self.leaf_indices(credentials)?;
        self.commit(
            client,
            |builder| Ok(builder.propose_removals(leaf_indices)),
            CommitExtras::default(),
        )
    }

    /// Removes every Client of the Participants the Messaging Server removed
    /// from the conversation, with server_remove Proposals (RCC.16 section 9.6)
    pub fn remove_members_for_server(
        &mut self,
        client: &MlsClient,
        credentials: &[Credential],
    ) -> Result<CommitOutput> {
        let leaf_indices = self.leaf_indices(credentials)?;
        self.commit(
            client,
            |builder| {
                Ok(builder.add_proposals(leaf_indices.into_iter().map(Proposal::server_remove)))
            },
            CommitExtras::default(),
        )
    }

    /// Replaces the leaves of the members holding one of `stale`, as
    /// `stale_members()` tells them, with the Clients of `key_packages`, each
    /// an MLSMessage holding a KeyPackage the Home KDS returned for their
    /// Participants: a KeyPackage Update (RCC.16 section 9.5.4), a Commit
    /// removing those leaves and adding the KeyPackages, with a Welcome for
    /// the Clients added
    ///
    /// The Home KDS returns KeyPackages of all the Clients of a Participant
    /// (section 5.3): those of Clients that stay members, as their signature
    /// key tells, and those of this client are left out. The leaf of this
    /// client takes on its renewed certificate, if it has one (section 9.5.3).
    pub fn replace_members(
        &mut self,
        client: &MlsClient,
        stale: &[Credential],
        key_packages: &[&[u8]],
    ) -> Result<CommitOutput> {
        let removed = self.leaf_indices(stale)?;
        let mut staying: Vec<Vec<u8>> = self
            .group
            .members()
            .filter(|member| !removed.contains(&member.index))
            .map(|member| member.signature_key)
            .collect();
        staying.push(client.signer().public().to_vec());

        let mut added = Vec::new();
        for key_package in key_packages {
            let key_package = self.read_key_package(client, key_package)?;
            let signature_key = key_package.leaf_node().signature_key().as_slice();
            if !staying.iter().any(|key| key == signature_key) {
                staying.push(signature_key.to_vec());
                added.push(key_package);
            }
        }

        let extras = CommitExtras {
            renewed: self.credential_outdated(client),
            ..CommitExtras::default()
        };
        self.commit(
            client,
            |builder| Ok(builder.propose_removals(removed).propose_adds(added)),
            extras,
        )
    }

    /// Leaves of the members holding one of `credentials`, each holding at least one
    fn leaf_indices(&self, credentials: &[Credential]) -> Result<Vec<LeafNodeIndex>> {
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
        Ok(leaf_indices)
    }

    /// Replaces this client's own key material, for post-compromise security
    /// (RCC.16 section 9.5.2), and with it the credential and signature key of
    /// its leaf, if the client renewed them since (section 9.5.3)
    pub fn update_keys(&mut self, client: &MlsClient) -> Result<CommitOutput> {
        let extras = CommitExtras {
            renewed: self.credential_outdated(client),
            ..CommitExtras::default()
        };
        self.commit(
            client,
            |builder| Ok(builder.force_self_update(true)),
            extras,
        )
    }

    /// Whether the leaf of this client in the group has another credential
    /// than the client, which renewed its certificate since (RCC.16 section
    /// 9.5.3)
    pub fn credential_outdated(&self, client: &MlsClient) -> bool {
        self.group.own_leaf_node().is_some_and(|leaf_node| {
            leaf_node.credential() != client.credential()
                || leaf_node.signature_key().as_slice() != client.signer().public()
        })
    }

    /// The signature key of the leaf of this client in the group, which signs
    /// what the client sends there: the client's, or the one it had before it
    /// renewed its certificate, until the leaf is updated
    pub(crate) fn signer(&self, client: &MlsClient) -> Result<SignatureKeyPair> {
        match self.group.own_leaf_node() {
            Some(leaf_node) if leaf_node.signature_key().as_slice() != client.signer().public() => {
                SignatureKeyPair::read(
                    client.provider().storage(),
                    leaf_node.signature_key().as_slice(),
                    client.ciphersuite().signature_algorithm(),
                )
                .ok_or(ErrorKind::Storage)
            }
            _ => Ok(client.signer().clone()),
        }
    }

    /// Commits the proposals received so far
    pub fn commit_pending_proposals(&mut self, client: &MlsClient) -> Result<CommitOutput> {
        let extras = CommitExtras::default();
        let bundle = self.stage(client, |builder| Ok(builder), &extras)?;

        if let Some(staged_commit) = self.group.pending_commit() {
            if !proposals_valid(client.validator(), staged_commit) {
                self.discard_pending_commit(client)?;
                return Err(ErrorKind::InvalidCredential);
            }
        }

        self.commit_output(client, bundle, extras)
    }

    /// Moves the conversation to unencrypted for `reason` (RCC.16 section 11.2),
    /// or with None back to encrypted (section 11.1.2), by committing the
    /// addition or removal of the end_mls extension
    pub fn set_encryption_ended(
        &mut self,
        client: &MlsClient,
        reason: Option<proto::EndMlsReason>,
    ) -> Result<CommitOutput> {
        self.update_context_extensions(
            client,
            |extensions| {
                extensions.retain(|extension| !is_end_mls(extension));
                if let Some(reason) = reason {
                    let metadata = proto::EndMlsMetadata {
                        downgrade_reason: reason as i32,
                    };
                    extensions.push(Extension::Unknown(
                        rcs::EXTENSION_END_MLS,
                        UnknownExtension(proto::encode(&metadata)),
                    ));
                }
            },
            CommitExtras::default(),
        )
    }

    /// Commits a change of the GroupContext extensions
    pub(crate) fn update_context_extensions(
        &mut self,
        client: &MlsClient,
        change: impl FnOnce(&mut Vec<Extension>),
        extras: CommitExtras,
    ) -> Result<CommitOutput> {
        let current = self.group.extensions();
        let mut extensions: Vec<Extension> = current
            .iter()
            .filter(|extension| !matches!(extension, Extension::RequiredCapabilities(_)))
            .cloned()
            .collect();
        change(&mut extensions);

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
            .map_err(fail("GroupContext extensions", ErrorKind::InvalidState))?;

        self.commit(
            client,
            |builder| {
                builder
                    .propose_group_context_extensions(extensions)
                    .map_err(fail("updating extensions", ErrorKind::InvalidState))
            },
            extras,
        )
    }

    /// Applies the Commit last created by this client
    pub fn merge_pending_commit(&mut self, client: &MlsClient) -> Result<()> {
        // its leaf updated by an UpdatePath (RCC.16 section 9.5.2)
        let updated = self
            .group
            .pending_commit()
            .is_some_and(|staged_commit| staged_commit.update_path_leaf_node().is_some());
        self.group
            .merge_pending_commit(client.provider())
            .map_err(fail("merging own Commit", ErrorKind::InvalidState))?;
        self.applied_commit = self.pending_commit.take();
        if updated {
            self.own_leaf_updated(client, false)?;
        }
        self.note_leaf_keys(client)?;

        // what was tried out on a copy before is done to the group itself as well
        if let Some(pending) = metadata::take_pending_epoch(client, self.group_id())? {
            if pending.epoch_authenticator.as_slice() == self.epoch_authenticator() {
                for _ in 0..pending.used_generations {
                    self.encrypt_with_aad(client, &[], Vec::new())?;
                }
                if let Some(keys) = pending.metadata {
                    metadata::store(client, self.group_id(), &proto::decode(keys.as_slice())?)?;
                }
            }
        }
        Ok(())
    }

    /// Drops the Commit last created by this client, e.g. because the
    /// Conversation Focus rejected it
    pub fn discard_pending_commit(&mut self, client: &MlsClient) -> Result<()> {
        self.pending_commit = None;
        metadata::take_pending_epoch(client, self.group_id())?;
        self.group
            .clear_pending_commit(client.provider().storage())
            .map_err(fail("discarding own Commit", ErrorKind::Storage))
    }

    /// Proposes to remove this client with a self_remove Proposal, which is
    /// what the Conversation Focus accepts (RCC.16 sections 6.2.3, 9.4); another
    /// member has to commit it
    pub fn leave(&mut self, client: &MlsClient) -> Result<Vec<u8>> {
        self.group
            .leave_group_via_self_remove(client.provider(), &self.signer(client)?)
            .map_err(fail("leaving group", ErrorKind::InvalidState))?
            .to_bytes()
            .map_err(fail("proposal encoding", ErrorKind::BadFormat))
    }

    /// Proposes to leave as `leave()` does, giving the `message/mls-rcs-client`
    /// body with the ProposalList for the BYE (RCC.16 sections 7.9.4, 9.4)
    pub fn leave_message(&mut self, client: &MlsClient) -> Result<Vec<u8>> {
        let proposal = self.leave(client)?;
        let proposal_list = wire::encode_message_list(&[&proposal])?;
        Ok(proto::encode(&proto::ClientMlsRcsMessage {
            payload: Some(client_mls_rcs_message::Payload::ProposalList(proposal_list)),
        }))
    }

    /// Drops the pending Proposals of this client, e.g. its self_remove once the
    /// Conversation Focus refused the leave, as OpenMLS makes no Commit while that
    /// is pending; those of other members are kept
    ///
    /// Only for Proposals the Conversation Focus did not take: this client could
    /// not process a Commit covering them once they are dropped.
    pub fn withdraw_own_proposals(&mut self, client: &MlsClient) -> Result<()> {
        let own = Sender::Member(self.group.own_leaf_index());
        let withdrawn: Vec<_> = self
            .group
            .pending_proposals()
            .filter(|proposal| proposal.sender() == &own)
            .map(|proposal| proposal.proposal_reference_ref().clone())
            .collect();

        for proposal_ref in &withdrawn {
            self.group
                .remove_pending_proposal(client.provider().storage(), proposal_ref)
                .map_err(fail("withdrawing proposal", ErrorKind::Storage))?;
        }
        Ok(())
    }

    /// The members with a self_remove Proposal pending, this client aside:
    /// those leaving, whose Proposals the Conversation Focus forwards for a
    /// member to commit, with the other Clients of their Participants (RCC.16
    /// section 9.4)
    pub fn leaving_members(&self) -> Vec<Credential> {
        let own = self.group.own_leaf_index();
        self.group
            .pending_proposals()
            .filter(|proposal| matches!(proposal.proposal(), Proposal::SelfRemove))
            .filter_map(|proposal| match proposal.sender() {
                Sender::Member(index) if *index != own => self.group.member(*index).cloned(),
                _ => None,
            })
            .collect()
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
            .create_message(client.provider(), &self.signer(client)?, plaintext)
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
        let counted = client
            .provider()
            .read_value(&key_generation_key(self.group_id()))?
            .and_then(|value| {
                value
                    .strip_prefix(self.epoch_authenticator())
                    .and_then(|count| count.try_into().ok())
                    .map(u32::from_be_bytes)
            });
        Ok(counted.unwrap_or(0))
    }

    fn set_key_generation(&self, client: &MlsClient, key_generation: u32) -> Result<()> {
        let value = [
            self.epoch_authenticator(),
            &key_generation.to_be_bytes()[..],
        ]
        .concat();
        client
            .provider()
            .write_value(key_generation_key(self.group_id()), value)
    }

    /// Handles a handshake or application message sent to the group
    ///
    /// Commits are validated and applied right away; a Commit introducing a
    /// credential the validator refuses is rejected as a whole. Handshake
    /// messages have to be PublicMessages (RCC.16 section 6.2.6).
    ///
    /// Commits and Proposals of past epochs were applied already, as the
    /// Conversation Focus only delivers one Commit for each epoch; they come out
    /// as Duplicate, as do Proposals already pending.
    pub fn process(&mut self, client: &MlsClient, message: &[u8]) -> Result<IncomingMessage> {
        if self.applied_commit.as_deref() == Some(message) {
            self.applied_commit = None;
            return Ok(IncomingMessage::Own);
        }

        let message = self.decode(message)?;
        if message.is_handshake_message() && message.epoch() < self.group.epoch() {
            return Ok(IncomingMessage::Duplicate);
        }
        self.process_protocol_message(client, message)
    }

    /// Handles a `message/mls-rcs-server` body received over MSRP
    pub fn process_server_message(
        &mut self,
        client: &MlsClient,
        body: &[u8],
    ) -> Result<Vec<IncomingMessage>> {
        self.process_server_mls_rcs_message(client, proto::decode(body)?)
    }

    pub(crate) fn process_server_mls_rcs_message(
        &mut self,
        client: &MlsClient,
        message: proto::ServerMlsRcsMessage,
    ) -> Result<Vec<IncomingMessage>> {
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
    ///
    /// A bundle of more than one message is tried out on a copy of the client
    /// first, so that one failing midway leaves the group as it was (section
    /// 6.2.6).
    pub fn process_commit_bundle(
        &mut self,
        client: &MlsClient,
        bundle: &proto::ServerCommitBundle,
    ) -> Result<Vec<IncomingMessage>> {
        let commits = wire::decode_message_list(&bundle.commit_list)?;
        if commits.len() > 1 || !bundle.private_message.is_empty() {
            let fork = client.fork()?;
            let mut copy = fork.load_conversation(self.group_id())?;
            copy.applied_commit = self.applied_commit.clone();
            copy.pending_commit = self.pending_commit.clone();
            copy.process_bundle_messages(&fork, &commits, &bundle.private_message)?;
        }

        self.process_bundle_messages(client, &commits, &bundle.private_message)
    }

    fn process_bundle_messages(
        &mut self,
        client: &MlsClient,
        commits: &[Vec<u8>],
        private_message: &[u8],
    ) -> Result<Vec<IncomingMessage>> {
        let mut processed = commits
            .iter()
            .map(|commit| self.process(client, commit))
            .collect::<Result<Vec<_>>>()?;

        // the PrivateMessage of a bundle applied before was read before too
        if !processed.is_empty()
            && processed
                .iter()
                .all(|message| matches!(message, IncomingMessage::Duplicate))
        {
            return Ok(processed);
        }

        if !private_message.is_empty() {
            let message = self.process(client, private_message)?;
            processed.push(metadata::receive_bundled(self, client, message)?);
        }
        Ok(processed)
    }

    /// Handles each MlsMessage of a ProposalList or CommitList
    ///
    /// A list of more than one message is tried out on a copy of the client
    /// first, so that one failing midway leaves the group as it was, as for
    /// a bundle (RCC.16 section 6.2.6).
    pub fn process_message_list(
        &mut self,
        client: &MlsClient,
        list: &[u8],
    ) -> Result<Vec<IncomingMessage>> {
        let messages = wire::decode_message_list(list)?;
        if messages.len() > 1 {
            let fork = client.fork()?;
            let mut copy = fork.load_conversation(self.group_id())?;
            copy.applied_commit = self.applied_commit.clone();
            copy.pending_commit = self.pending_commit.clone();
            for message in &messages {
                copy.process(&fork, message)?;
            }
        }

        messages
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
                if self.group.pending_proposals().any(|pending| {
                    pending.proposal_reference_ref() == proposal.proposal_reference_ref()
                }) {
                    return Ok(IncomingMessage::Duplicate);
                }

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
                // an External Commit takes the place of the leaves it removes,
                // with server_remove Proposals as well (RCC.16 section 10.1.1)
                let replaced: Vec<Member> = match committer {
                    Some(committer) => vec![committer],
                    None => staged_commit
                        .remove_proposals()
                        .filter_map(|p| self.group.member_at(p.remove_proposal().removed()))
                        .collect(),
                };
                if !commit_credentials_valid(client.validator(), &staged_commit, &replaced) {
                    return Err(ErrorKind::InvalidCredential);
                }

                let (added, removed) = self.membership_changes(&staged_commit);
                let self_removed = staged_commit.self_removed();

                self.group
                    .merge_staged_commit(client.provider(), *staged_commit)
                    .map_err(fail("merging Commit", ErrorKind::Storage))?;
                self.note_leaf_keys(client)?;

                // a Commit of this client still pending is void now
                self.pending_commit = None;
                metadata::take_pending_epoch(client, self.group_id())?;
                if !self_removed {
                    metadata::drop_stale_keys(self, client)?;
                }

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

    /// Erases the group from local state, apart from its group metadata keys and
    /// continuity token, which carry over to the next Era
    pub fn delete(mut self, client: &MlsClient) -> Result<()> {
        client
            .provider()
            .remove_value(&key_generation_key(self.group_id()))?;
        self.forget_own_leaf(client)?;
        self.forget_leaf_keys(client)?;

        self.group
            .delete(client.provider().storage())
            .map_err(fail("deleting group", ErrorKind::Storage))
    }

    /// Creates a Commit of what `build` proposes, see `stage()`
    pub(crate) fn commit(
        &mut self,
        client: &MlsClient,
        build: impl FnOnce(CommitBuilder<'_, Initial>) -> Result<CommitBuilder<'_, Initial>>,
        extras: CommitExtras,
    ) -> Result<CommitOutput> {
        let bundle = self.stage(client, build, &extras)?;
        self.commit_output(client, bundle, extras)
    }

    /// Stages the Commit `build` prepares; a Welcome gets the group metadata keys
    /// and the continuity token (RCC.16 section 9.7.1.3), but no ratchet tree
    /// (section 7.9.2)
    fn stage(
        &mut self,
        client: &MlsClient,
        build: impl FnOnce(CommitBuilder<'_, Initial>) -> Result<CommitBuilder<'_, Initial>>,
        extras: &CommitExtras,
    ) -> Result<CommitMessageBundle> {
        let welcome_extensions =
            metadata::welcome_extensions(self, client, extras.metadata.as_ref())?;
        let signer = self.signer(client)?;

        let builder = build(self.group.commit_builder())?
            .load_psks(client.provider().storage())
            .map_err(fail("loading PSKs", ErrorKind::Storage))?
            .create_group_info_with_extensions(welcome_extensions)
            .map_err(fail("Welcome extensions", ErrorKind::InvalidState))?
            // the GroupInfo for the Conversation Focus is made in commit_output()
            .create_group_info(false);
        let rand = client.provider().rand();
        let crypto = client.provider().crypto();
        let builder = if extras.renewed {
            let renewed = NewSignerBundle {
                signer: client.signer(),
                credential_with_key: client.credential_with_key().clone(),
            };
            builder.build_with_new_signer(rand, crypto, &signer, renewed, |_| true)
        } else {
            builder.build(rand, crypto, &signer, |_| true)
        };
        builder
            .map_err(fail("creating Commit", ErrorKind::InvalidState))?
            .stage_commit(client.provider())
            .map_err(fail("staging Commit", ErrorKind::InvalidState))
    }

    /// Collects what the Conversation Focus needs next to a Commit of this client
    ///
    /// The GroupInfo has to commit to the continuity token at the epoch
    /// authenticator of the new epoch (RCC.16 section 7.11.12.2), and a bundled
    /// PrivateMessage has to be encrypted in the new epoch: both are made on a
    /// copy of the client with the Commit applied. Once the Commit is applied to
    /// the group itself, the key generations used on the copy are skipped.
    fn commit_output(
        &mut self,
        client: &MlsClient,
        bundle: CommitMessageBundle,
        extras: CommitExtras,
    ) -> Result<CommitOutput> {
        let staged_commit = self.group.pending_commit().ok_or(ErrorKind::InvalidState)?;
        let first_in_era = self.epoch() == 0;
        let (commit, welcome, _) = bundle.into_messages();

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

        let fork = client.fork()?;
        let mut next = fork.load_conversation(self.group_id())?;
        next.group
            .merge_pending_commit(fork.provider())
            .map_err(fail("trying out own Commit", ErrorKind::InvalidState))?;

        let keys = match &extras.metadata {
            Some(keys) => keys.clone(),
            None => metadata::load(client, self.group_id())?,
        };
        let group_info = next
            .group
            .export_group_info_with_additional_extensions(
                fork.provider().crypto(),
                &next.signer(&fork)?,
                false,
                metadata::group_info_extensions(&next, &fork, &keys)?,
            )
            .map_err(fail("GroupInfo export", ErrorKind::InvalidState))?
            .to_bytes()
            .map_err(fail("GroupInfo encoding", ErrorKind::BadFormat))?;

        let private_message = match extras.bundled {
            Some((payload, message_id)) => {
                let authenticated_data = AuthenticatedData::new(
                    &message_id,
                    b"",
                    next.era().ok_or(ErrorKind::InvalidState)?,
                    VerifiableDerivedContent::None,
                );
                Some(next.encrypt_secret_payload(
                    &fork,
                    SecretPayloadType::GroupMetadataKeys,
                    payload,
                    &authenticated_data,
                )?)
            }
            None => None,
        };

        let used_generations = next.key_generation(&fork)?;
        if used_generations > 0 || extras.metadata.is_some() {
            metadata::set_pending_epoch(
                client,
                self.group_id(),
                &epoch_authenticator,
                used_generations,
                extras.metadata.as_ref(),
            )?;
        }

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
            private_message,
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

        let self_removed =
            staged_commit
                .queued_proposals()
                .filter_map(|p| match (p.proposal(), p.sender()) {
                    (Proposal::SelfRemove, Sender::Member(index)) => Some(*index),
                    _ => None,
                });
        let removed = staged_commit
            .remove_proposals()
            .map(|p| p.remove_proposal().removed())
            .chain(self_removed)
            .filter_map(|index| self.group.member(index).cloned())
            .collect();

        (added, removed)
    }

    fn read_key_package(&self, client: &MlsClient, key_package: &[u8]) -> Result<KeyPackage> {
        let key_package = validated_key_package(client.provider().crypto(), key_package)?;

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

/// What goes along with a Commit of this client
#[derive(Default)]
pub(crate) struct CommitExtras {
    /// GroupMetadataKeys to send in a PrivateMessage of the new epoch, and the
    /// Message-ID of the CPIM message carrying the Commit
    pub bundled: Option<(Vec<u8>, Vec<u8>)>,
    /// Group metadata of this client once the Commit is applied, if it changes
    pub metadata: Option<proto::GroupMetadataKeys>,
    /// Whether the UpdatePath brings in the credential and signature key the
    /// client renewed, the Commit signed with those of its leaf until then
    pub renewed: bool,
}

fn is_end_mls(extension: &Extension) -> bool {
    matches!(extension, Extension::Unknown(rcs::EXTENSION_END_MLS, _))
}

/// Runs every credential a Commit of another client introduces through the
/// validator, mirroring `StagedCommit::credentials_to_verify()` but keeping the
/// signature keys at hand, as well as the credential of the committer
///
/// `replaced` are the leaves the Commit's UpdatePath takes the place of: the
/// committer's own, or for an External Commit the ones it removes, each of which
/// has to be one the new leaf may replace.
fn commit_credentials_valid(
    validator: &dyn CredentialValidator,
    staged_commit: &StagedCommit,
    replaced: &[Member],
) -> bool {
    let path_valid = match (staged_commit.update_path_leaf_node(), replaced) {
        (Some(leaf_node), []) => leaf_node_valid(validator, leaf_node),
        (Some(leaf_node), replaced) => replaced.iter().all(|old| {
            validator.validate_replacement(
                &old.credential,
                leaf_node.credential(),
                leaf_node.signature_key().as_slice(),
            )
        }),
        // Commits signed with credentials no longer valid are refused (RCC.16 Annex A.4.1)
        (None, [committer]) => validator.validate(&committer.credential, &committer.signature_key),
        (None, _) => true,
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
