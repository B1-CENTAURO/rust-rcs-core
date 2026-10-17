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

use std::sync::Arc;

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;

use super::conversation::{CommitOutput, MlsConversation};
use super::provider::{self, MlsProvider};
use super::rcs;
use super::{fail, ErrorKind, Result};

const SNAPSHOT_MAGIC: &[u8] = b"RCSMLS";
const SNAPSHOT_VERSION: u8 = 1;

/// Decides which identities are allowed into a group
///
/// MLS leaves authenticating members to the application (RFC 9420, Section 5.3.1).
/// Every credential is passed through here before it enters local group state:
/// KeyPackages about to be added, all members of a group joined through a Welcome,
/// every credential introduced by a Commit, and the credential of the committer.
///
/// `rcs::certificate::RcsCredentialValidator` implements the rules of RCC.16.
pub trait CredentialValidator: Send + Sync {
    fn validate(&self, credential: &Credential, signature_key: &[u8]) -> bool;

    /// Decides whether this client may add the owner of `credential` to a group,
    /// which can be stricter than accepting one others added
    fn validate_addition(&self, credential: &Credential, signature_key: &[u8]) -> bool {
        self.validate(credential, signature_key)
    }

    /// Decides whether `new` may take the place of `old`, through the committer's
    /// own update or an External Commit removing `old`; unlike `old`, `new` is
    /// not yet trusted
    fn validate_replacement(
        &self,
        old: &Credential,
        new: &Credential,
        signature_key: &[u8],
    ) -> bool {
        let _ = old;
        self.validate(new, signature_key)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MlsConfig {
    /// Cap on the number of past epochs whose secrets are kept, so that messages
    /// sent before a Commit but delivered after it can still be decrypted
    ///
    /// None keeps them until `MlsConversation::prune_past_epochs()` drops them;
    /// RCC.16 requires keeping them for at least `rcs::PAST_EPOCH_RETENTION`.
    pub max_past_epochs: Option<usize>,
}

/// One MLS client, i.e. one device of a user
pub struct MlsClient {
    provider: MlsProvider,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    ciphersuite: Ciphersuite,
    config: MlsConfig,
    validator: Arc<dyn CredentialValidator>,
}

impl MlsClient {
    /// Creates a client with a new signature key and a basic credential holding `identity`
    pub fn new(
        identity: &[u8],
        ciphersuite: Ciphersuite,
        config: MlsConfig,
        validator: Box<dyn CredentialValidator>,
    ) -> Result<MlsClient> {
        let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
            .map_err(fail("signature key generation", ErrorKind::Crypto))?;

        MlsClient::with_credential(
            BasicCredential::new(identity.to_vec()).into(),
            signer,
            ciphersuite,
            config,
            validator,
        )
    }

    /// Creates a client from a credential that was issued for the public key of `signer`
    pub fn with_credential(
        credential: Credential,
        signer: SignatureKeyPair,
        ciphersuite: Ciphersuite,
        config: MlsConfig,
        validator: Box<dyn CredentialValidator>,
    ) -> Result<MlsClient> {
        if signer.signature_scheme() != ciphersuite.signature_algorithm() {
            return Err(ErrorKind::Crypto);
        }

        let provider = MlsProvider::default();

        signer
            .store(provider.storage())
            .map_err(fail("storing signature key", ErrorKind::Storage))?;

        let credential = CredentialWithKey {
            credential,
            signature_key: signer.to_public_vec().into(),
        };

        Ok(MlsClient {
            provider,
            signer,
            credential,
            ciphersuite,
            config,
            validator: validator.into(),
        })
    }

    /// Restores a client from the output of `snapshot()`
    pub fn restore(
        snapshot: &[u8],
        config: MlsConfig,
        validator: Box<dyn CredentialValidator>,
    ) -> Result<MlsClient> {
        let mut data = snapshot
            .strip_prefix(SNAPSHOT_MAGIC)
            .ok_or(ErrorKind::BadFormat)?;

        match data.split_first() {
            Some((&SNAPSHOT_VERSION, rest)) => data = rest,
            _ => return Err(ErrorKind::BadFormat),
        }

        if data.len() < 2 {
            return Err(ErrorKind::BadFormat);
        }
        let ciphersuite = Ciphersuite::try_from(u16::from_be_bytes([data[0], data[1]]))
            .map_err(fail("ciphersuite decoding", ErrorKind::BadFormat))?;
        data = &data[2..];

        let credential = Credential::tls_deserialize_exact(provider::read_bytes(&mut data)?)
            .map_err(fail("credential decoding", ErrorKind::BadFormat))?;

        let signature_key = provider::read_bytes(&mut data)?.to_vec();

        let provider = MlsProvider::import_storage(&mut data)?;

        if !data.is_empty() {
            return Err(ErrorKind::BadFormat);
        }

        let signer = SignatureKeyPair::read(
            provider.storage(),
            &signature_key,
            ciphersuite.signature_algorithm(),
        )
        .ok_or(ErrorKind::Storage)?;

        let credential = CredentialWithKey {
            credential,
            signature_key: signature_key.into(),
        };

        Ok(MlsClient {
            provider,
            signer,
            credential,
            ciphersuite,
            config,
            validator: validator.into(),
        })
    }

    /// Serializes the complete client state, private keys included
    ///
    /// The snapshot has to be stored encrypted, and refreshed after every call that
    /// takes `&MlsClient`, before anything produced by that call is sent out. Sending
    /// again from an outdated snapshot reuses message keys, breaking confidentiality.
    pub fn snapshot(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();

        out.extend_from_slice(SNAPSHOT_MAGIC);
        out.push(SNAPSHOT_VERSION);
        out.extend_from_slice(&u16::from(self.ciphersuite).to_be_bytes());

        let credential = self
            .credential
            .credential
            .tls_serialize_detached()
            .map_err(fail("credential encoding", ErrorKind::BadFormat))?;
        provider::write_bytes(&mut out, &credential);
        provider::write_bytes(&mut out, self.signer.public());

        self.provider.export_storage(&mut out)?;

        Ok(out)
    }

    pub fn credential(&self) -> &Credential {
        &self.credential.credential
    }

    pub fn ciphersuite(&self) -> Ciphersuite {
        self.ciphersuite
    }

    /// Escape hatch for using OpenMLS directly
    pub fn provider(&self) -> &MlsProvider {
        &self.provider
    }

    /// Escape hatch for using OpenMLS directly
    pub fn signer(&self) -> &SignatureKeyPair {
        &self.signer
    }

    pub(crate) fn validator(&self) -> &dyn CredentialValidator {
        self.validator.as_ref()
    }

    /// Copy of this client and its state, to try out changes on
    pub(crate) fn fork(&self) -> Result<MlsClient> {
        Ok(MlsClient {
            provider: self.provider.fork()?,
            signer: self.signer.clone(),
            credential: self.credential.clone(),
            ciphersuite: self.ciphersuite,
            config: self.config,
            validator: self.validator.clone(),
        })
    }

    /// Leaf node capabilities, covering the extensions and proposals of RCC.16
    ///
    /// OpenMLS only lists basic credentials by default, while every member has to
    /// support the credential types of all others. Whether a credential is trusted
    /// is up to the CredentialValidator, so all types this client can carry are listed.
    fn capabilities(&self, last_resort: bool) -> Capabilities {
        let mut credentials = vec![CredentialType::Basic, CredentialType::X509];
        let own = self.credential.credential.credential_type();
        if !credentials.contains(&own) {
            credentials.push(own);
        }

        // including the types reserved for future use (RCC.16 section 7.11.11)
        let mut extensions: Vec<ExtensionType> = rcs::EXTENSIONS
            .iter()
            .copied()
            .chain(rcs::RESERVED_FOR_FUTURE_USE)
            .map(ExtensionType::from)
            .collect();
        if last_resort {
            extensions.push(ExtensionType::LastResort);
        }

        let proposals: Vec<ProposalType> = rcs::PROPOSALS
            .iter()
            .copied()
            .chain(rcs::RESERVED_FOR_FUTURE_USE)
            .map(ProposalType::from)
            .collect();

        Capabilities::new(
            None,
            None,
            Some(&extensions),
            Some(&proposals),
            Some(&credentials),
        )
    }

    fn past_epoch_deletion_policy(&self) -> PastEpochDeletionPolicy {
        match self.config.max_past_epochs {
            Some(max_past_epochs) => PastEpochDeletionPolicy::MaxEpochs(max_past_epochs),
            None => PastEpochDeletionPolicy::KeepAll,
        }
    }

    /// Handshake messages go out as PublicMessages, which the Conversation Focus
    /// has to be able to validate (RCC.16 section 6.2.6), and application messages
    /// are padded to `padding_size`. Welcomes go without ratchet tree (section
    /// 7.9.2).
    pub(crate) fn join_config(&self, padding_size: usize) -> MlsGroupJoinConfig {
        MlsGroupJoinConfig::builder()
            .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .set_past_epoch_deletion_policy(self.past_epoch_deletion_policy())
            .padding_size(padding_size)
            .use_ratchet_tree_extension(false)
            .build()
    }

    /// Generates a KeyPackage others can use to add this client to a group,
    /// encoded as an MLSMessage
    ///
    /// Its private part is kept until a Welcome consumes it. A `last_resort`
    /// KeyPackage is never consumed, and serves when no other one is left.
    pub fn generate_key_package(&self, last_resort: bool) -> Result<Vec<u8>> {
        let mut builder =
            KeyPackage::builder().leaf_node_capabilities(self.capabilities(last_resort));
        if last_resort {
            builder = builder.mark_as_last_resort();
        }

        let bundle = builder
            .build(
                self.ciphersuite,
                &self.provider,
                &self.signer,
                self.credential.clone(),
            )
            .map_err(fail("KeyPackage generation", ErrorKind::Crypto))?;

        MlsMessageOut::from(bundle.key_package().clone())
            .to_bytes()
            .map_err(fail("KeyPackage encoding", ErrorKind::BadFormat))
    }

    /// Creates a group with this client as its only member, in Era `era`
    ///
    /// RCC.16 uses a random GUID as `group_id` for 1-to-1 chats, which is what
    /// passing None generates, and the Conversation-ID for group chats (section
    /// 6.1.1). The GUID is written as 32 hex digits, the length of the group id
    /// fields of Annex C.4. Starting a new Era of a group requires deleting the
    /// old one first.
    ///
    /// The group takes on the continuity token kept for `group_id`, or a new one,
    /// and commits to the keys of the icon and subject kept for it (sections
    /// 8.3.1, 9.7.1.3).
    pub fn create_conversation(
        &self,
        group_id: Option<&[u8]>,
        era: u32,
    ) -> Result<MlsConversation> {
        let group_id = match group_id {
            Some(group_id) => GroupId::from_slice(group_id),
            None => GroupId::from_slice(uuid::Uuid::new_v4().simple().to_string().as_bytes()),
        };

        rcs::metadata::ensure_continuity_token(self, group_id.as_slice())?;
        let mut extensions = vec![Extension::Unknown(
            rcs::EXTENSION_ERA,
            UnknownExtension(era.to_be_bytes().to_vec()),
        )];
        extensions.extend(rcs::metadata::initial_context_extensions(
            self,
            group_id.as_slice(),
        )?);
        let extensions = Extensions::from_vec(extensions)
            .map_err(fail("GroupContext extensions", ErrorKind::InvalidState))?;

        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(self.ciphersuite)
            .capabilities(self.capabilities(false))
            .with_group_context_extensions(extensions)
            .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .set_past_epoch_deletion_policy(self.past_epoch_deletion_policy())
            .build();

        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            group_id,
            self.credential.clone(),
        )
        .map_err(fail("group creation", ErrorKind::InvalidState))?;

        Ok(MlsConversation::new(group))
    }

    /// Joins a group through a Welcome generated for one of this client's KeyPackages
    ///
    /// `ratchet_tree` is the one the Conversation Focus sent along with the
    /// Welcome (RCC.16 section 7.9.3); it may be left empty for a Welcome that
    /// carries the tree in an extension. Any attempt uses up the KeyPackage
    /// unless it is a last resort one, even one failing for lack of the tree.
    ///
    /// The keys of the icon and subject and the continuity token in the Welcome
    /// are kept (RCC.16 section 9.7.1.3); a continuity token that differs from
    /// the one kept so far replaces it, see `group_metadata()`.
    pub fn join_conversation(
        &self,
        welcome: &[u8],
        ratchet_tree: &[u8],
    ) -> Result<MlsConversation> {
        let message = MlsMessageIn::tls_deserialize_exact(welcome)
            .map_err(fail("Welcome decoding", ErrorKind::BadFormat))?;

        let welcome = match message.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(ErrorKind::UnexpectedMessage),
        };

        let mut builder =
            StagedWelcome::build_from_welcome(&self.provider, &self.join_config(0), welcome)
                .map_err(fail("Welcome processing", ErrorKind::Rejected))?;
        if !ratchet_tree.is_empty() {
            let ratchet_tree = RatchetTreeIn::tls_deserialize_exact(ratchet_tree)
                .map_err(fail("ratchet tree decoding", ErrorKind::BadFormat))?;
            builder = builder.with_ratchet_tree(ratchet_tree);
        }

        // being added again to a group this client was removed from earlier; a
        // group still active locally is never replaced
        let group_id = builder
            .processed_welcome()
            .unverified_group_info()
            .group_id();
        let builder = match MlsGroup::load(self.provider.storage(), group_id) {
            Ok(Some(old_group)) if !old_group.is_active() => builder.replace_old_group(),
            _ => builder,
        };

        let welcome_extensions: Vec<(u16, Vec<u8>)> = builder
            .processed_welcome()
            .unverified_group_info()
            .extensions()
            .iter()
            .filter_map(|extension| match extension {
                Extension::Unknown(extension_type, UnknownExtension(data)) => {
                    Some((*extension_type, data.clone()))
                }
                _ => None,
            })
            .collect();

        let staged_welcome = builder
            .build()
            .map_err(fail("Welcome processing", ErrorKind::Rejected))?;

        if !self.members_valid(staged_welcome.members()) {
            return Err(ErrorKind::InvalidCredential);
        }

        let group = staged_welcome
            .into_group(&self.provider)
            .map_err(fail("joining group", ErrorKind::Storage))?;

        let conversation = MlsConversation::new(group);
        rcs::metadata::receive_welcome(&conversation, self, &welcome_extensions)?;
        Ok(conversation)
    }

    /// Self-heals by re-joining a group through an External Commit, after losing
    /// or corrupting its local state (RCC.16 section 10.1.1)
    ///
    /// `group_info` is what the Conversation Focus returned to an
    /// MLS-Group-Info-Pull INFO request. Any local state of the group is dropped.
    /// The self_remove Proposals among its pending Proposals are committed too,
    /// as the Conversation Focus only accepts Commits that cover all of them
    /// (section 6.2.1).
    /// Unlike other Commits the External Commit is applied locally right away;
    /// should the Conversation Focus reject it, self-healing has to start over.
    pub fn rejoin_conversation(
        &self,
        group_info: &rcs::proto::MlsGroupInfo,
    ) -> Result<(MlsConversation, CommitOutput)> {
        self.rejoin_conversation_replacing(group_info, &[])
    }

    /// Self-heals as `rejoin_conversation()` does, removing the Clients holding
    /// `replaced` as well: the old Clients of this Participant, e.g. all those of
    /// a former Participant Key (RCC.16 section 10.1.1)
    ///
    /// A Remove Proposal takes out the leaf this client had, or else the first
    /// of these, and server_remove Proposals the rest, as an External Commit has
    /// at most one Remove Proposal.
    pub fn rejoin_conversation_replacing(
        &self,
        group_info: &rcs::proto::MlsGroupInfo,
        replaced: &[Credential],
    ) -> Result<(MlsConversation, CommitOutput)> {
        let message = MlsMessageIn::tls_deserialize_exact(&group_info.group_info)
            .map_err(fail("GroupInfo decoding", ErrorKind::BadFormat))?;

        let verifiable_group_info = match message.extract() {
            MlsMessageBodyIn::GroupInfo(group_info) => group_info,
            _ => return Err(ErrorKind::UnexpectedMessage),
        };

        let group_id = verifiable_group_info.group_id().clone();
        if let Ok(Some(mut old_group)) = MlsGroup::load(self.provider.storage(), &group_id) {
            old_group
                .delete(self.provider.storage())
                .map_err(fail("deleting group", ErrorKind::Storage))?;
        }

        let mut pending_proposals = Vec::new();
        if !group_info.pending_proposals.is_empty() {
            for proposal in rcs::wire::decode_message_list(&group_info.pending_proposals)? {
                let message = MlsMessageIn::tls_deserialize_exact(&proposal)
                    .map_err(fail("Proposal decoding", ErrorKind::BadFormat))?;
                match message.extract() {
                    MlsMessageBodyIn::PublicMessage(proposal) => pending_proposals.push(proposal),
                    _ => return Err(ErrorKind::UnexpectedMessage),
                }
            }
        }

        let mut builder = MlsGroup::external_commit_builder()
            .with_config(self.join_config(0))
            .with_proposals(pending_proposals)
            .with_removed_credentials(replaced.to_vec());
        if !group_info.ratchet_tree.is_empty() {
            let ratchet_tree = RatchetTreeIn::tls_deserialize_exact(&group_info.ratchet_tree)
                .map_err(fail("ratchet tree decoding", ErrorKind::BadFormat))?;
            builder = builder.with_ratchet_tree(ratchet_tree);
        }

        let (group, bundle) = builder
            .build_group(
                &self.provider,
                verifiable_group_info,
                self.credential.clone(),
            )
            .map_err(fail("External Commit", ErrorKind::Rejected))?
            .leaf_node_parameters(
                LeafNodeParameters::builder()
                    .with_capabilities(self.capabilities(false))
                    .build(),
            )
            .load_psks(self.provider.storage())
            .map_err(fail("External Commit", ErrorKind::Storage))?
            .create_group_info(true)
            .build(
                self.provider.rand(),
                self.provider.crypto(),
                &self.signer,
                |_| true,
            )
            .map_err(fail("External Commit", ErrorKind::Rejected))?
            .finalize(&self.provider)
            .map_err(fail("External Commit", ErrorKind::Storage))?;

        let mut conversation = MlsConversation::new(group);

        if !self.members_valid(conversation.mls_group().members()) {
            conversation.delete(self)?;
            return Err(ErrorKind::InvalidCredential);
        }

        // OpenMLS applies External Commits right away, unlike other Commits
        let commit = bundle
            .into_commit()
            .to_bytes()
            .map_err(fail("Commit encoding", ErrorKind::BadFormat))?;

        rcs::metadata::drop_stale_keys(&conversation, self)?;
        let keys = rcs::metadata::load(self, group_id.as_slice())?;
        let extensions = rcs::metadata::group_info_extensions(&conversation, self, &keys)?;
        let group_info = conversation
            .group
            .export_group_info_with_additional_extensions(
                self.provider.crypto(),
                &self.signer,
                false,
                extensions,
            )
            .map_err(fail("GroupInfo export", ErrorKind::InvalidState))?
            .to_bytes()
            .map_err(fail("GroupInfo encoding", ErrorKind::BadFormat))?;

        let output = CommitOutput {
            commit: commit.clone(),
            welcome: None,
            group_info,
            epoch_authenticator: conversation.epoch_authenticator().to_vec(),
            private_message: None,
            ratchet_tree: None,
            first_in_era: false,
        };
        conversation.applied_commit = Some(commit);

        Ok((conversation, output))
    }

    fn members_valid(&self, mut members: impl Iterator<Item = Member>) -> bool {
        members.all(|member| {
            self.validator
                .validate(&member.credential, &member.signature_key)
        })
    }

    /// Loads a group this client is a member of from local state
    pub fn load_conversation(&self, group_id: &[u8]) -> Result<MlsConversation> {
        match MlsGroup::load(self.provider.storage(), &GroupId::from_slice(group_id)) {
            Ok(Some(group)) => Ok(MlsConversation::new(group)),
            Ok(None) => Err(ErrorKind::UnknownGroup),
            Err(e) => Err(fail("group loading", ErrorKind::Storage)(e)),
        }
    }
}
