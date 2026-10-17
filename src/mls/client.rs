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

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;

use super::conversation::MlsConversation;
use super::provider::{self, MlsProvider};
use super::{fail, ErrorKind, Result};

const SNAPSHOT_MAGIC: &[u8] = b"RCSMLS";
const SNAPSHOT_VERSION: u8 = 1;

/// Decides which identities are allowed into a group
///
/// MLS leaves authenticating members to the application (RFC 9420, Section 5.3.1).
/// Every credential is passed through here before it enters local group state:
/// KeyPackages about to be added, all members of a group joined through a Welcome,
/// and every credential introduced by a Commit.
pub trait CredentialValidator: Send + Sync {
    fn validate(&self, credential: &Credential, signature_key: &[u8]) -> bool;
}

#[derive(Clone, Copy, Debug)]
pub struct MlsConfig {
    /// Number of past epochs whose secrets are kept, so that messages sent before
    /// a Commit but delivered after it can still be decrypted
    pub max_past_epochs: usize,
    /// Application messages are padded to a multiple of this many bytes, hiding
    /// their exact length; 0 disables padding
    pub padding_size: usize,
}

impl Default for MlsConfig {
    fn default() -> MlsConfig {
        MlsConfig {
            // SIP MESSAGE and MSRP give no ordering guarantee relative to each other,
            // so allow for some reordering around Commits
            max_past_epochs: 3,
            padding_size: 0,
        }
    }
}

/// One MLS client, i.e. one device of a user
pub struct MlsClient {
    provider: MlsProvider,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    ciphersuite: Ciphersuite,
    config: MlsConfig,
    validator: Box<dyn CredentialValidator>,
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
            validator,
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
            validator,
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

    /// Leaf node capabilities
    ///
    /// OpenMLS only lists basic credentials by default, while every member has to
    /// support the credential types of all others. Whether a credential is trusted
    /// is up to the CredentialValidator, so all types this client can carry are listed.
    fn capabilities(&self, extensions: &[ExtensionType]) -> Capabilities {
        let mut credentials = vec![CredentialType::Basic, CredentialType::X509];
        let own = self.credential.credential.credential_type();
        if !credentials.contains(&own) {
            credentials.push(own);
        }

        Capabilities::new(None, None, Some(extensions), None, Some(&credentials))
    }

    /// Generates a KeyPackage others can use to add this client to a group,
    /// encoded as an MLSMessage
    ///
    /// Its private part is kept until a Welcome consumes it. A `last_resort`
    /// KeyPackage is never consumed, and serves when no other one is left.
    pub fn generate_key_package(&self, last_resort: bool) -> Result<Vec<u8>> {
        let mut builder = KeyPackage::builder();
        if last_resort {
            builder = builder
                .mark_as_last_resort()
                .leaf_node_capabilities(self.capabilities(&[ExtensionType::LastResort]));
        } else {
            builder = builder.leaf_node_capabilities(self.capabilities(&[]));
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

    /// Creates a group with this client as its only member
    ///
    /// Without a `group_id` a random one is generated.
    pub fn create_conversation(&self, group_id: Option<&[u8]>) -> Result<MlsConversation> {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(self.ciphersuite)
            .capabilities(self.capabilities(&[]))
            .max_past_epochs(self.config.max_past_epochs)
            .padding_size(self.config.padding_size)
            .use_ratchet_tree_extension(true)
            .build();

        let group = match group_id {
            Some(group_id) => MlsGroup::new_with_group_id(
                &self.provider,
                &self.signer,
                &config,
                GroupId::from_slice(group_id),
                self.credential.clone(),
            ),
            None => MlsGroup::new(
                &self.provider,
                &self.signer,
                &config,
                self.credential.clone(),
            ),
        }
        .map_err(fail("group creation", ErrorKind::InvalidState))?;

        Ok(MlsConversation::new(group))
    }

    /// Joins a group through a Welcome generated for one of this client's KeyPackages
    pub fn join_conversation(&self, welcome: &[u8]) -> Result<MlsConversation> {
        let message = MlsMessageIn::tls_deserialize_exact(welcome)
            .map_err(fail("Welcome decoding", ErrorKind::BadFormat))?;

        let welcome = match message.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(ErrorKind::UnexpectedMessage),
        };

        let config = MlsGroupJoinConfig::builder()
            .max_past_epochs(self.config.max_past_epochs)
            .padding_size(self.config.padding_size)
            .use_ratchet_tree_extension(true)
            .build();

        let builder = StagedWelcome::build_from_welcome(&self.provider, &config, welcome)
            .map_err(fail("Welcome processing", ErrorKind::Rejected))?;

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

        let staged_welcome = builder
            .build()
            .map_err(fail("Welcome processing", ErrorKind::Rejected))?;

        for member in staged_welcome.members() {
            if !self
                .validator
                .validate(&member.credential, &member.signature_key)
            {
                return Err(ErrorKind::InvalidCredential);
            }
        }

        let group = staged_welcome
            .into_group(&self.provider)
            .map_err(fail("joining group", ErrorKind::Storage))?;

        Ok(MlsConversation::new(group))
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
