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

//! Re-Sent Messages after a Fail to Decrypt (RCC.16 sections 7.5.4, 10.3, 10.4, Annex C.4)
//!
//! The Original Message is encrypted with HPKE to the leaf key of the client that
//! failed to decrypt it, and that ciphertext is sent to the whole group as an
//! ordinary encrypted message. An HMAC of the Original Message goes along, by
//! which the members that did decrypt it can tell whether they were sent the
//! same message (Annex C.4.3).

use openmls::prelude::{Ciphersuite, Credential, HpkeCiphertext};
use openmls::treesync::EncryptionKey;
use openmls_traits::storage::{traits, Entity, StorageProvider, CURRENT_VERSION};
use openmls_traits::types::HpkePrivateKey;
use openmls_traits::{crypto::OpenMlsCrypto, random::OpenMlsRand, OpenMlsProvider};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::super::client::MlsClient;
use super::super::conversation::MlsConversation;
use super::super::{fail, ErrorKind, Result};
use super::file;
use super::messaging::ResentFailure;
use super::wire::{
    self, AuthenticatedData, HpkeInnerEncapsulatedKeyAndCiphertext, ResentMessage,
    SecretPayloadType, VerifiableDerivedContent, VerifiableResentMessage,
};

const DISCRIMINANT: &[u8; 26] = b"MLSv1 RCSv1 1:1 Encryption";

/// What the inner encryption is bound to, encoded as HPKEAADStruct and, behind
/// the discriminant, as OuterInfo
struct Binding {
    group_id: [u8; 32],
    epoch: u64,
    era: u32,
    receiver_leaf_index: u32,
    sender_leaf_index: u32,
}

impl Binding {
    fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(52);
        aad.extend_from_slice(&self.group_id);
        aad.extend_from_slice(&self.epoch.to_be_bytes());
        aad.extend_from_slice(&self.era.to_be_bytes());
        aad.extend_from_slice(&self.receiver_leaf_index.to_be_bytes());
        aad.extend_from_slice(&self.sender_leaf_index.to_be_bytes());
        aad
    }

    fn info(&self) -> Vec<u8> {
        [&DISCRIMINANT[..], &self.aad()].concat()
    }
}

/// `opaque group_id[32]`: RCC.16 does not say how group ids of other lengths fit,
/// so those are hashed with SHA-256; the 1-to-1 group ids `MlsClient` generates,
/// GUIDs in 32 hex digits, fit as they are
fn fixed_group_id(group_id: &[u8]) -> [u8; 32] {
    match group_id.try_into() {
        Ok(group_id) => group_id,
        Err(_) => Sha256::digest(group_id).into(),
    }
}

/// HPKE key pair of a tree node, as OpenMLS stores it (`EncryptionKeyPair` is
/// private to OpenMLS)
#[derive(Serialize, Deserialize)]
struct LeafKeyPair {
    public_key: EncryptionKey,
    private_key: LeafPrivateKey,
}

#[derive(Serialize, Deserialize)]
struct LeafPrivateKey {
    key: HpkePrivateKey,
}

impl Entity<CURRENT_VERSION> for LeafKeyPair {}
impl traits::HpkeKeyPair<CURRENT_VERSION> for LeafKeyPair {}

/// HMAC of the group's Cipher Suite, which is HKDF-Extract with the key as salt
fn hmac(client: &MlsClient, ciphersuite: Ciphersuite, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    client
        .provider()
        .crypto()
        .hkdf_extract(ciphersuite.hash_algorithm(), key, data)
        .map(|tag| tag.as_slice().to_vec())
        .map_err(fail("HMAC", ErrorKind::Crypto))
}

impl MlsConversation {
    /// Re-sends an Original Message to the client that reported failing to decrypt
    /// it (RCC.16 section 10.3)
    ///
    /// `original_cpim` is the CPIM message as originally encrypted, which only the
    /// client of `recipient` can read. `message_id` is the IMDN Message-ID of the
    /// new CPIM message, which carries `original_message_id` in its
    /// Original-Message-ID header. RCC.16 has a key update follow.
    pub fn encrypt_resent(
        &mut self,
        client: &MlsClient,
        original_cpim: &[u8],
        recipient: &Credential,
        message_id: &[u8],
        original_message_id: &[u8],
    ) -> Result<Vec<u8>> {
        self.seal_resent(
            client,
            original_cpim,
            original_cpim,
            recipient,
            message_id,
            original_message_id,
        )
    }

    /// encrypt_resent(), with the HMAC of `hmac_of`, which is the
    /// `original_cpim` sealed but for tests
    fn seal_resent(
        &mut self,
        client: &MlsClient,
        original_cpim: &[u8],
        hmac_of: &[u8],
        recipient: &Credential,
        message_id: &[u8],
        original_message_id: &[u8],
    ) -> Result<Vec<u8>> {
        let era = self.era().ok_or(ErrorKind::InvalidState)?;

        let receiver = self
            .group
            .members()
            .find(|member| &member.credential == recipient)
            .ok_or(ErrorKind::UnknownMember)?;

        let binding = Binding {
            group_id: fixed_group_id(self.group_id()),
            epoch: self.epoch(),
            era,
            receiver_leaf_index: receiver.index.u32(),
            sender_leaf_index: self.group.own_leaf_index().u32(),
        };

        // padded as PADME does for files, the length of the padding being unspecified
        let padding = file::padme(original_cpim.len() as u64) as usize - original_cpim.len();
        let resent = wire::encode(&ResentMessage {
            original_message: original_cpim.into(),
            padding: vec![0; padding].into(),
        })?;

        let sealed = client
            .provider()
            .crypto()
            .hpke_seal(
                self.group.ciphersuite().hpke_config(),
                &receiver.encryption_key,
                &binding.info(),
                &binding.aad(),
                &resent,
            )
            .map_err(fail("HPKE encryption", ErrorKind::Crypto))?;

        // hmac_key || hmac_tag, the key as long as the tag
        let ciphersuite = self.group.ciphersuite();
        let hmac_key = client
            .provider()
            .rand()
            .random_vec(ciphersuite.hash_length())
            .map_err(fail("HMAC key generation", ErrorKind::Crypto))?;
        let hmac_tag = hmac(client, ciphersuite, &hmac_key, hmac_of)?;

        let inner = wire::encode(&HpkeInnerEncapsulatedKeyAndCiphertext {
            receiver_leaf_index: binding.receiver_leaf_index,
            encapsulated_key: sealed.kem_output,
            ciphertext: sealed.ciphertext,
            original_message_hmac: [hmac_key, hmac_tag].concat().into(),
        })?;

        let authenticated_data = AuthenticatedData::new(
            message_id,
            original_message_id,
            era,
            VerifiableDerivedContent::ResentMessage(VerifiableResentMessage::new(
                original_message_id,
            )),
        );
        self.encrypt_secret_payload(
            client,
            SecretPayloadType::Hpke1To1Message,
            inner,
            &authenticated_data,
        )
    }

    /// Whether the Original Message of a Re-Sent Message decrypted by another
    /// member is the `original_contents` this client decrypted earlier (RCC.16
    /// Annex C.4.2); a mismatch points at members being shown different messages
    ///
    /// `original_message_hmac` is the one of the DecryptedMessage.
    pub fn resent_matches(
        &self,
        client: &MlsClient,
        original_message_hmac: &[u8],
        original_contents: &[u8],
    ) -> Result<bool> {
        let ciphersuite = self.group.ciphersuite();
        let tag_length = ciphersuite.hash_length();
        if original_message_hmac.len() <= tag_length {
            return Err(ErrorKind::BadFormat);
        }

        let (hmac_key, hmac_tag) =
            original_message_hmac.split_at(original_message_hmac.len() - tag_length);
        Ok(hmac(client, ciphersuite, hmac_key, original_contents)? == hmac_tag)
    }

    /// Opens the inner layer of a Re-Sent Message sent in `epoch` by the client
    /// with `sender_leaf_index`: its Original Message, None when it is
    /// addressed to another client, or why it gave none (RCC.16 section 10.4,
    /// Annex C.4.2). Also returns the original_message_hmac.
    pub(super) fn open_resent(
        &self,
        client: &MlsClient,
        inner: &[u8],
        epoch: u64,
        sender_leaf_index: u32,
    ) -> Result<(std::result::Result<Option<Vec<u8>>, ResentFailure>, Vec<u8>)> {
        let inner: HpkeInnerEncapsulatedKeyAndCiphertext = wire::decode(inner)?;
        let original_message_hmac: Vec<u8> = inner.original_message_hmac.into();

        let own_leaf_index = self.group.own_leaf_index().u32();
        if inner.receiver_leaf_index != own_leaf_index {
            return Ok((Ok(None), original_message_hmac));
        }

        let binding = Binding {
            group_id: fixed_group_id(self.group_id()),
            epoch,
            era: self.era().ok_or(ErrorKind::InvalidState)?,
            receiver_leaf_index: own_leaf_index,
            sender_leaf_index,
        };

        // stored along with the path keys of the current epoch; a message sealed
        // to a leaf key replaced since cannot be opened anymore
        let own_leaf = self.group.own_leaf().ok_or(ErrorKind::InvalidState)?;
        let key_pairs: Vec<LeafKeyPair> = client
            .provider()
            .storage()
            .encryption_epoch_key_pairs(self.group.group_id(), &self.group.epoch(), own_leaf_index)
            .map_err(fail("reading leaf key", ErrorKind::Storage))?;
        let Some(key_pair) = key_pairs
            .iter()
            .find(|key_pair| &key_pair.public_key == own_leaf.encryption_key())
        else {
            return Ok((Err(ResentFailure::NotDecrypted), original_message_hmac));
        };

        let opened = client.provider().crypto().hpke_open(
            self.group.ciphersuite().hpke_config(),
            &HpkeCiphertext {
                kem_output: inner.encapsulated_key,
                ciphertext: inner.ciphertext,
            },
            &key_pair.private_key.key,
            &binding.info(),
            &binding.aad(),
        );
        let resent = match opened {
            Ok(resent) => resent,
            Err(e) => {
                fail("HPKE decryption", ErrorKind::Rejected)(e);
                return Ok((Err(ResentFailure::NotDecrypted), original_message_hmac));
            }
        };

        let resent: ResentMessage = wire::decode(&resent)?;
        let original_message: Vec<u8> = resent.original_message.into();
        if !self.resent_matches(client, &original_message_hmac, &original_message)? {
            return Ok((Err(ResentFailure::NotMatching), original_message_hmac));
        }

        Ok((Ok(Some(original_message)), original_message_hmac))
    }

    /// encrypt_resent(), with the HMAC of `hmac_of` rather than of the
    /// Original Message
    #[cfg(test)]
    pub(crate) fn encrypt_resent_mismatched(
        &mut self,
        client: &MlsClient,
        original_cpim: &[u8],
        hmac_of: &[u8],
        recipient: &Credential,
        message_id: &[u8],
        original_message_id: &[u8],
    ) -> Result<Vec<u8>> {
        self.seal_resent(
            client,
            original_cpim,
            hmac_of,
            recipient,
            message_id,
            original_message_id,
        )
    }
}
