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

//! Encrypted and signed messages (RCC.16 sections 7.5, 7.6, 9.1)

use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;

use super::super::client::MlsClient;
use super::super::conversation::{IncomingMessage, MlsConversation};
use super::super::{fail, ErrorKind, Result};
use super::wire::{
    self, AuthenticatedData, SecretPayload, SecretPayloadType, VerifiableDerivedContent,
};
use super::PROPOSAL_RCS_SIGNATURE;

pub struct DecryptedMessage {
    pub sender: Credential,
    pub payload_type: SecretPayloadType,
    /// The CPIM message without its unencrypted headers; for a Re-Sent Message,
    /// the Original Message, or None when it was re-sent to another client
    pub payload: Option<Vec<u8>>,
    /// Original-Message-ID bound to the message, empty unless re-sent
    pub original_message_id: Vec<u8>,
    /// For a Re-Sent Message, what `resent_matches()` checks the Original
    /// Message against; empty otherwise
    pub original_message_hmac: Vec<u8>,
}

impl MlsConversation {
    /// Encrypts a CPIM message into the MlsMessage to send as `message/mls`
    /// (RCC.16 sections 7.5.1 to 7.5.3)
    ///
    /// `cpim` holds the CPIM namespaces other than IMDN, the headers not listed by
    /// `is_unencrypted_cpim_header()` and the MIME body. `message_id` is the IMDN
    /// Message-ID of the enclosing CPIM message, which receivers check.
    pub fn encrypt_cpim(
        &mut self,
        client: &MlsClient,
        cpim: &[u8],
        message_id: &[u8],
        original_message_id: &[u8],
    ) -> Result<Vec<u8>> {
        let authenticated_data = AuthenticatedData::new(
            message_id,
            original_message_id,
            self.era().ok_or(ErrorKind::InvalidState)?,
            VerifiableDerivedContent::None,
        );
        self.encrypt_secret_payload(
            client,
            SecretPayloadType::Application,
            cpim.to_vec(),
            &authenticated_data,
        )
    }

    /// Encrypts a SecretPayload of `payload_type` (RCC.16 sections 7.5.1 to 7.5.3)
    pub(crate) fn encrypt_secret_payload(
        &mut self,
        client: &MlsClient,
        payload_type: SecretPayloadType,
        payload: Vec<u8>,
        authenticated_data: &AuthenticatedData,
    ) -> Result<Vec<u8>> {
        if self.is_encryption_ended() {
            return Err(ErrorKind::InvalidState);
        }

        let payload = wire::encode(&SecretPayload::new(
            payload_type,
            self.key_generation(client)?,
            payload,
        ))?;

        let message = self.encrypt_with_aad(client, &payload, wire::encode(authenticated_data)?)?;
        // towards the next key update (RCC.16 section 9.5.2)
        self.count_sent(client)?;
        Ok(message)
    }

    /// Decrypts an encrypted message received as `message/mls`
    ///
    /// `message_id` is the IMDN Message-ID of the CPIM message it arrived in, which
    /// has to match the one the sender bound to it (RCC.16 section 7.5.3.1).
    /// Messages of this client coming back fail with UnexpectedMessage.
    ///
    /// The key_generation of the SecretPayload is not checked against the one of
    /// the PrivateMessage (section 9.1.1): OpenMLS does not tell the latter.
    pub fn decrypt(
        &mut self,
        client: &MlsClient,
        message: &[u8],
        message_id: &[u8],
    ) -> Result<DecryptedMessage> {
        let message = self.decode(message)?;
        if message.content_type() != ContentType::Application {
            return Err(ErrorKind::UnexpectedMessage);
        }
        let epoch = message.epoch().as_u64();

        let (sender, sender_leaf_index, data, authenticated_data) =
            match self.process_protocol_message(client, message)? {
                IncomingMessage::Application {
                    sender,
                    sender_leaf_index,
                    data,
                    authenticated_data,
                } => (sender, sender_leaf_index, data, authenticated_data),
                _ => return Err(ErrorKind::UnexpectedMessage),
            };

        let authenticated_data: AuthenticatedData = wire::decode(&authenticated_data)?;
        if authenticated_data.message_id.as_slice() != message_id
            || Some(authenticated_data.era_id) != self.era()
        {
            return Err(ErrorKind::Rejected);
        }

        let secret_payload: SecretPayload = wire::decode(&data)?;

        // a Re-Sent Message names its Original Message in either place
        let mut original_message_id: Vec<u8> = authenticated_data.original_message_id.into();
        if let VerifiableDerivedContent::ResentMessage(resent) =
            &authenticated_data.verifiable_derived_content
        {
            if original_message_id.is_empty() {
                original_message_id = resent.original_content_message_id.as_slice().to_vec();
            }
        }

        let mut original_message_hmac = Vec::new();
        let payload = match secret_payload.payload_type {
            SecretPayloadType::Application | SecretPayloadType::GroupMetadataKeys => {
                Some(secret_payload.payload.into())
            }
            SecretPayloadType::Hpke1To1Message => {
                let (payload, hmac) = self.open_resent(
                    client,
                    secret_payload.payload.as_slice(),
                    epoch,
                    sender_leaf_index,
                )?;
                original_message_hmac = hmac;
                payload
            }
        };

        Ok(DecryptedMessage {
            sender,
            payload_type: secret_payload.payload_type,
            payload,
            original_message_id,
            original_message_hmac,
        })
    }

    /// Signs content that is sent unencrypted, such as IMDNs (RCC.16 section 7.6.1)
    ///
    /// `derived_content` is one of the Verifiable* structures of `wire`, encoded.
    /// The result goes Base64 encoded into the MLS-Derived-Content-Signature header.
    pub fn sign(&mut self, client: &MlsClient, derived_content: &[u8]) -> Result<Vec<u8>> {
        self.group.set_aad(derived_content.to_vec());

        let (message, proposal_ref) = self
            .group
            .propose_custom_proposal_by_value(
                client.provider(),
                &self.signer(client)?,
                CustomProposal::new(PROPOSAL_RCS_SIGNATURE, Vec::new()),
            )
            .map_err(fail("signing", ErrorKind::InvalidState))?;

        // only a carrier for the signature, never to be committed
        self.group
            .remove_pending_proposal(client.provider().storage(), &proposal_ref)
            .map_err(fail("dropping signature proposal", ErrorKind::Storage))?;

        message
            .to_bytes()
            .map_err(fail("signature encoding", ErrorKind::BadFormat))
    }

    /// Checks a decoded MLS-Derived-Content-Signature header against the
    /// content derived from the received message, returning the signer
    /// (RCC.16 section 7.6.2)
    pub fn verify_signature(
        &mut self,
        client: &MlsClient,
        signature: &[u8],
        derived_content: &[u8],
    ) -> Result<Credential> {
        let message = self.decode(signature)?;
        if message.wire_format() != WireFormat::PublicMessage {
            return Err(ErrorKind::Rejected);
        }

        let processed = self
            .group
            .process_message(client.provider(), message)
            .map_err(fail("signature verification", ErrorKind::Rejected))?;

        if processed.aad() != derived_content {
            return Err(ErrorKind::Rejected);
        }

        let sender = processed.credential().clone();
        match processed.into_content() {
            ProcessedMessageContent::ProposalMessage(proposal)
                if proposal.proposal().proposal_type()
                    == ProposalType::Custom(PROPOSAL_RCS_SIGNATURE) =>
            {
                Ok(sender)
            }
            _ => Err(ErrorKind::Rejected),
        }
    }
}
