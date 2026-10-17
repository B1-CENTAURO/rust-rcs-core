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
use super::wire::{self, AuthenticatedData, SecretPayload, SecretPayloadType};
use super::PROPOSAL_RCS_SIGNATURE;

pub struct DecryptedMessage {
    pub sender: Credential,
    pub payload_type: SecretPayloadType,
    /// For Application payloads, the CPIM message without its unencrypted headers
    pub payload: Vec<u8>,
    /// Original-Message-Id bound to the message, empty unless re-sent
    pub original_message_id: Vec<u8>,
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
        if self.is_encryption_ended() {
            return Err(ErrorKind::InvalidState);
        }
        let era = self.era().ok_or(ErrorKind::InvalidState)?;

        let authenticated_data = wire::encode(&AuthenticatedData::new(
            message_id,
            original_message_id,
            era,
        ))?;
        let payload = wire::encode(&SecretPayload::new(
            SecretPayloadType::Application,
            cpim.to_vec(),
        ))?;

        self.encrypt_with_aad(client, &payload, authenticated_data)
    }

    /// Decrypts an encrypted message received as `message/mls`
    ///
    /// `message_id` is the IMDN Message-ID of the CPIM message it arrived in, which
    /// has to match the one the sender bound to it (RCC.16 section 7.5.3.1).
    /// Messages of this client coming back fail with UnexpectedMessage.
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

        let (sender, data, authenticated_data) =
            match self.process_protocol_message(client, message)? {
                IncomingMessage::Application {
                    sender,
                    data,
                    authenticated_data,
                } => (sender, data, authenticated_data),
                _ => return Err(ErrorKind::UnexpectedMessage),
            };

        let authenticated_data: AuthenticatedData = wire::decode(&authenticated_data)?;
        if authenticated_data.message_id.as_slice() != message_id
            || Some(authenticated_data.era_id) != self.era()
        {
            return Err(ErrorKind::Rejected);
        }

        let secret_payload: SecretPayload = wire::decode(&data)?;

        Ok(DecryptedMessage {
            sender,
            payload_type: secret_payload.payload_type,
            payload: secret_payload.payload.into(),
            original_message_id: authenticated_data.original_message_id.into(),
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
                client.signer(),
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
