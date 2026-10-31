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

//! New Eras of a group (RCC.16 section 8.3)

use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::*;

use super::super::client::MlsClient;
use super::super::conversation::MlsConversation;
use super::super::{fail, ErrorKind, Result};
use super::certificate::{credential_tel_uris, same_tel_uri};
use super::{proto, EXTENSION_END_MLS, EXTENSION_ERA};

/// What the next Era of a group is made from: the group as the GroupInfo of
/// its Conversation Focus tells it, or else as this client has it (RCC.16
/// section 8.3.1)
#[derive(Clone, Debug)]
pub struct EraBase {
    group_id: Vec<u8>,
    era: u32,
    /// The GroupContext extensions besides the Era, which the next Era copies
    extensions: Vec<(u16, Vec<u8>)>,
    members: Vec<Credential>,
    /// Whether it is the group this client has
    local: bool,
}

/// The Era a GroupContext has, 0 without one
pub(crate) fn era_of(extensions: &Extensions<GroupContext>) -> u32 {
    era_and_extensions(extensions).0
}

/// The Era and the other extensions of a GroupContext
fn era_and_extensions(extensions: &Extensions<GroupContext>) -> (u32, Vec<(u16, Vec<u8>)>) {
    let mut era = 0;
    let mut others = Vec::new();
    for extension in extensions.iter() {
        if let Extension::Unknown(extension_type, UnknownExtension(data)) = extension {
            if *extension_type == EXTENSION_ERA {
                era = data
                    .as_slice()
                    .try_into()
                    .map(u32::from_be_bytes)
                    .unwrap_or(0);
            } else {
                others.push((*extension_type, data.clone()));
            }
        }
    }
    (era, others)
}

impl EraBase {
    /// The group as the MlsGroupInfo `group_info` of its Conversation Focus
    /// tells it (RCC.16 section 7.10.1), its members those of its ratchet tree
    pub fn of_group_info(group_info: &proto::MlsGroupInfo) -> Result<EraBase> {
        let message = MlsMessageIn::tls_deserialize_exact(&group_info.group_info)
            .map_err(fail("GroupInfo decoding", ErrorKind::BadFormat))?;
        let verifiable_group_info = match message.extract() {
            MlsMessageBodyIn::GroupInfo(group_info) => group_info,
            _ => return Err(ErrorKind::UnexpectedMessage),
        };
        let ratchet_tree = RatchetTreeIn::tls_deserialize_exact(&group_info.ratchet_tree)
            .map_err(fail("ratchet tree decoding", ErrorKind::BadFormat))?;

        let context = verifiable_group_info.group_context();
        let (era, extensions) = era_and_extensions(context.extensions());
        Ok(EraBase {
            group_id: context.group_id().as_slice().to_vec(),
            era,
            extensions,
            members: ratchet_tree
                .leaves()
                .map(|leaf_node| leaf_node.credential().clone())
                .collect(),
            local: false,
        })
    }

    /// The group as this client has it, for when its Conversation Focus no
    /// longer has it (RCC.16 section 8.3.1)
    pub fn of_conversation(conversation: &MlsConversation) -> EraBase {
        let (era, extensions) = era_and_extensions(conversation.group.extensions());
        EraBase {
            group_id: conversation.group_id().to_vec(),
            era,
            extensions,
            members: conversation.members(),
            local: true,
        }
    }

    pub fn group_id(&self) -> &[u8] {
        &self.group_id
    }

    /// The Era of the group, which the next one follows
    pub fn era(&self) -> u32 {
        self.era
    }

    pub fn members(&self) -> &[Credential] {
        &self.members
    }

    /// Whether the group was moved to unencrypted, having the end_mls
    /// extension (RCC.16 sections 10.1, 11.2)
    pub fn is_encryption_ended(&self) -> bool {
        self.extensions
            .iter()
            .any(|(extension_type, _)| *extension_type == EXTENSION_END_MLS)
    }

    /// The base of an Era moving the group back to encrypted, which copies
    /// its GroupContext extensions but end_mls (RCC.16 sections 8.3.1, 11.1)
    pub fn without_encryption_end(mut self) -> EraBase {
        self.extensions
            .retain(|(extension_type, _)| *extension_type != EXTENSION_END_MLS);
        self
    }

    /// Whether the continuity token kept for the group carries over to the
    /// next Era (RCC.16 section 8.3.1.2), `participants` the tel URIs of the
    /// Participants of the RCS conversation, and `local` the group this
    /// client has, if it has one
    ///
    /// It does not if a Participant is not a member of the group, by MSISDN,
    /// nor if the group has members that the group of this client does not
    /// have. Section 8.3.1.2 keeps the token in the latter case if the
    /// GroupInfo commits to it; but that commitment, made at the epoch
    /// authenticator of the GroupInfo, can only be checked by a client in the
    /// same epoch, whose group then has the same members. Without a group of
    /// its own to compare with, the token does not carry over: asking the
    /// members for it (section 8.3.1.3) is not done.
    pub fn continuity_holds(&self, local: Option<&MlsConversation>, participants: &[&str]) -> bool {
        let tel_uris = |members: &[Credential]| -> Vec<String> {
            members
                .iter()
                .flat_map(|member| credential_tel_uris(member).unwrap_or_default())
                .collect()
        };
        let has = |tel_uris: &[String], uri: &str| tel_uris.iter().any(|t| same_tel_uri(t, uri));
        let members = tel_uris(&self.members);
        if !participants
            .iter()
            .all(|participant| has(&members, participant))
        {
            return false;
        }
        if self.local {
            return true;
        }
        local
            .filter(|local| local.group_id() == self.group_id.as_slice())
            .is_some_and(|local| {
                let known = tel_uris(&local.members());
                members.iter().all(|member| has(&known, member))
            })
    }
}

impl MlsClient {
    /// Creates the next Era of the group `base` tells, with this client as its
    /// only member, in place of any group this client has of the Era before
    /// (RCC.16 section 8.3.1): its GroupContext extensions those of `base`,
    /// but for the Era, one more
    ///
    /// The continuity token kept for the group goes on in the next Era, unless
    /// `renew_continuity_token`, as continuity_holds() tells (section
    /// 8.3.1.2). Without a token kept, a new one is made. The keys of the icon
    /// and subject kept for the group go into the Welcome as for a new group,
    /// as far as they match the commitments copied.
    pub fn create_next_era(
        &self,
        base: &EraBase,
        renew_continuity_token: bool,
    ) -> Result<MlsConversation> {
        let era = base.era.checked_add(1).ok_or(ErrorKind::InvalidState)?;
        if let Ok(conversation) = self.load_conversation(&base.group_id) {
            conversation.delete(self)?;
        }
        if renew_continuity_token {
            self.renew_continuity_token(&base.group_id)?;
        }

        let mut extensions = vec![Extension::Unknown(
            EXTENSION_ERA,
            UnknownExtension(era.to_be_bytes().to_vec()),
        )];
        extensions.extend(base.extensions.iter().map(|(extension_type, data)| {
            Extension::Unknown(*extension_type, UnknownExtension(data.clone()))
        }));
        self.create_group(GroupId::from_slice(&base.group_id), extensions)
    }
}
