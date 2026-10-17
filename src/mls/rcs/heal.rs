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

//! Enhanced self-healing: catching up on the control messages the Conversation
//! Focus accepted since the epoch this client is in, before resorting to an
//! External Commit (RCC.16 sections 6.3.2, 7.10.2 to 7.10.5, 10.1.2)

use super::super::client::MlsClient;
use super::super::conversation::{IncomingMessage, MlsConversation};
use super::super::{ErrorKind, Result};
use super::proto::{self, MlsEnhancedGroupInfo, MlsGroupInfo};

/// Where enhanced self-healing stands after a response
#[derive(Debug, PartialEq)]
pub enum SelfHealProgress {
    /// The group is in the latest epoch the Conversation Focus knows of
    UpToDate,
    /// More control messages are left, to be asked for with another
    /// `enhanced_group_info_request()`
    NextPage,
    /// The control messages cannot bring the group up to date: heal with an
    /// External Commit, through `MlsClient::rejoin_conversation()` with this
    /// GroupInfo
    Rejoin(MlsGroupInfo),
}

pub struct EnhancedSelfHeal {
    pub progress: SelfHealProgress,
    /// What was applied, by the RCS Message-ID of each control message; these
    /// get no IMDN unless delivered over MSRP as well, where they come out as
    /// Duplicate (RCC.16 section 10.1.2)
    pub applied: Vec<(String, Vec<IncomingMessage>)>,
}

impl MlsConversation {
    /// Body of an MLS-Enhanced-Group-Info-Pull INFO request, of Content-Type
    /// `rcs::CONTENT_TYPE_MLS_RCS`, asking for what came after the current epoch
    /// (RCC.16 sections 6.3.2, 7.10.2)
    pub fn enhanced_group_info_request(&self) -> Vec<u8> {
        proto::encode(&self.epoch_identifier())
    }

    /// Applies the control messages of the MlsEnhancedGroupInfo in the 200 OK to
    /// an MLS-Enhanced-Group-Info-Pull request (RCC.16 section 10.1.2)
    ///
    /// Messages of epochs already applied are skipped. Should one fail, the rest
    /// are left alone and the group is to be rejoined.
    pub fn process_enhanced_group_info(
        &mut self,
        client: &MlsClient,
        body: &[u8],
    ) -> Result<EnhancedSelfHeal> {
        let info: MlsEnhancedGroupInfo = proto::decode(body)?;
        let latest = info.latest_epoch_identifier.ok_or(ErrorKind::BadFormat)?;
        let rejoin = || {
            info.mls_group_info
                .clone()
                .map(SelfHealProgress::Rejoin)
                .ok_or(ErrorKind::BadFormat)
        };

        let mut applied = Vec::new();
        if latest == self.epoch_identifier() {
            return Ok(EnhancedSelfHeal {
                progress: SelfHealProgress::UpToDate,
                applied,
            });
        }

        // the epoch of this client is unknown to the Conversation Focus, or the
        // control messages since are not offered
        let Some(paginated) = info.paginated_epoch_identifier.clone() else {
            return Ok(EnhancedSelfHeal {
                progress: rejoin()?,
                applied,
            });
        };

        for control_messages in &info.committed_control_messages {
            let processed = match control_messages.server_mls_rcs_message.clone() {
                Some(message) => self.process_server_mls_rcs_message(client, message),
                None => Err(ErrorKind::BadFormat),
            };
            match processed {
                Ok(messages) => applied.push((control_messages.rcs_message_id.clone(), messages)),
                Err(_) => {
                    return Ok(EnhancedSelfHeal {
                        progress: rejoin()?,
                        applied,
                    })
                }
            }
        }

        let progress = if self.epoch_identifier() != paginated {
            rejoin()?
        } else if paginated == latest {
            SelfHealProgress::UpToDate
        } else {
            SelfHealProgress::NextPage
        };
        Ok(EnhancedSelfHeal { progress, applied })
    }
}
