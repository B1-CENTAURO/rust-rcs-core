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

//! When this client updates its keys in a group (RCC.16 section 9.5.2)

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openmls::prelude::ExtensionType;

use super::super::client::MlsClient;
use super::super::conversation::MlsConversation;
use super::super::{ErrorKind, Result};

/// When a key update is due: not before `min`, and once `max` passed or
/// `max_messages` were sent since the leaf was last updated, whichever comes
/// first (RCC.16 section 9.5.2, Table 7)
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct KeyUpdateInterval {
    pub min: Duration,
    pub max: Duration,
    pub max_messages: u32,
}

const DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// The first key update after joining with a last resort KeyPackage
pub const INITIAL_LAST_RESORT_KEY_UPDATE: KeyUpdateInterval = KeyUpdateInterval {
    min: Duration::ZERO,
    max: DAY,
    max_messages: 30,
};

/// All other key updates
pub const REGULAR_KEY_UPDATE: KeyUpdateInterval = KeyUpdateInterval {
    min: Duration::from_secs(7 * 24 * 60 * 60),
    max: Duration::from_secs(30 * 24 * 60 * 60),
    max_messages: 50,
};

/// What is kept of the leaf of this client in a group
#[derive(Debug, PartialEq)]
struct OwnLeaf {
    /// When it was last updated, in seconds since the Unix epoch
    updated: u64,
    /// The messages this client encrypted since
    sent: u32,
    /// Whether it came from a last resort KeyPackage
    last_resort: bool,
}

impl OwnLeaf {
    fn encode(&self) -> Vec<u8> {
        let mut value = Vec::with_capacity(13);
        value.extend_from_slice(&self.updated.to_be_bytes());
        value.extend_from_slice(&self.sent.to_be_bytes());
        value.push(self.last_resort as u8);
        value
    }

    fn decode(value: &[u8]) -> Result<OwnLeaf> {
        if value.len() != 13 {
            return Err(ErrorKind::BadFormat);
        }
        Ok(OwnLeaf {
            updated: u64::from_be_bytes(value[..8].try_into().unwrap()),
            sent: u32::from_be_bytes(value[8..12].try_into().unwrap()),
            last_resort: value[12] != 0,
        })
    }

    fn interval(&self) -> KeyUpdateInterval {
        if self.last_resort {
            INITIAL_LAST_RESORT_KEY_UPDATE
        } else {
            REGULAR_KEY_UPDATE
        }
    }
}

/// Storage key of what is kept of the leaf of this client in the group
/// `group_id`, apart from the keys OpenMLS uses
fn own_leaf_key(group_id: &[u8]) -> Vec<u8> {
    [&b"RcsOwnLeaf"[..], group_id].concat()
}

fn seconds_since_epoch(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

impl MlsConversation {
    /// Whether this client is to update its keys in the group at `now`, with
    /// `update_keys()` (RCC.16 section 9.5.2): once the maximum number of days
    /// or of messages sent since its leaf was last updated is reached, and not
    /// before the minimum number of days, by the intervals of
    /// `INITIAL_LAST_RESORT_KEY_UPDATE` if it joined with a last resort
    /// KeyPackage and has not updated its leaf since, else of
    /// `REGULAR_KEY_UPDATE`
    ///
    /// Never in a group moved to unencrypted, nor in one this client is no
    /// longer a member of. A group with no record of when its leaf was last
    /// updated, as one joined before such records were kept, is due.
    pub fn key_update_due(&self, client: &MlsClient, now: SystemTime) -> Result<bool> {
        if self.is_encryption_ended() || !self.is_active() {
            return Ok(false);
        }
        let Some(own_leaf) = self.own_leaf(client)? else {
            return Ok(true);
        };

        let interval = own_leaf.interval();
        let elapsed =
            Duration::from_secs(seconds_since_epoch(now).saturating_sub(own_leaf.updated));
        Ok(elapsed >= interval.min
            && (elapsed >= interval.max || own_leaf.sent >= interval.max_messages))
    }

    fn own_leaf(&self, client: &MlsClient) -> Result<Option<OwnLeaf>> {
        client
            .provider()
            .read_value(&own_leaf_key(self.group_id()))?
            .map(|value| OwnLeaf::decode(&value))
            .transpose()
    }

    /// Takes note of the leaf of this client in the group being updated now:
    /// as the group is created or joined, or a Commit of this client with an
    /// UpdatePath is applied; `last_resort` if it comes from a last resort
    /// KeyPackage
    pub(crate) fn own_leaf_updated(&self, client: &MlsClient, last_resort: bool) -> Result<()> {
        let own_leaf = OwnLeaf {
            updated: seconds_since_epoch(SystemTime::now()),
            sent: 0,
            last_resort,
        };
        client
            .provider()
            .write_value(own_leaf_key(self.group_id()), own_leaf.encode())
    }

    /// Whether the leaf of this client in the group came from a last resort
    /// KeyPackage, as one joined through a Welcome is, by its capabilities,
    /// which list the last_resort extension for one only
    pub(crate) fn own_leaf_from_last_resort(&self) -> bool {
        self.group.own_leaf_node().is_some_and(|leaf_node| {
            leaf_node
                .capabilities()
                .extensions()
                .contains(&ExtensionType::LastResort)
        })
    }

    /// Counts a message this client encrypted towards its next key update
    pub(crate) fn count_sent(&self, client: &MlsClient) -> Result<()> {
        let Some(mut own_leaf) = self.own_leaf(client)? else {
            return Ok(());
        };
        own_leaf.sent = own_leaf.sent.saturating_add(1);
        client
            .provider()
            .write_value(own_leaf_key(self.group_id()), own_leaf.encode())
    }

    /// Forgets what is kept of the leaf of this client in the group
    pub(crate) fn forget_own_leaf(&self, client: &MlsClient) -> Result<()> {
        client
            .provider()
            .remove_value(&own_leaf_key(self.group_id()))
    }
}
