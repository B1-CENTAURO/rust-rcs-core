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

//! When this client updates its keys in a group, and replaces the leaves of
//! other members (RCC.16 sections 9.5.2, 9.5.4)

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openmls::prelude::{Credential, ExtensionType, Member};

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

/// Leaf keys of other members not updated for longer than this are replaced
/// with a KeyPackage Update (RCC.16 section 9.5.4)
pub const LEAF_KEY_MAX_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

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
pub(crate) fn own_leaf_key(group_id: &[u8]) -> Vec<u8> {
    [&b"RcsOwnLeaf"[..], group_id].concat()
}

/// When this client first saw each leaf key of a group: the encryption key
/// of the leaf, and the time in seconds since the Unix epoch
#[derive(Debug, Default, PartialEq)]
struct LeafKeys(Vec<(Vec<u8>, u64)>);

impl LeafKeys {
    fn encode(&self) -> Vec<u8> {
        let mut value = Vec::new();
        for (key, seen) in &self.0 {
            value.extend_from_slice(&(key.len() as u16).to_be_bytes());
            value.extend_from_slice(key);
            value.extend_from_slice(&seen.to_be_bytes());
        }
        value
    }

    fn decode(mut value: &[u8]) -> Result<LeafKeys> {
        let mut leaf_keys = Vec::new();
        while !value.is_empty() {
            let length = usize::from(u16::from_be_bytes(
                value
                    .get(..2)
                    .ok_or(ErrorKind::BadFormat)?
                    .try_into()
                    .unwrap(),
            ));
            let key = value.get(2..2 + length).ok_or(ErrorKind::BadFormat)?;
            let seen = value
                .get(2 + length..10 + length)
                .ok_or(ErrorKind::BadFormat)?;
            leaf_keys.push((key.to_vec(), u64::from_be_bytes(seen.try_into().unwrap())));
            value = &value[10 + length..];
        }
        Ok(LeafKeys(leaf_keys))
    }

    fn first_seen(&self, key: &[u8]) -> Option<u64> {
        self.0
            .iter()
            .find(|(seen_key, _)| seen_key == key)
            .map(|(_, seen)| *seen)
    }
}

/// Storage key of when this client first saw each leaf key of the group
/// `group_id`, apart from the keys OpenMLS uses
pub(crate) fn leaf_keys_key(group_id: &[u8]) -> Vec<u8> {
    [&b"RcsLeafKeys"[..], group_id].concat()
}

fn seconds_since_epoch(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

impl MlsConversation {
    /// Whether this client is to update its keys in the group now, as it
    /// tells the time, with `update_keys()` (RCC.16 section 9.5.2): once the
    /// maximum number of days or of messages sent since its leaf was last
    /// updated is reached, and not before the minimum number of days, by the
    /// intervals of `INITIAL_LAST_RESORT_KEY_UPDATE` if it joined with a last
    /// resort KeyPackage and has not updated its leaf since, else of
    /// `REGULAR_KEY_UPDATE`
    ///
    /// One is due at once, too, while the leaf has another credential than
    /// the client, which renewed its certificate since: the key update brings
    /// the new one into the group (section 9.5.3).
    ///
    /// Never in a group moved to unencrypted, nor in one this client is no
    /// longer a member of. A group with no record of when its leaf was last
    /// updated, as one joined before such records were kept, is due.
    pub fn key_update_due(&self, client: &MlsClient) -> Result<bool> {
        if self.is_encryption_ended() || !self.is_active() {
            return Ok(false);
        }
        if self.credential_outdated(client) {
            return Ok(true);
        }
        let Some(own_leaf) = self.own_leaf(client)? else {
            return Ok(true);
        };

        let interval = own_leaf.interval();
        let elapsed =
            Duration::from_secs(seconds_since_epoch(client.now()).saturating_sub(own_leaf.updated));
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
            updated: seconds_since_epoch(client.now()),
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

    /// Has this client update its keys in the group at once, as after it
    /// re-sent a message (RCC.16 section 10.3): `key_update_due()` tells so,
    /// as if its leaf had never been updated, until it does
    pub fn want_key_update(&self, client: &MlsClient) -> Result<()> {
        let Some(mut own_leaf) = self.own_leaf(client)? else {
            return Ok(());
        };
        own_leaf.updated = 0;
        client
            .provider()
            .write_value(own_leaf_key(self.group_id()), own_leaf.encode())
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

    /// The Clients of other members whose leaves this client is to replace
    /// with `replace_members()`, as it tells the time (RCC.16 section
    /// 9.5.4): those whose credential expired, or no longer passes the
    /// validator otherwise, and those whose leaf keys were not updated in
    /// over 30 days, since this client first saw them (`LEAF_KEY_MAX_AGE`)
    ///
    /// Not those leaving, whose self_remove a Commit is to take. None in a
    /// group moved to unencrypted, nor in one this client is no longer a
    /// member of. A leaf key this client has no record of, as one of a group
    /// joined before such records were kept, is not counted as old.
    pub fn stale_members(&self, client: &MlsClient) -> Result<Vec<Credential>> {
        if self.is_encryption_ended() || !self.is_active() {
            return Ok(Vec::new());
        }
        let leaf_keys = self.leaf_keys(client)?;
        let now = seconds_since_epoch(client.now());

        Ok(self.others(|member| {
            !client
                .validator()
                .validate(&member.credential, &member.signature_key)
                || leaf_keys
                    .first_seen(&member.encryption_key)
                    .is_some_and(|seen| now.saturating_sub(seen) > LEAF_KEY_MAX_AGE.as_secs())
        }))
    }

    /// The Clients of other members whose credential expired, or no longer
    /// passes the validator otherwise, as this client tells the time: those
    /// to replace when moving the group back to encrypted with `resurrect()`
    /// (RCC.16 section 11.1.2), whether it is encrypted or not
    ///
    /// Not those leaving, whose self_remove a Commit is to take.
    pub fn expired_members(&self, client: &MlsClient) -> Vec<Credential> {
        self.others(|member| {
            !client
                .validator()
                .validate(&member.credential, &member.signature_key)
        })
    }

    /// The credentials of the members besides this client and those leaving
    /// that `filter` keeps
    fn others(&self, filter: impl Fn(&Member) -> bool) -> Vec<Credential> {
        let own = self.group.own_leaf_index();
        let leaving = self.leaving_members();
        self.group
            .members()
            .filter(|member| member.index != own && !leaving.contains(&member.credential))
            .filter(|member| filter(member))
            .map(|member| member.credential)
            .collect()
    }

    fn leaf_keys(&self, client: &MlsClient) -> Result<LeafKeys> {
        Ok(client
            .provider()
            .read_value(&leaf_keys_key(self.group_id()))?
            .map(|value| LeafKeys::decode(&value))
            .transpose()?
            .unwrap_or_default())
    }

    /// Forgets when this client first saw the leaf keys of the group
    pub(crate) fn forget_leaf_keys(&self, client: &MlsClient) -> Result<()> {
        client
            .provider()
            .remove_value(&leaf_keys_key(self.group_id()))
    }

    /// Takes note of the leaf keys of the group this client sees for the
    /// first time, now that it joined it or moved to a new epoch, and
    /// forgets those no longer in it
    pub(crate) fn note_leaf_keys(&self, client: &MlsClient) -> Result<()> {
        let kept = self.leaf_keys(client)?;
        let now = seconds_since_epoch(client.now());
        let leaf_keys = LeafKeys(
            self.group
                .members()
                .map(|member| {
                    let seen = kept.first_seen(&member.encryption_key).unwrap_or(now);
                    (member.encryption_key, seen)
                })
                .collect(),
        );
        if leaf_keys == kept {
            return Ok(());
        }
        client
            .provider()
            .write_value(leaf_keys_key(self.group_id()), leaf_keys.encode())
    }
}
