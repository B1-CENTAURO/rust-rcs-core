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

//! Messaging Layer Security (RFC 9420) on top of OpenMLS
//!
//! Universal Profile 3.0 bases end-to-end encryption on MLS. `MlsClient` and
//! `MlsConversation` cover identities, KeyPackages, group lifecycle and message
//! protection, set up the way GSMA RCC.16 requires; the `rcs` module holds the
//! RCC.16 wire formats and procedures. Carrying the results over SIP / MSRP,
//! talking to the KDS and certifying credentials is left to the caller.

pub mod client;
pub mod conversation;
pub mod provider;
pub mod rcs;

#[cfg(test)]
mod tests;

pub use openmls::prelude::{Ciphersuite, Credential, CredentialType};
/// The signature key of a client, made with `SignatureKeyPair::new()` for the
/// signature scheme of its ciphersuite, its public key certified by the Home KDS
pub use openmls_basic_credential::SignatureKeyPair;

pub use client::{Clock, CredentialValidator, MlsClient, MlsConfig};
pub use conversation::{
    inspect, key_package_info, CommitOutput, IncomingMessage, KeyPackageInfo, MessageKind,
    MlsConversation,
};
pub use provider::MlsProvider;

use crate::ffi::log::platform_log;

const LOG_TAG: &str = "mls";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// Input could not be decoded as the expected MLS structure
    BadFormat,
    /// Input is a valid MLS message, but not one that can be handled here
    UnexpectedMessage,
    /// No group with the given id exists in local state
    UnknownGroup,
    /// A referenced member is not part of the group
    UnknownMember,
    /// A credential was refused by the CredentialValidator
    InvalidCredential,
    /// The message failed MLS validation (signature, epoch, membership...)
    Rejected,
    /// The operation is not allowed in the current group state
    InvalidState,
    /// Key generation or another cryptographic operation failed
    Crypto,
    /// Reading or writing local state failed
    Storage,
}

pub type Result<T> = std::result::Result<T, ErrorKind>;

/// Logs the underlying OpenMLS error and maps it to `kind`
pub(crate) fn fail<E: std::fmt::Debug>(
    operation: &'static str,
    kind: ErrorKind,
) -> impl FnOnce(E) -> ErrorKind {
    move |e| {
        platform_log(LOG_TAG, format!("{} failed: {:?}", operation, e));
        kind
    }
}
