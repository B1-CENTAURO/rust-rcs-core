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

use std::collections::HashMap;

use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::OpenMlsProvider;

use super::{ErrorKind, Result};

/// Crypto and storage backend handed to OpenMLS
///
/// Everything OpenMLS persists (group states, private keys, KeyPackages awaiting a
/// Welcome) lives in memory and can be exported as a single blob, leaving it to
/// the platform to keep that blob safe at rest.
#[derive(Debug, Default)]
pub struct MlsProvider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl OpenMlsProvider for MlsProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

impl MlsProvider {
    pub(crate) fn export_storage(&self, out: &mut Vec<u8>) -> Result<()> {
        let values = self.storage.values.read().map_err(|_| ErrorKind::Storage)?;

        // sorted so that identical state always exports to identical bytes
        let mut entries: Vec<(&Vec<u8>, &Vec<u8>)> = values.iter().collect();
        entries.sort();

        out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for (k, v) in entries {
            write_bytes(out, k);
            write_bytes(out, v);
        }

        Ok(())
    }

    /// Value this crate keeps next to the state of OpenMLS, under a key starting
    /// with a label of its own; OpenMLS labels its keys likewise
    pub(crate) fn read_value(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let values = self.storage.values.read().map_err(|_| ErrorKind::Storage)?;
        Ok(values.get(key).cloned())
    }

    pub(crate) fn write_value(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        let mut values = self
            .storage
            .values
            .write()
            .map_err(|_| ErrorKind::Storage)?;
        values.insert(key, value);
        Ok(())
    }

    pub(crate) fn remove_value(&self, key: &[u8]) -> Result<()> {
        let mut values = self
            .storage
            .values
            .write()
            .map_err(|_| ErrorKind::Storage)?;
        values.remove(key);
        Ok(())
    }

    /// Copy of the state, to try out changes on
    pub(crate) fn fork(&self) -> Result<MlsProvider> {
        let values = self.storage.values.read().map_err(|_| ErrorKind::Storage)?;

        Ok(MlsProvider {
            crypto: RustCrypto::default(),
            storage: MemoryStorage {
                values: values.clone().into(),
            },
        })
    }

    pub(crate) fn import_storage(data: &mut &[u8]) -> Result<MlsProvider> {
        let count = read_u32(data)?;
        let mut values = HashMap::new();
        for _ in 0..count {
            let k = read_bytes(data)?.to_vec();
            let v = read_bytes(data)?.to_vec();
            values.insert(k, v);
        }

        Ok(MlsProvider {
            crypto: RustCrypto::default(),
            storage: MemoryStorage {
                values: values.into(),
            },
        })
    }
}

pub(crate) fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

pub(crate) fn read_u32(data: &mut &[u8]) -> Result<u32> {
    if data.len() < 4 {
        return Err(ErrorKind::BadFormat);
    }
    let (n, rest) = data.split_at(4);
    *data = rest;
    Ok(u32::from_be_bytes([n[0], n[1], n[2], n[3]]))
}

pub(crate) fn read_bytes<'a>(data: &mut &'a [u8]) -> Result<&'a [u8]> {
    let len = read_u32(data)? as usize;
    if data.len() < len {
        return Err(ErrorKind::BadFormat);
    }
    let (bytes, rest) = data.split_at(len);
    *data = rest;
    Ok(bytes)
}
