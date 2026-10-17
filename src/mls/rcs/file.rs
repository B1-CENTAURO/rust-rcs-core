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

//! Encryption of files, thumbnails, group icons and subjects (RCC.16 Annex C.2, C.3)

use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;

use super::super::{ErrorKind, Result};
use super::proto::{Algorithm, FileEncryptionInfo};

type Aes256Ctr = ctr::Ctr32BE<Aes256>;

/// 256 bit binary representation of pi, the HKDF salt
const SALT: [u8; 32] = [
    0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
    0x4a, 0x40, 0x93, 0x82, 0x22, 0x99, 0xf3, 0x1d, 0x00, 0x82, 0xef, 0xa9, 0x8e, 0xc4, 0xe6, 0xc8,
];

const KEY_LENGTH: usize = 32;
const IV_LENGTH: usize = 12;
const TAG_LENGTH: usize = 32;
/// Length of the trailing messageLength and paddingLength
const TRAILER_LENGTH: usize = 8;

const MAX_FILE_LENGTH: usize = (1 << 31) - 1;
const MAX_NAME_LENGTH: usize = (1 << 16) - 1;

/// Granularity PADME rounds `length` up to
///
/// PADME is defined in "Reducing Metadata Leakage from Encrypted Files and
/// Communication with PURBs" (Nikitin et al.), referenced by RCC.16 as [PADME].
pub fn padme_block(length: u64) -> u64 {
    if length < 2 {
        return 1;
    }
    let e = 63 - length.leading_zeros(); // floor(log2(length))
    let s = 32 - e.leading_zeros(); // floor(log2(e)) + 1
    1 << (e - s)
}

pub fn padme(length: u64) -> u64 {
    let block = padme_block(length);
    length.div_ceil(block) * block
}

pub struct EncryptedFile {
    pub ciphertext: Vec<u8>,
    /// To be sent in the FileInfo, together with `file_name`
    pub encryption_info: FileEncryptionInfo,
}

/// Encrypts `file` under a fresh key
///
/// `file_name` is the original file name, or GROUP_ICON_FILE_NAME /
/// GROUP_SUBJECT_FILE_NAME for group metadata, and has to be sent alongside as
/// FileMetadata.file_name since decryption depends on it.
pub fn encrypt_file(file: &[u8], file_name: &str) -> Result<EncryptedFile> {
    let mut key = [0u8; KEY_LENGTH];
    let mut iv = [0u8; IV_LENGTH];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut iv);

    encrypt(&key, &iv, file, file_name)
}

pub(super) fn encrypt(
    key: &[u8; KEY_LENGTH],
    iv: &[u8; IV_LENGTH],
    file: &[u8],
    file_name: &str,
) -> Result<EncryptedFile> {
    if file.len() >= MAX_FILE_LENGTH || file_name.len() >= MAX_NAME_LENGTH {
        return Err(ErrorKind::BadFormat);
    }

    let (k_enc, k_hmac) = derive_keys(key, file_name.as_bytes())?;

    let message_length = file.len() as u32;
    let padding_length = (padme(file.len() as u64) - file.len() as u64) as u32;

    let mut data = Vec::with_capacity(file.len() + padding_length as usize + TRAILER_LENGTH);
    data.extend_from_slice(file);
    data.resize(file.len() + padding_length as usize, 0);
    data.extend_from_slice(&message_length.to_be_bytes());
    data.extend_from_slice(&padding_length.to_be_bytes());

    Aes256Ctr::new(&k_enc.into(), &counter_block(iv).into()).apply_keystream(&mut data);

    let tag = tag_mac(&k_hmac, iv, &data)?
        .finalize()
        .into_bytes()
        .to_vec();

    Ok(EncryptedFile {
        ciphertext: data,
        encryption_info: FileEncryptionInfo {
            key_material: key.to_vec(),
            initialization_vector: iv.to_vec(),
            hmac_tag: tag,
            algorithm: Algorithm::Aes256CtrHmacSha256256tag as i32,
            file_length_hint: message_length,
        },
    })
}

/// Verifies and decrypts a file encrypted by `encrypt_file()`
///
/// Fails with Rejected when the tag does not match, and with BadFormat for any
/// other inconsistency.
pub fn decrypt_file(
    ciphertext: &[u8],
    file_name: &str,
    encryption_info: &FileEncryptionInfo,
) -> Result<Vec<u8>> {
    if encryption_info.algorithm != Algorithm::Aes256CtrHmacSha256256tag as i32
        || encryption_info.key_material.len() != KEY_LENGTH
        || encryption_info.initialization_vector.len() != IV_LENGTH
        || encryption_info.hmac_tag.len() != TAG_LENGTH
        || ciphertext.len() < TRAILER_LENGTH
    {
        return Err(ErrorKind::BadFormat);
    }

    let iv = &encryption_info.initialization_vector;
    let (k_dec, k_hmac) = derive_keys(&encryption_info.key_material, file_name.as_bytes())?;

    tag_mac(&k_hmac, iv, ciphertext)?
        .verify_slice(&encryption_info.hmac_tag)
        .map_err(|_| ErrorKind::Rejected)?;

    let mut plaintext = ciphertext.to_vec();
    let mut iv_bytes = [0u8; IV_LENGTH];
    iv_bytes.copy_from_slice(iv);
    Aes256Ctr::new(&k_dec.into(), &counter_block(&iv_bytes).into()).apply_keystream(&mut plaintext);

    let n = plaintext.len();
    let message_length = u32::from_be_bytes([
        plaintext[n - 8],
        plaintext[n - 7],
        plaintext[n - 6],
        plaintext[n - 5],
    ]) as u64;
    let padding_length = u32::from_be_bytes([
        plaintext[n - 4],
        plaintext[n - 3],
        plaintext[n - 2],
        plaintext[n - 1],
    ]) as u64;

    if message_length >= 1 << 31
        || message_length != encryption_info.file_length_hint as u64
        || n as u64 != TRAILER_LENGTH as u64 + message_length + padding_length
        || padding_length != padme(message_length) - message_length
    {
        return Err(ErrorKind::BadFormat);
    }

    let message_length = message_length as usize;
    if plaintext[message_length..n - TRAILER_LENGTH]
        .iter()
        .any(|b| *b != 0)
    {
        return Err(ErrorKind::BadFormat);
    }

    plaintext.truncate(message_length);
    Ok(plaintext)
}

fn derive_keys(key: &[u8], info: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    let mut okm = [0u8; 64];
    Hkdf::<Sha256>::new(Some(&SALT), key)
        .expand(info, &mut okm)
        .map_err(|_| ErrorKind::Crypto)?;

    let mut k_enc = [0u8; 32];
    let mut k_hmac = [0u8; 32];
    k_enc.copy_from_slice(&okm[..32]);
    k_hmac.copy_from_slice(&okm[32..]);
    Ok((k_enc, k_hmac))
}

/// IV || ZV, ZV being four zero bytes
fn counter_block(iv: &[u8; IV_LENGTH]) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[..IV_LENGTH].copy_from_slice(iv);
    block
}

/// HMAC over IV || Ciphertext
fn tag_mac(k_hmac: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Hmac<Sha256>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(k_hmac).map_err(|_| ErrorKind::Crypto)?;
    mac.update(iv);
    mac.update(ciphertext);
    Ok(mac)
}
