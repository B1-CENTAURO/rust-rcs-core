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

//! SFrame (RFC 9605) media encryption, keyed from the MLS group of a Group
//! RCS Video Chat (RCC.16 section 9.8.2)
//!
//! The frames of the media are encrypted each on its own, the SFrame header
//! telling the key and the counter they are encrypted with (RFC 9605 section
//! 4). The keys come from the MLS group (section 5.2): each epoch, the group
//! exports a base key, from which every sender derives its own key by its Key
//! ID, which carries its leaf index in the group and the low bits of the
//! epoch. An SframeSession keeps those keys, and switches to those of a new
//! epoch as RCC.16 section 9.8.2 has it, the committer first, and takes each
//! frame of a sender once (RFC 9605 section 9.3).
//!
//! The media themselves, their packetization and their transport, are the
//! app's: frames are handed in and out as bytes.

use std::collections::{HashMap, VecDeque};

use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM};
use sha2::{Sha256, Sha512};

use super::super::client::MlsClient;
use super::super::conversation::MlsConversation;
use super::super::{ErrorKind, Result};

/// The label the base key of an epoch is exported with from the MLS group
/// (RFC 9605 section 5.2)
pub const BASE_KEY_LABEL: &str = "SFrame 1.0 Base Key";

const KEY_LABEL: &[u8] = b"SFrame 1.0 Secret key ";
const SALT_LABEL: &[u8] = b"SFrame 1.0 Secret salt ";

/// An SFrame cipher suite (RFC 9605 section 4.5)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherSuite {
    AesCtr128HmacSha256_80,
    AesCtr128HmacSha256_64,
    AesCtr128HmacSha256_32,
    /// The one that goes with the MLS cipher suite of RCC.16,
    /// MLS_128_DHKEMP256_AES128GCM_SHA256_P256
    AesGcm128Sha256,
    AesGcm256Sha512,
}

impl CipherSuite {
    /// Its value in the IANA registry
    pub fn value(self) -> u16 {
        match self {
            CipherSuite::AesCtr128HmacSha256_80 => 0x0001,
            CipherSuite::AesCtr128HmacSha256_64 => 0x0002,
            CipherSuite::AesCtr128HmacSha256_32 => 0x0003,
            CipherSuite::AesGcm128Sha256 => 0x0004,
            CipherSuite::AesGcm256Sha512 => 0x0005,
        }
    }

    /// The cipher suite of value `value`, if one is
    pub fn from_value(value: u16) -> Option<CipherSuite> {
        [
            CipherSuite::AesCtr128HmacSha256_80,
            CipherSuite::AesCtr128HmacSha256_64,
            CipherSuite::AesCtr128HmacSha256_32,
            CipherSuite::AesGcm128Sha256,
            CipherSuite::AesGcm256Sha512,
        ]
        .into_iter()
        .find(|suite| suite.value() == value)
    }

    fn is_ctr(self) -> bool {
        matches!(
            self,
            CipherSuite::AesCtr128HmacSha256_80
                | CipherSuite::AesCtr128HmacSha256_64
                | CipherSuite::AesCtr128HmacSha256_32
        )
    }

    /// Nk, the length of a key: for AES-CTR, the AES key then the HMAC key
    pub fn key_len(self) -> usize {
        match self {
            CipherSuite::AesGcm128Sha256 => 16,
            CipherSuite::AesGcm256Sha512 => 32,
            _ => 16 + 32,
        }
    }

    /// Nn, the length of a nonce
    pub fn nonce_len(self) -> usize {
        12
    }

    /// Nt, the length of an authentication tag
    pub fn tag_len(self) -> usize {
        match self {
            CipherSuite::AesCtr128HmacSha256_80 => 10,
            CipherSuite::AesCtr128HmacSha256_64 => 8,
            CipherSuite::AesCtr128HmacSha256_32 => 4,
            CipherSuite::AesGcm128Sha256 | CipherSuite::AesGcm256Sha512 => 16,
        }
    }
}

/// The SFrame header of a frame: the Key ID and the counter it is encrypted
/// with (RFC 9605 section 4.3)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub kid: u64,
    pub ctr: u64,
}

impl Header {
    /// The header as it starts a frame: a config byte, then the Key ID and
    /// the counter that do not fit in it, each on the fewest bytes it takes
    pub fn encode(&self) -> Vec<u8> {
        let (kid_bits, kid) = field(self.kid);
        let (ctr_bits, ctr) = field(self.ctr);
        let mut header = vec![kid_bits << 4 | ctr_bits];
        header.extend_from_slice(&kid);
        header.extend_from_slice(&ctr);
        header
    }

    /// The header starting `frame`, and its length
    pub fn decode(frame: &[u8]) -> Result<(Header, usize)> {
        let config = *frame.first().ok_or(ErrorKind::BadFormat)?;
        let mut at = 1;
        let mut read = |bits: u8| -> Result<u64> {
            if bits & 0x08 == 0 {
                return Ok(u64::from(bits & 0x07));
            }
            let len = usize::from(bits & 0x07) + 1;
            let bytes = frame.get(at..at + len).ok_or(ErrorKind::BadFormat)?;
            at += len;
            Ok(bytes
                .iter()
                .fold(0u64, |value, byte| value << 8 | u64::from(*byte)))
        };
        let kid = read(config >> 4)?;
        let ctr = read(config & 0x0f)?;
        Ok((Header { kid, ctr }, at))
    }
}

/// The 4 bits of the config byte telling `value`, and the bytes following it:
/// none if it fits in 3 bits, else its big-endian bytes, without leading zeros
fn field(value: u64) -> (u8, Vec<u8>) {
    if value < 8 {
        return (value as u8, Vec::new());
    }
    let bytes = value.to_be_bytes();
    let skip = bytes.iter().take_while(|byte| **byte == 0).count();
    let bytes = bytes[skip..].to_vec();
    (0x08 | (bytes.len() - 1) as u8, bytes)
}

/// The key and salt a sender encrypts with under one Key ID (RFC 9605
/// section 4.4.2)
#[derive(Clone, PartialEq, Eq)]
pub struct SframeKey {
    suite: CipherSuite,
    /// For AES-CTR, the AES key then the HMAC key
    key: Vec<u8>,
    salt: Vec<u8>,
}

impl std::fmt::Debug for SframeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SframeKey")
            .field("suite", &self.suite)
            .finish_non_exhaustive()
    }
}

impl SframeKey {
    /// The key and salt of the Key ID `kid`, derived from `base_key`
    pub fn derive(suite: CipherSuite, kid: u64, base_key: &[u8]) -> Result<SframeKey> {
        let label =
            |prefix: &[u8]| [prefix, &kid.to_be_bytes(), &suite.value().to_be_bytes()].concat();
        let mut key = vec![0u8; suite.key_len()];
        let mut salt = vec![0u8; suite.nonce_len()];
        match suite {
            CipherSuite::AesGcm256Sha512 => {
                let hkdf = Hkdf::<Sha512>::new(None, base_key);
                hkdf.expand(&label(KEY_LABEL), &mut key)
                    .and_then(|()| hkdf.expand(&label(SALT_LABEL), &mut salt))
            }
            _ => {
                let hkdf = Hkdf::<Sha256>::new(None, base_key);
                hkdf.expand(&label(KEY_LABEL), &mut key)
                    .and_then(|()| hkdf.expand(&label(SALT_LABEL), &mut salt))
            }
        }
        .map_err(|_| ErrorKind::Crypto)?;
        Ok(SframeKey { suite, key, salt })
    }

    pub fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// The nonce of the counter `ctr`: the salt, the counter XORed into its
    /// last bytes
    fn nonce(&self, ctr: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&self.salt);
        for (byte, ctr_byte) in nonce[4..].iter_mut().zip(ctr.to_be_bytes()) {
            *byte ^= ctr_byte;
        }
        nonce
    }

    /// `frame` encrypted as the frame of the Key ID `kid` and the counter
    /// `ctr`, `metadata` authenticated with it: its header, then its
    /// ciphertext and tag (RFC 9605 section 4.4.3)
    ///
    /// A counter is never to be used twice with the same key.
    pub fn encrypt(&self, kid: u64, ctr: u64, metadata: &[u8], frame: &[u8]) -> Result<Vec<u8>> {
        let mut out = Header { kid, ctr }.encode();
        let aad = [&out[..], metadata].concat();
        out.extend(seal(self, &self.nonce(ctr), &aad, frame)?);
        Ok(out)
    }

    /// The frame that `encrypted`, the frame of the header `header` of
    /// length `header_len`, carries, `metadata` authenticated with it (RFC
    /// 9605 section 4.4.4)
    fn decrypt_after(
        &self,
        header: &Header,
        header_len: usize,
        metadata: &[u8],
        encrypted: &[u8],
    ) -> Result<Vec<u8>> {
        let aad = [&encrypted[..header_len], metadata].concat();
        open(
            self,
            &self.nonce(header.ctr),
            &aad,
            &encrypted[header_len..],
        )
    }

    /// The header and the frame that `encrypted` carries, encrypted with this
    /// key, `metadata` authenticated with it; Rejected if it does not open
    ///
    /// The frame is not checked against replays, as in an SframeSession.
    pub fn decrypt(&self, metadata: &[u8], encrypted: &[u8]) -> Result<(Header, Vec<u8>)> {
        let (header, header_len) = Header::decode(encrypted)?;
        let frame = self.decrypt_after(&header, header_len, metadata, encrypted)?;
        Ok((header, frame))
    }
}

/// `plaintext` encrypted with `key` and `nonce`, `aad` authenticated: the
/// ciphertext, then the tag
fn seal(key: &SframeKey, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if key.suite.is_ctr() {
        let (enc_key, auth_key) = key.key.split_at(16);
        let mut out = plaintext.to_vec();
        ctr_apply(enc_key, nonce, &mut out);
        let tag = ctr_tag(key.suite, auth_key, nonce, aad, &out)?;
        out.extend_from_slice(&tag[..key.suite.tag_len()]);
        return Ok(out);
    }
    let mut out = plaintext.to_vec();
    gcm_key(key)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            &mut out,
        )
        .map_err(|_| ErrorKind::Crypto)?;
    Ok(out)
}

/// The plaintext of `ciphertext`, its tag after it, encrypted with `key` and
/// `nonce`, `aad` authenticated; Rejected if it does not open
fn open(key: &SframeKey, nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let tag_len = key.suite.tag_len();
    if ciphertext.len() < tag_len {
        return Err(ErrorKind::Rejected);
    }
    if key.suite.is_ctr() {
        let (enc_key, auth_key) = key.key.split_at(16);
        let (ciphertext, tag) = ciphertext.split_at(ciphertext.len() - tag_len);
        ctr_mac(key.suite, auth_key, nonce, aad, ciphertext)?
            .verify_truncated_left(tag)
            .map_err(|_| ErrorKind::Rejected)?;
        let mut out = ciphertext.to_vec();
        ctr_apply(enc_key, nonce, &mut out);
        return Ok(out);
    }
    let mut in_out = ciphertext.to_vec();
    let len = gcm_key(key)?
        .open_in_place(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            &mut in_out,
        )
        .map_err(|_| ErrorKind::Rejected)?
        .len();
    in_out.truncate(len);
    Ok(in_out)
}

fn gcm_key(key: &SframeKey) -> Result<LessSafeKey> {
    let algorithm = match key.suite {
        CipherSuite::AesGcm256Sha512 => &AES_256_GCM,
        _ => &AES_128_GCM,
    };
    UnboundKey::new(algorithm, &key.key)
        .map(LessSafeKey::new)
        .map_err(|_| ErrorKind::Crypto)
}

/// `data` XORed with the AES-CTR key stream of `enc_key`, the counter block
/// starting as the nonce then four zero bytes (RFC 9605 section 4.5.1)
fn ctr_apply(enc_key: &[u8], nonce: &[u8; 12], data: &mut [u8]) {
    let mut iv = [0u8; 16];
    iv[..12].copy_from_slice(nonce);
    // the AES-128 key the suites split off is of the length AES-128 takes
    if let Ok(mut cipher) = ctr::Ctr32BE::<Aes128>::new_from_slices(enc_key, &iv) {
        cipher.apply_keystream(data);
    }
}

/// The HMAC of the AES-CTR suites over the lengths of `aad`, of `ciphertext`
/// and of the tag, then the nonce, `aad` and `ciphertext` (RFC 9605 section
/// 4.5.1)
fn ctr_mac(
    suite: CipherSuite,
    auth_key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Hmac<Sha256>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(auth_key).map_err(|_| ErrorKind::Crypto)?;
    mac.update(&(aad.len() as u64).to_be_bytes());
    mac.update(&(ciphertext.len() as u64).to_be_bytes());
    mac.update(&(suite.tag_len() as u64).to_be_bytes());
    mac.update(nonce);
    mac.update(aad);
    mac.update(ciphertext);
    Ok(mac)
}

fn ctr_tag(
    suite: CipherSuite,
    auth_key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    Ok(ctr_mac(suite, auth_key, nonce, aad, ciphertext)?
        .finalize()
        .into_bytes()
        .to_vec())
}

/// How the 64 bits of a Key ID are shared out in an MLS group (RFC 9605
/// section 5.2): its `E` least significant bits are those of the epoch, the
/// `S` above them the leaf index of the sender, and the rest a context the
/// sender chooses
///
/// Every member of a video chat has to share them out the same way, which
/// RCC.16 leaves to the clients; DEFAULT_LAYOUT is the one of this library.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KidLayout {
    epoch_bits: u8,
    index_bits: u8,
}

/// 4 bits of epoch, so that 16 epochs in a row are told apart, and 16 bits
/// of leaf index, for groups of up to 65536 leaves
pub const DEFAULT_LAYOUT: KidLayout = KidLayout {
    epoch_bits: 4,
    index_bits: 16,
};

/// The parts of a Key ID, as a KidLayout shares them out
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KidParts {
    pub context_id: u64,
    pub leaf_index: u32,
    /// The `E` least significant bits of the epoch
    pub epoch_bits: u64,
}

impl KidLayout {
    /// `epoch_bits` (E) of epoch, at least one, and `index_bits` (S) of leaf
    /// index, at most 32, leaving at least one bit of context
    pub fn new(epoch_bits: u8, index_bits: u8) -> Result<KidLayout> {
        if epoch_bits == 0 || index_bits > 32 || u32::from(epoch_bits) + u32::from(index_bits) > 63
        {
            return Err(ErrorKind::InvalidState);
        }
        Ok(KidLayout {
            epoch_bits,
            index_bits,
        })
    }

    pub fn epoch_bits(&self) -> u8 {
        self.epoch_bits
    }

    pub fn index_bits(&self) -> u8 {
        self.index_bits
    }

    /// How many epochs in a row the Key IDs tell apart
    pub fn epochs_told_apart(&self) -> u64 {
        1 << self.epoch_bits.min(63)
    }

    /// The Key ID of the sender at leaf `leaf_index`, in `epoch`, under
    /// `context_id`; InvalidState if the index or the context does not fit
    pub fn kid(&self, context_id: u64, leaf_index: u32, epoch: u64) -> Result<u64> {
        let shift = self.epoch_bits + self.index_bits;
        if u64::from(leaf_index) >> self.index_bits != 0 || context_id >> (64 - shift) != 0 {
            return Err(ErrorKind::InvalidState);
        }
        let epoch_mask = (1u64 << self.epoch_bits) - 1;
        Ok(context_id << shift | u64::from(leaf_index) << self.epoch_bits | epoch & epoch_mask)
    }

    /// The parts of the Key ID `kid`
    pub fn parts(&self, kid: u64) -> KidParts {
        let index_mask = (1u64 << self.index_bits) - 1;
        KidParts {
            context_id: kid >> (self.epoch_bits + self.index_bits),
            leaf_index: ((kid >> self.epoch_bits) & index_mask) as u32,
            epoch_bits: kid & ((1u64 << self.epoch_bits) - 1),
        }
    }
}

impl MlsConversation {
    /// The SFrame base key of the current epoch of the group, for `suite`
    /// (RFC 9605 section 5.2)
    pub fn sframe_base_key(&self, client: &MlsClient, suite: CipherSuite) -> Result<Vec<u8>> {
        self.export_secret(client, BASE_KEY_LABEL, b"", suite.key_len())
    }
}

/// How many epochs before the one sent in a session keeps the keys of, for
/// the frames still on their way
const EPOCHS_KEPT: usize = 3;

/// A frame decrypted in an SframeSession
#[derive(Debug, PartialEq, Eq)]
pub struct DecryptedFrame {
    /// The leaf index of its sender in the MLS group
    pub leaf_index: u32,
    /// The epoch it was encrypted in
    pub epoch: u64,
    pub frame: Vec<u8>,
}

/// How many counters before the latest of a Key ID an SframeSession still
/// takes frames of, each once (RFC 9605 section 9.3)
pub const REPLAY_WINDOW: u64 = 128;

/// The counters of the frames taken under a Key ID: the latest, and which of
/// the REPLAY_WINDOW before it
#[derive(Default)]
struct ReplayWindow {
    latest: Option<u64>,
    /// Bit `i` set if the counter `latest - i` was taken
    taken: u128,
}

impl ReplayWindow {
    /// Whether a frame of the counter `ctr` may be taken: one after the
    /// latest, or one of the window not taken yet
    fn admits(&self, ctr: u64) -> bool {
        let Some(latest) = self.latest else {
            return true;
        };
        if ctr > latest {
            return true;
        }
        let behind = latest - ctr;
        behind < REPLAY_WINDOW && self.taken & 1 << behind == 0
    }

    /// Takes the counter `ctr`, of a frame that opened
    fn take(&mut self, ctr: u64) {
        match self.latest {
            Some(latest) if ctr <= latest => {
                let behind = latest - ctr;
                if behind < REPLAY_WINDOW {
                    self.taken |= 1 << behind;
                }
            }
            Some(latest) => {
                let ahead = ctr - latest;
                let kept = if ahead < REPLAY_WINDOW {
                    self.taken << ahead
                } else {
                    0
                };
                self.taken = kept | 1;
                self.latest = Some(ctr);
            }
            None => {
                self.taken = 1;
                self.latest = Some(ctr);
            }
        }
    }
}

/// The keys of an epoch
struct EpochKeys {
    epoch: u64,
    base_key: Vec<u8>,
    /// Those derived, by Key ID
    derived: HashMap<u64, SframeKey>,
    /// The counters taken, by Key ID
    replays: HashMap<u64, ReplayWindow>,
}

impl EpochKeys {
    fn new(epoch: u64, base_key: Vec<u8>) -> EpochKeys {
        EpochKeys {
            epoch,
            base_key,
            derived: HashMap::new(),
            replays: HashMap::new(),
        }
    }
}

impl EpochKeys {
    fn key(&mut self, suite: CipherSuite, kid: u64) -> Result<SframeKey> {
        if let Some(key) = self.derived.get(&kid) {
            return Ok(key.clone());
        }
        let key = SframeKey::derive(suite, kid, &self.base_key)?;
        self.derived.insert(kid, key.clone());
        Ok(key)
    }
}

/// The SFrame keys of one sender in a Group RCS Video Chat, from the epochs
/// of its MLS group (RCC.16 section 9.8.2, RFC 9605 section 5.2)
///
/// Frames are encrypted in the epoch the session sends in, and decrypted in
/// whichever of the epochs kept they were encrypted in. Once the group moves
/// to a new epoch, the session keeps sending in the one before: the client
/// that committed switches once all the clients of the chat took its Commit,
/// as their delivery receipts tell (switch_to_new_epoch()), and the others
/// once a frame of the committer in the new epoch comes. A committer sending
/// no media sends an empty frame then, for the others to switch.
///
/// The frames of each Key ID are taken once each: one of a counter taken
/// already, or more than REPLAY_WINDOW behind the latest taken, is Replayed
/// (RFC 9605 section 9.3). A session made again for a leaf, in an epoch it
/// sent in already, is to send under another `context_id`: its counter
/// starts again at 0, a counter is never to be used twice with the same key,
/// and the others would take its frames as replayed.
pub struct SframeSession {
    suite: CipherSuite,
    layout: KidLayout,
    context_id: u64,
    leaf_index: u32,
    /// The epochs kept, the oldest first
    epochs: VecDeque<EpochKeys>,
    /// The epoch sent in
    sending: u64,
    /// The counter of the next frame sent
    next_ctr: u64,
    /// The epoch to switch to, and the leaf index of the client whose
    /// Commit moved the group to it
    pending: Option<(u64, u32)>,
}

impl SframeSession {
    /// The session of the client at leaf `leaf_index` of its group, sending
    /// under `context_id` with `layout`, from the `epoch` the group is in and
    /// its base key `base_key` (MlsConversation::sframe_base_key())
    pub fn new(
        suite: CipherSuite,
        layout: KidLayout,
        context_id: u64,
        leaf_index: u32,
        epoch: u64,
        base_key: Vec<u8>,
    ) -> Result<SframeSession> {
        layout.kid(context_id, leaf_index, epoch)?;
        Ok(SframeSession {
            suite,
            layout,
            context_id,
            leaf_index,
            epochs: VecDeque::from([EpochKeys::new(epoch, base_key)]),
            sending: epoch,
            next_ctr: 0,
            pending: None,
        })
    }

    /// The session of the client `client` in the group `conversation`, from
    /// its current epoch
    pub fn of(
        conversation: &MlsConversation,
        client: &MlsClient,
        suite: CipherSuite,
        layout: KidLayout,
        context_id: u64,
    ) -> Result<SframeSession> {
        let base_key = conversation.sframe_base_key(client, suite)?;
        SframeSession::new(
            suite,
            layout,
            context_id,
            conversation.own_leaf_index(),
            conversation.epoch(),
            base_key,
        )
    }

    pub fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// The epoch the session sends in
    pub fn sending_epoch(&self) -> u64 {
        self.sending
    }

    /// The epoch the session is to switch to, if any
    pub fn pending_epoch(&self) -> Option<u64> {
        self.pending.map(|(epoch, _)| epoch)
    }

    /// Takes the group moving to `epoch`, of base key `base_key`, by a Commit
    /// of the client at leaf `committer`: frames are decrypted in it from now
    /// on, and sent in it once the session switches to it (RCC.16 section
    /// 9.8.2)
    ///
    /// An epoch not after the latest kept is passed over.
    pub fn epoch_advanced(&mut self, epoch: u64, base_key: Vec<u8>, committer: u32) {
        if self
            .epochs
            .back()
            .is_some_and(|latest| epoch <= latest.epoch)
        {
            return;
        }
        self.epochs.push_back(EpochKeys::new(epoch, base_key));
        self.pending = Some((epoch, committer));
        self.let_go_of_old_epochs();
    }

    /// Takes the group moving to its current epoch, from `conversation`, as
    /// epoch_advanced() does
    pub fn advance_with(
        &mut self,
        conversation: &MlsConversation,
        client: &MlsClient,
        committer: u32,
    ) -> Result<()> {
        let base_key = conversation.sframe_base_key(client, self.suite)?;
        self.epoch_advanced(conversation.epoch(), base_key, committer);
        Ok(())
    }

    /// Sends in the epoch to switch to from now on, as the committer does
    /// once all the clients of the chat took its Commit (RCC.16 section
    /// 9.8.2); whether there was one
    pub fn switch_to_new_epoch(&mut self) -> bool {
        let Some((epoch, _)) = self.pending.take() else {
            return false;
        };
        self.sending = epoch;
        self.next_ctr = 0;
        self.let_go_of_old_epochs();
        true
    }

    /// Lets go of the epochs more than EPOCHS_KEPT before the one sent in,
    /// and of those the Key IDs would not tell apart from the latest; never
    /// of the one sent in
    fn let_go_of_old_epochs(&mut self) {
        let latest = self.epochs.back().map_or(0, |keys| keys.epoch);
        let told_apart = self.layout.epochs_told_apart();
        let sending = self.sending;
        let earliest = self
            .epochs
            .iter()
            .filter(|keys| keys.epoch < sending)
            .count()
            .saturating_sub(EPOCHS_KEPT);
        let mut before = 0;
        self.epochs.retain(|keys| {
            if keys.epoch == sending {
                return true;
            }
            let kept =
                (keys.epoch > sending || before >= earliest) && latest - keys.epoch < told_apart;
            if keys.epoch < sending {
                before += 1;
            }
            kept
        });
    }

    /// `frame` encrypted in the epoch sent in, `metadata` authenticated with
    /// it, as an SFrame frame (RFC 9605 section 4.4.3)
    pub fn encrypt(&mut self, metadata: &[u8], frame: &[u8]) -> Result<Vec<u8>> {
        let kid = self
            .layout
            .kid(self.context_id, self.leaf_index, self.sending)?;
        let ctr = self.next_ctr;
        self.next_ctr = ctr.checked_add(1).ok_or(ErrorKind::InvalidState)?;
        let suite = self.suite;
        let sending = self.sending;
        let keys = self
            .epochs
            .iter_mut()
            .find(|keys| keys.epoch == sending)
            .ok_or(ErrorKind::InvalidState)?;
        keys.key(suite, kid)?.encrypt(kid, ctr, metadata, frame)
    }

    /// The frame that `encrypted` carries, `metadata` authenticated with it,
    /// in the epoch of those kept its Key ID tells (RFC 9605 section 4.4.4);
    /// UnknownMember if no epoch kept is its, Replayed if its counter was
    /// taken already or is too old to tell (section 9.3), Rejected if it does
    /// not open
    ///
    /// A frame of the committer in the epoch to switch to has the session
    /// send in it from now on (RCC.16 section 9.8.2).
    pub fn decrypt(&mut self, metadata: &[u8], encrypted: &[u8]) -> Result<DecryptedFrame> {
        let (header, header_len) = Header::decode(encrypted)?;
        let parts = self.layout.parts(header.kid);
        let mask = self.layout.epochs_told_apart() - 1;
        let suite = self.suite;
        let keys = self
            .epochs
            .iter_mut()
            .rev()
            .find(|keys| (keys.epoch & mask) == parts.epoch_bits)
            .ok_or(ErrorKind::UnknownMember)?;
        let epoch = keys.epoch;
        if keys
            .replays
            .get(&header.kid)
            .is_some_and(|window| !window.admits(header.ctr))
        {
            return Err(ErrorKind::Replayed);
        }
        let frame = keys
            .key(suite, header.kid)?
            .decrypt_after(&header, header_len, metadata, encrypted)?;
        // only once it opened, so that a forged header takes no counter
        keys.replays.entry(header.kid).or_default().take(header.ctr);
        if self.pending == Some((epoch, parts.leaf_index)) && parts.leaf_index != self.leaf_index {
            self.switch_to_new_epoch();
        }
        Ok(DecryptedFrame {
            leaf_index: parts.leaf_index,
            epoch,
            frame,
        })
    }
}

#[cfg(test)]
#[path = "sframe_tests.rs"]
mod tests;
