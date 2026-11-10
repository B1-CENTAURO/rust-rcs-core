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

//! The vectors of `testdata/sframe-test-vectors.json` are those of RFC 9605
//! Appendix C, as the sframe crate (MIT or Apache-2.0) ships them.

use serde_json::Value;

use super::super::super::{
    Ciphersuite, Credential, CredentialValidator, ErrorKind, MlsClient, MlsConfig, MlsConversation,
};
use super::{
    open, seal, CipherSuite, Header, KidLayout, KidParts, SframeKey, SframeSession, DEFAULT_LAYOUT,
};

const VECTORS: &str = include_str!("testdata/sframe-test-vectors.json");

fn vectors(kind: &str) -> Vec<Value> {
    let all: Value = serde_json::from_str(VECTORS).unwrap();
    all[kind].as_array().unwrap().clone()
}

fn hex(value: &Value) -> Vec<u8> {
    let text = value.as_str().unwrap();
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

fn suite(vector: &Value) -> CipherSuite {
    CipherSuite::from_value(vector["cipher_suite"].as_u64().unwrap() as u16).unwrap()
}

#[test]
fn headers_are_encoded_and_decoded_as_rfc_9605_has_them() {
    let headers = vectors("header");
    assert_eq!(headers.len(), 289);
    for vector in headers {
        let header = Header {
            kid: vector["kid"].as_u64().unwrap(),
            ctr: vector["ctr"].as_u64().unwrap(),
        };
        let encoded = hex(&vector["encoded"]);
        assert_eq!(header.encode(), encoded, "{:?}", header);
        let mut frame = encoded.clone();
        frame.extend_from_slice(b"rest");
        assert_eq!(Header::decode(&frame), Ok((header, encoded.len())));
    }

    // none, or cut short
    assert_eq!(Header::decode(&[]), Err(ErrorKind::BadFormat));
    assert_eq!(Header::decode(&[0x9f, 0x01]), Err(ErrorKind::BadFormat));
    assert_eq!(Header::decode(&[0x0b, 0x01]), Err(ErrorKind::BadFormat));
    // a value under 8 sent on a byte of its own, as another sender may
    assert_eq!(
        Header::decode(&[0x80, 0x05]),
        Ok((Header { kid: 5, ctr: 0 }, 2))
    );
}

#[test]
fn the_aes_ctr_suites_seal_and_open_as_rfc_9605_has_them() {
    let all = vectors("aes_ctr_hmac");
    assert_eq!(all.len(), 3);
    for vector in all {
        let suite = suite(&vector);
        let key = SframeKey {
            suite,
            key: hex(&vector["key"]),
            salt: vec![0; 12],
        };
        assert_eq!(key.key[..16], hex(&vector["enc_key"])[..]);
        assert_eq!(key.key[16..], hex(&vector["auth_key"])[..]);
        let nonce: [u8; 12] = hex(&vector["nonce"]).try_into().unwrap();
        let (aad, pt, ct) = (hex(&vector["aad"]), hex(&vector["pt"]), hex(&vector["ct"]));

        assert_eq!(seal(&key, &nonce, &aad, &pt), Ok(ct.clone()), "{:?}", suite);
        assert_eq!(open(&key, &nonce, &aad, &ct), Ok(pt), "{:?}", suite);

        // nor with another tag, ciphertext, AAD or nonce, nor too short
        let mut tag = ct.clone();
        *tag.last_mut().unwrap() ^= 1;
        let mut body = ct.clone();
        body[0] ^= 1;
        let mut other_nonce = nonce;
        other_nonce[0] ^= 1;
        assert_eq!(open(&key, &nonce, &aad, &tag), Err(ErrorKind::Rejected));
        assert_eq!(open(&key, &nonce, &aad, &body), Err(ErrorKind::Rejected));
        assert_eq!(open(&key, &nonce, b"other", &ct), Err(ErrorKind::Rejected));
        assert_eq!(
            open(&key, &other_nonce, &aad, &ct),
            Err(ErrorKind::Rejected)
        );
        assert_eq!(
            open(&key, &nonce, &aad, &ct[..suite.tag_len() - 1]),
            Err(ErrorKind::Rejected)
        );
    }
}

#[test]
fn frames_are_encrypted_and_decrypted_as_rfc_9605_has_them() {
    let all = vectors("sframe");
    assert_eq!(all.len(), 5);
    for vector in all {
        let suite = suite(&vector);
        let kid = vector["kid"].as_u64().unwrap();
        let ctr = vector["ctr"].as_u64().unwrap();
        let key = SframeKey::derive(suite, kid, &hex(&vector["base_key"])).unwrap();
        assert_eq!(key.key, hex(&vector["sframe_key"]), "{:?}", suite);
        assert_eq!(key.salt, hex(&vector["sframe_salt"]), "{:?}", suite);
        assert_eq!(
            key.nonce(ctr).to_vec(),
            hex(&vector["nonce"]),
            "{:?}",
            suite
        );

        let (metadata, pt, ct) = (
            hex(&vector["metadata"]),
            hex(&vector["pt"]),
            hex(&vector["ct"]),
        );
        assert_eq!(
            key.encrypt(kid, ctr, &metadata, &pt),
            Ok(ct.clone()),
            "{:?}",
            suite
        );
        assert_eq!(key.decrypt(&metadata, &ct), Ok((Header { kid, ctr }, pt)));

        // nor with other metadata, nor with the key of another Key ID
        assert_eq!(key.decrypt(b"other", &ct), Err(ErrorKind::Rejected));
        let other = SframeKey::derive(suite, kid + 1, &hex(&vector["base_key"])).unwrap();
        assert_eq!(other.decrypt(&metadata, &ct), Err(ErrorKind::Rejected));
    }
}

#[test]
fn the_cipher_suites_are_those_of_the_iana_registry() {
    for value in 1..=5 {
        assert_eq!(CipherSuite::from_value(value).unwrap().value(), value);
    }
    assert_eq!(CipherSuite::from_value(0), None);
    assert_eq!(CipherSuite::from_value(6), None);
    assert_eq!(CipherSuite::AesGcm128Sha256.key_len(), 16);
    assert_eq!(CipherSuite::AesGcm256Sha512.key_len(), 32);
    assert_eq!(CipherSuite::AesCtr128HmacSha256_80.key_len(), 48);
    assert_eq!(CipherSuite::AesCtr128HmacSha256_32.tag_len(), 4);
    assert_eq!(CipherSuite::AesGcm256Sha512.tag_len(), 16);
}

#[test]
fn a_key_id_carries_the_context_leaf_index_and_epoch_bits() {
    // RFC 9605 section 5.2: context, then S bits of index, then E of epoch
    let layout = KidLayout::new(4, 16).unwrap();
    assert_eq!(layout, DEFAULT_LAYOUT);
    assert_eq!(layout.epochs_told_apart(), 16);
    let kid = layout.kid(3, 0x1234, 0x25).unwrap();
    assert_eq!(kid, 3 << 20 | 0x1234 << 4 | 0x5);
    assert_eq!(
        layout.parts(kid),
        KidParts {
            context_id: 3,
            leaf_index: 0x1234,
            epoch_bits: 0x5,
        }
    );
    // the leaf index of the first member of the group in its first epoch
    // makes a Key ID that fits in the config byte
    assert_eq!(layout.kid(0, 0, 0), Ok(0));
    assert_eq!(Header { kid: 0, ctr: 0 }.encode(), [0x00]);

    // not with an index or a context too large, nor in a layout leaving no
    // bit of epoch or context
    assert_eq!(layout.kid(0, 0x1_0000, 0), Err(ErrorKind::InvalidState));
    assert_eq!(layout.kid(1 << 44, 0, 0), Err(ErrorKind::InvalidState));
    assert!(layout.kid((1 << 44) - 1, 0xffff, u64::MAX).is_ok());
    assert_eq!(KidLayout::new(0, 16), Err(ErrorKind::InvalidState));
    assert_eq!(KidLayout::new(32, 32), Err(ErrorKind::InvalidState));
    assert_eq!(KidLayout::new(4, 33), Err(ErrorKind::InvalidState));
    assert!(KidLayout::new(31, 32).is_ok());
}

struct AllowAll;

impl CredentialValidator for AllowAll {
    fn validate(&self, _credential: &Credential, _signature_key: &[u8]) -> bool {
        true
    }
}

fn client(identity: &str) -> MlsClient {
    MlsClient::new(
        identity.as_bytes(),
        Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
        MlsConfig::default(),
        Box::new(AllowAll),
    )
    .unwrap()
}

/// Alice's group, with Bob
fn alice_and_bob(alice: &MlsClient, bob: &MlsClient) -> (MlsConversation, MlsConversation) {
    let key_package = bob.generate_key_package(false).unwrap();
    let mut alices = alice.create_conversation(None, 0).unwrap();
    let output = alices.add_members(alice, &[&key_package]).unwrap();
    alices.merge_pending_commit(alice).unwrap();
    let bobs = bob
        .join_conversation(&output.welcome.unwrap(), &output.ratchet_tree.unwrap())
        .unwrap();
    (alices, bobs)
}

fn session(conversation: &MlsConversation, client: &MlsClient) -> SframeSession {
    SframeSession::of(
        conversation,
        client,
        CipherSuite::AesGcm128Sha256,
        DEFAULT_LAYOUT,
        0,
    )
    .unwrap()
}

#[test]
fn the_members_of_a_group_take_each_others_frames() {
    let (alice, bob) = (client("alice"), client("bob"));
    let (alices, bobs) = alice_and_bob(&alice, &bob);
    // the same base key in both, the key of each sender its own (RFC 9605
    // section 5.2)
    let suite = CipherSuite::AesGcm128Sha256;
    assert_eq!(
        alices.sframe_base_key(&alice, suite),
        bobs.sframe_base_key(&bob, suite)
    );
    assert_eq!(alices.own_leaf_index(), 0);
    assert_eq!(bobs.own_leaf_index(), 1);
    assert_eq!(alices.leaf_index_of(&bobs.members()[1]), Some(1));
    assert_eq!(alices.leaf_index_of(&alices.members()[0]), Some(0));
    assert_eq!(
        alices.leaf_index_of(&client("carol").credential().clone()),
        None
    );

    let mut alices_video = session(&alices, &alice);
    let mut bobs_video = session(&bobs, &bob);
    let first = alices_video.encrypt(b"rtp header", b"frame 1").unwrap();
    let second = alices_video.encrypt(b"rtp header", b"frame 2").unwrap();
    assert_eq!(
        Header::decode(&first).unwrap().0,
        Header {
            kid: DEFAULT_LAYOUT.kid(0, 0, 1).unwrap(),
            ctr: 0
        }
    );
    assert_eq!(Header::decode(&second).unwrap().0.ctr, 1);
    let decrypted = bobs_video.decrypt(b"rtp header", &first).unwrap();
    assert_eq!(
        (decrypted.leaf_index, decrypted.epoch, decrypted.frame),
        (0, 1, b"frame 1".to_vec())
    );
    let reply = bobs_video.encrypt(b"", b"frame of bob").unwrap();
    assert_eq!(
        alices_video.decrypt(b"", &reply).unwrap().frame,
        b"frame of bob"
    );

    // nor with other metadata, nor changed, nor of another group
    assert_eq!(
        bobs_video.decrypt(b"other", &second),
        Err(ErrorKind::Rejected)
    );
    let mut changed = second.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert_eq!(
        bobs_video.decrypt(b"rtp header", &changed),
        Err(ErrorKind::Rejected)
    );
    let (carol, dave) = (client("carol"), client("dave"));
    let (carols, _) = alice_and_bob(&carol, &dave);
    let mut carols_video = session(&carols, &carol);
    let elsewhere = carols_video.encrypt(b"", b"frame of carol").unwrap();
    assert_eq!(
        bobs_video.decrypt(b"", &elsewhere),
        Err(ErrorKind::Rejected)
    );
}

#[test]
fn a_new_epoch_is_sent_in_once_the_committer_switches_to_it() {
    let (alice, bob) = (client("alice"), client("bob"));
    let (mut alices, mut bobs) = alice_and_bob(&alice, &bob);
    let mut alices_video = session(&alices, &alice);
    let mut bobs_video = session(&bobs, &bob);

    // Bob commits, both apply it, both still sending in the epoch before
    // (RCC.16 section 9.8.2)
    let output = bobs.update_keys(&bob).unwrap();
    bobs.merge_pending_commit(&bob).unwrap();
    alices.process(&alice, &output.commit).unwrap();
    let committer = bobs.own_leaf_index();
    bobs_video.advance_with(&bobs, &bob, committer).unwrap();
    alices_video
        .advance_with(&alices, &alice, committer)
        .unwrap();
    assert_eq!(alices_video.pending_epoch(), Some(2));
    assert_eq!(alices_video.sending_epoch(), 1);
    assert_eq!(bobs_video.sending_epoch(), 1);
    let old = alices_video.encrypt(b"", b"in epoch 1").unwrap();
    assert_eq!(bobs_video.decrypt(b"", &old).unwrap().epoch, 1);
    let old_of_bob = bobs_video.encrypt(b"", b"bob in epoch 1").unwrap();
    assert_eq!(alices_video.decrypt(b"", &old_of_bob).unwrap().epoch, 1);
    assert_eq!(alices_video.sending_epoch(), 1);

    // Bob switches once all took his Commit, as their receipts tell, his
    // counter starting anew
    assert!(bobs_video.switch_to_new_epoch());
    assert!(!bobs_video.switch_to_new_epoch());
    assert_eq!(bobs_video.sending_epoch(), 2);
    let new = bobs_video.encrypt(b"", b"").unwrap();
    assert_eq!(
        Header::decode(&new).unwrap().0,
        Header {
            kid: DEFAULT_LAYOUT.kid(0, 1, 2).unwrap(),
            ctr: 0
        }
    );
    // Alice too once a frame of his in it comes, an empty one as when he
    // sends no media
    let decrypted = alices_video.decrypt(b"", &new).unwrap();
    assert_eq!((decrypted.epoch, decrypted.frame), (2, Vec::new()));
    assert_eq!(alices_video.sending_epoch(), 2);
    assert_eq!(alices_video.pending_epoch(), None);
    let newer = alices_video.encrypt(b"", b"in epoch 2").unwrap();
    assert_eq!(bobs_video.decrypt(b"", &newer).unwrap().epoch, 2);
    // the frames of the epoch before still taken
    assert_eq!(bobs_video.decrypt(b"", &old).unwrap().frame, b"in epoch 1");
}

#[test]
fn a_frame_of_another_than_the_committer_does_not_switch_to_the_new_epoch() {
    let base_key = |epoch: u8| vec![epoch; 16];
    let suite = CipherSuite::AesGcm128Sha256;
    let mut alices_video = SframeSession::new(suite, DEFAULT_LAYOUT, 0, 0, 1, base_key(1)).unwrap();
    let mut bobs_video = SframeSession::new(suite, DEFAULT_LAYOUT, 0, 1, 1, base_key(1)).unwrap();
    // carol's Commit, at leaf 2
    alices_video.epoch_advanced(2, base_key(2), 2);
    bobs_video.epoch_advanced(2, base_key(2), 2);
    // Bob sending in it, as when he switched before Alice: not hers yet
    bobs_video.switch_to_new_epoch();
    let of_bob = bobs_video.encrypt(b"", b"bob in epoch 2").unwrap();
    assert_eq!(alices_video.decrypt(b"", &of_bob).unwrap().epoch, 2);
    assert_eq!(alices_video.sending_epoch(), 1);
    // nor a frame of its own leaf, sent under another context: the
    // committer switches as told
    let mut carols = SframeSession::new(suite, DEFAULT_LAYOUT, 0, 2, 1, base_key(1)).unwrap();
    carols.epoch_advanced(2, base_key(2), 2);
    let mut own = SframeSession::new(suite, DEFAULT_LAYOUT, 1, 2, 1, base_key(1)).unwrap();
    own.epoch_advanced(2, base_key(2), 2);
    own.switch_to_new_epoch();
    let of_own = own.encrypt(b"", b"").unwrap();
    assert_eq!(carols.decrypt(b"", &of_own).unwrap().leaf_index, 2);
    assert_eq!(carols.sending_epoch(), 1);
    // an epoch not after the latest passed over
    alices_video.epoch_advanced(2, base_key(9), 0);
    alices_video.epoch_advanced(1, base_key(9), 0);
    assert_eq!(alices_video.pending_epoch(), Some(2));
    assert_eq!(
        alices_video.decrypt(b"", &of_bob).unwrap().frame,
        b"bob in epoch 2"
    );
}

#[test]
fn the_keys_of_old_epochs_are_let_go_of() {
    let suite = CipherSuite::AesGcm128Sha256;
    let base_key = |epoch: u64| vec![epoch as u8; 16];
    let mut sender = SframeSession::new(suite, DEFAULT_LAYOUT, 0, 1, 1, base_key(1)).unwrap();
    let mut receiver = SframeSession::new(suite, DEFAULT_LAYOUT, 0, 0, 1, base_key(1)).unwrap();
    let mut frames = vec![sender.encrypt(b"", b"in epoch 1").unwrap()];
    for epoch in 2..=6 {
        sender.epoch_advanced(epoch, base_key(epoch), 1);
        sender.switch_to_new_epoch();
        receiver.epoch_advanced(epoch, base_key(epoch), 1);
        let frame = sender.encrypt(b"", b"").unwrap();
        // the receiver switching with each frame of the committer
        assert_eq!(receiver.decrypt(b"", &frame).unwrap().epoch, epoch);
        assert_eq!(receiver.sending_epoch(), epoch);
        frames.push(frame);
    }
    // so keeping the 3 epochs before the one it sends in, 6
    assert_eq!(
        receiver.decrypt(b"", &frames[0]),
        Err(ErrorKind::UnknownMember)
    );
    assert_eq!(
        receiver.decrypt(b"", &frames[1]),
        Err(ErrorKind::UnknownMember)
    );
    for frame in &frames[2..] {
        assert!(receiver.decrypt(b"", frame).is_ok());
    }

    // one not switching keeps the epoch it sends in, however many come
    // after, and those the Key IDs tell apart from the latest
    let mut late = SframeSession::new(suite, DEFAULT_LAYOUT, 0, 0, 1, base_key(1)).unwrap();
    for epoch in 2..=40 {
        late.epoch_advanced(epoch, base_key(epoch), 1);
    }
    assert_eq!(late.sending_epoch(), 1);
    assert!(late.encrypt(b"", b"still in epoch 1").is_ok());
    // epoch 20 taken for 36, which its Key ID tells as well
    let mut twenty = SframeSession::new(suite, DEFAULT_LAYOUT, 0, 1, 20, base_key(20)).unwrap();
    let of_twenty = twenty.encrypt(b"", b"in epoch 20").unwrap();
    assert_eq!(late.decrypt(b"", &of_twenty), Err(ErrorKind::Rejected));
    let mut forty = SframeSession::new(suite, DEFAULT_LAYOUT, 0, 1, 40, base_key(40)).unwrap();
    let of_forty = forty.encrypt(b"", b"in epoch 40").unwrap();
    assert_eq!(late.decrypt(b"", &of_forty).unwrap().epoch, 40);
}

#[test]
fn a_session_is_not_made_for_a_leaf_its_layout_cannot_carry() {
    let suite = CipherSuite::AesGcm128Sha256;
    let layout = KidLayout::new(4, 2).unwrap();
    assert!(SframeSession::new(suite, layout, 0, 3, 1, vec![0; 16]).is_ok());
    assert_eq!(
        SframeSession::new(suite, layout, 0, 4, 1, vec![0; 16]).err(),
        Some(ErrorKind::InvalidState)
    );
}
