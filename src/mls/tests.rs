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

use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::{KeyPackage, MlsMessageBodyIn, MlsMessageIn, ProtocolVersion};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::types::SignatureScheme;
use openmls_traits::OpenMlsProvider;

use super::*;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

struct AllowAll;

impl CredentialValidator for AllowAll {
    fn validate(&self, _credential: &Credential, _signature_key: &[u8]) -> bool {
        true
    }
}

struct AllowList(Vec<&'static [u8]>);

impl CredentialValidator for AllowList {
    fn validate(&self, credential: &Credential, _signature_key: &[u8]) -> bool {
        self.0.contains(&credential.serialized_content())
    }
}

fn client(identity: &str) -> MlsClient {
    MlsClient::new(
        identity.as_bytes(),
        CIPHERSUITE,
        MlsConfig::default(),
        Box::new(AllowAll),
    )
    .unwrap()
}

fn identity(credential: &Credential) -> &[u8] {
    credential.serialized_content()
}

/// Creates a group owned by `creator` and adds `others` with a single Commit
fn establish(
    creator: &MlsClient,
    others: &[&MlsClient],
) -> (MlsConversation, Vec<MlsConversation>) {
    let key_packages: Vec<Vec<u8>> = others
        .iter()
        .map(|c| c.generate_key_package(false).unwrap())
        .collect();
    let key_packages: Vec<&[u8]> = key_packages.iter().map(|k| k.as_slice()).collect();

    let mut conversation = creator.create_conversation(None, 0).unwrap();
    let output = conversation.add_members(creator, &key_packages).unwrap();
    conversation.merge_pending_commit(creator).unwrap();

    let welcome = output.welcome.unwrap();
    let ratchet_tree = output.ratchet_tree.unwrap();
    let joined = others
        .iter()
        .map(|c| c.join_conversation(&welcome, &ratchet_tree).unwrap())
        .collect();

    (conversation, joined)
}

fn decrypt(
    conversation: &mut MlsConversation,
    client: &MlsClient,
    message: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    match conversation.process(client, message).unwrap() {
        IncomingMessage::Application { sender, data, .. } => (identity(&sender).to_vec(), data),
        _ => panic!("expected an application message"),
    }
}

#[test]
fn one_to_one_round_trip() {
    let alice = client("tel:+491701234567");
    let bob = client("tel:+491707654321");

    let (mut alice_conversation, mut joined) = establish(&alice, &[&bob]);
    let mut bob_conversation = joined.pop().unwrap();

    assert_eq!(alice_conversation.group_id(), bob_conversation.group_id());
    assert_eq!(alice_conversation.epoch(), bob_conversation.epoch());
    assert_eq!(bob_conversation.members().len(), 2);

    let message = alice_conversation.encrypt(&alice, b"hello bob").unwrap();
    let (sender, data) = decrypt(&mut bob_conversation, &bob, &message);
    assert_eq!(sender, b"tel:+491701234567");
    assert_eq!(data, b"hello bob");

    let reply = bob_conversation.encrypt(&bob, b"hello alice").unwrap();
    let (sender, data) = decrypt(&mut alice_conversation, &alice, &reply);
    assert_eq!(sender, b"tel:+491707654321");
    assert_eq!(data, b"hello alice");
}

#[test]
fn group_membership_changes() {
    let alice = client("alice");
    let bob = client("bob");
    let charlie = client("charlie");

    let (mut alice_conversation, mut joined) = establish(&alice, &[&bob, &charlie]);
    let mut charlie_conversation = joined.pop().unwrap();
    let mut bob_conversation = joined.pop().unwrap();
    assert_eq!(alice_conversation.members().len(), 3);

    // bob removes charlie
    let output = bob_conversation
        .remove_members(&bob, &[charlie.credential().clone()])
        .unwrap();
    assert!(output.welcome.is_none());
    bob_conversation.merge_pending_commit(&bob).unwrap();

    match alice_conversation.process(&alice, &output.commit).unwrap() {
        IncomingMessage::Commit {
            sender,
            added,
            removed,
            self_removed,
        } => {
            assert_eq!(identity(&sender), b"bob");
            assert!(added.is_empty());
            assert_eq!(removed.len(), 1);
            assert_eq!(identity(&removed[0]), b"charlie");
            assert!(!self_removed);
        }
        _ => panic!("expected a commit"),
    }

    match charlie_conversation
        .process(&charlie, &output.commit)
        .unwrap()
    {
        IncomingMessage::Commit { self_removed, .. } => assert!(self_removed),
        _ => panic!("expected a commit"),
    }
    assert!(!charlie_conversation.is_active());

    assert_eq!(alice_conversation.epoch(), bob_conversation.epoch());
    assert_eq!(alice_conversation.members().len(), 2);

    // charlie can no longer read the group
    let message = alice_conversation.encrypt(&alice, b"just us").unwrap();
    assert!(charlie_conversation.process(&charlie, &message).is_err());
    let (_, data) = decrypt(&mut bob_conversation, &bob, &message);
    assert_eq!(data, b"just us");

    // alice adds charlie back through a fresh KeyPackage
    let key_package = charlie.generate_key_package(false).unwrap();
    let output = alice_conversation
        .add_members(&alice, &[&key_package])
        .unwrap();
    alice_conversation.merge_pending_commit(&alice).unwrap();

    match bob_conversation.process(&bob, &output.commit).unwrap() {
        IncomingMessage::Commit { added, .. } => {
            assert_eq!(added.len(), 1);
            assert_eq!(identity(&added[0]), b"charlie");
        }
        _ => panic!("expected a commit"),
    }

    let mut charlie_conversation = charlie
        .join_conversation(&output.welcome.unwrap(), &output.ratchet_tree.unwrap())
        .unwrap();
    let message = bob_conversation.encrypt(&bob, b"welcome back").unwrap();
    let (_, data) = decrypt(&mut charlie_conversation, &charlie, &message);
    assert_eq!(data, b"welcome back");
}

#[test]
fn update_keys_and_late_delivery() {
    let alice = client("alice");
    let bob = client("bob");

    let (mut alice_conversation, mut joined) = establish(&alice, &[&bob]);
    let mut bob_conversation = joined.pop().unwrap();

    // sent in the current epoch, but delivered only after bob's Commit
    let early = alice_conversation.encrypt(&alice, b"sent before").unwrap();

    let epoch = bob_conversation.epoch();
    let output = bob_conversation.update_keys(&bob).unwrap();
    assert!(output.welcome.is_none());
    bob_conversation.merge_pending_commit(&bob).unwrap();
    assert_eq!(bob_conversation.epoch(), epoch + 1);

    match alice_conversation.process(&alice, &output.commit).unwrap() {
        IncomingMessage::Commit { sender, .. } => assert_eq!(identity(&sender), b"bob"),
        _ => panic!("expected a commit"),
    }
    assert_eq!(alice_conversation.epoch(), epoch + 1);

    let (_, data) = decrypt(&mut bob_conversation, &bob, &early);
    assert_eq!(data, b"sent before");

    let late = alice_conversation.encrypt(&alice, b"sent after").unwrap();
    let (_, data) = decrypt(&mut bob_conversation, &bob, &late);
    assert_eq!(data, b"sent after");
}

#[test]
fn leave_through_proposal() {
    let alice = client("alice");
    let bob = client("bob");

    let (mut alice_conversation, mut joined) = establish(&alice, &[&bob]);
    let mut bob_conversation = joined.pop().unwrap();

    let proposal = bob_conversation.leave(&bob).unwrap();
    match alice_conversation.process(&alice, &proposal).unwrap() {
        IncomingMessage::Proposal { sender } => assert_eq!(identity(&sender), b"bob"),
        _ => panic!("expected a proposal"),
    }

    let output = alice_conversation.commit_pending_proposals(&alice).unwrap();
    alice_conversation.merge_pending_commit(&alice).unwrap();
    assert_eq!(alice_conversation.members().len(), 1);

    match bob_conversation.process(&bob, &output.commit).unwrap() {
        IncomingMessage::Commit { self_removed, .. } => assert!(self_removed),
        _ => panic!("expected a commit"),
    }
    assert!(!bob_conversation.is_active());
}

#[test]
fn pending_commit_lifecycle() {
    let alice = client("alice");
    let bob = client("bob");
    let charlie = client("charlie");

    let (mut conversation, mut joined) = establish(&alice, &[&bob]);
    let mut bob_conversation = joined.pop().unwrap();
    let epoch = conversation.epoch();

    let key_package = charlie.generate_key_package(false).unwrap();
    conversation.add_members(&alice, &[&key_package]).unwrap();
    assert!(conversation.has_pending_commit());

    // still sending in the current epoch until the Commit is merged
    let message = conversation.encrypt(&alice, b"meanwhile").unwrap();
    let (_, data) = decrypt(&mut bob_conversation, &bob, &message);
    assert_eq!(data, b"meanwhile");

    // e.g. another member's Commit for this epoch won the race
    conversation.discard_pending_commit(&alice).unwrap();
    assert!(!conversation.has_pending_commit());
    assert_eq!(conversation.epoch(), epoch);
    assert_eq!(conversation.members().len(), 2);

    let mut conversation = alice.create_conversation(Some(b"chat-1"), 0).unwrap();
    assert_eq!(conversation.group_id(), b"chat-1");
    assert!(conversation.encrypt(&alice, b"alone").is_ok());

    // group ids are unique per client
    assert_eq!(
        alice.create_conversation(Some(b"chat-1"), 0).err(),
        Some(ErrorKind::InvalidState)
    );
}

#[test]
fn snapshot_and_restore() {
    let alice = client("alice");
    let bob = client("bob");

    let (mut alice_conversation, mut joined) = establish(&alice, &[&bob]);
    let group_id = joined.pop().unwrap().group_id().to_vec();

    // a KeyPackage generated before the snapshot must still be usable after it
    let key_package = bob.generate_key_package(false).unwrap();
    let snapshot = bob.snapshot().unwrap();
    assert_eq!(snapshot, bob.snapshot().unwrap());
    drop(bob);

    let bob = MlsClient::restore(&snapshot, MlsConfig::default(), Box::new(AllowAll)).unwrap();
    assert_eq!(identity(bob.credential()), b"bob");
    assert_eq!(bob.ciphersuite(), CIPHERSUITE);

    let mut bob_conversation = bob.load_conversation(&group_id).unwrap();
    let message = alice_conversation.encrypt(&alice, b"still there?").unwrap();
    let (_, data) = decrypt(&mut bob_conversation, &bob, &message);
    assert_eq!(data, b"still there?");

    let reply = bob_conversation.encrypt(&bob, b"yes").unwrap();
    let (_, data) = decrypt(&mut alice_conversation, &alice, &reply);
    assert_eq!(data, b"yes");

    let mut other = alice.create_conversation(None, 0).unwrap();
    let output = other.add_members(&alice, &[&key_package]).unwrap();
    other.merge_pending_commit(&alice).unwrap();
    assert!(bob
        .join_conversation(&output.welcome.unwrap(), &output.ratchet_tree.unwrap())
        .is_ok());

    assert_eq!(
        bob.load_conversation(b"no such group").err(),
        Some(ErrorKind::UnknownGroup)
    );

    bob_conversation.delete(&bob).unwrap();
    assert_eq!(
        bob.load_conversation(&group_id).err(),
        Some(ErrorKind::UnknownGroup)
    );
}

#[test]
fn restore_rejects_bad_snapshots() {
    let snapshot = client("alice").snapshot().unwrap();

    for bad in [
        &b""[..],
        &b"garbage"[..],
        &snapshot[..snapshot.len() - 1],
        &[snapshot.as_slice(), b"x"].concat(),
    ] {
        assert_eq!(
            MlsClient::restore(bad, MlsConfig::default(), Box::new(AllowAll)).err(),
            Some(ErrorKind::BadFormat)
        );
    }
}

#[test]
fn key_packages_are_consumed_unless_last_resort() {
    let alice = client("alice");
    let bob = client("bob");

    let one_time = bob.generate_key_package(false).unwrap();
    let last_resort = bob.generate_key_package(true).unwrap();

    for key_package in [&one_time, &last_resort] {
        let mut first = alice.create_conversation(None, 0).unwrap();
        let output = first.add_members(&alice, &[key_package]).unwrap();
        assert!(bob
            .join_conversation(&output.welcome.unwrap(), &output.ratchet_tree.unwrap())
            .is_ok());

        let mut second = alice.create_conversation(None, 0).unwrap();
        let output = second.add_members(&alice, &[key_package]).unwrap();
        let joined = bob.join_conversation(&output.welcome.unwrap(), &output.ratchet_tree.unwrap());

        if key_package == &last_resort {
            assert!(joined.is_ok());
        } else {
            assert_eq!(joined.err(), Some(ErrorKind::Rejected));
        }
    }
}

#[test]
fn validator_guards_membership() {
    let validator = || Box::new(AllowList(vec![b"alice", b"bob", b"lenient"]));
    let alice = MlsClient::new(b"alice", CIPHERSUITE, MlsConfig::default(), validator()).unwrap();
    let bob = MlsClient::new(b"bob", CIPHERSUITE, MlsConfig::default(), validator()).unwrap();
    let mallory = client("mallory");
    // accepts anyone, unlike alice and bob
    let lenient = client("lenient");

    // adding a refused identity
    let mut conversation = alice.create_conversation(None, 0).unwrap();
    let key_package = mallory.generate_key_package(false).unwrap();
    assert_eq!(
        conversation.add_members(&alice, &[&key_package]).err(),
        Some(ErrorKind::InvalidCredential)
    );

    // joining a group that contains a refused identity
    let mut conversation = mallory.create_conversation(None, 0).unwrap();
    let key_package = bob.generate_key_package(false).unwrap();
    let output = conversation.add_members(&mallory, &[&key_package]).unwrap();
    assert_eq!(
        bob.join_conversation(&output.welcome.unwrap(), &output.ratchet_tree.unwrap())
            .err(),
        Some(ErrorKind::InvalidCredential)
    );

    // a Commit that brings in a refused identity
    let (mut lenient_conversation, mut joined) = establish(&lenient, &[&bob]);
    let mut bob_conversation = joined.pop().unwrap();
    let epoch = bob_conversation.epoch();
    let key_package = mallory.generate_key_package(false).unwrap();
    let output = lenient_conversation
        .add_members(&lenient, &[&key_package])
        .unwrap();
    assert_eq!(
        bob_conversation.process(&bob, &output.commit).err(),
        Some(ErrorKind::InvalidCredential)
    );
    assert_eq!(bob_conversation.epoch(), epoch);
}

#[test]
fn routing_and_malformed_input() {
    let alice = client("alice");
    let bob = client("bob");

    let key_package = bob.generate_key_package(false).unwrap();
    assert!(matches!(inspect(&key_package), Ok(MessageKind::KeyPackage)));

    let mut conversation = alice.create_conversation(Some(b"route-me"), 0).unwrap();
    let output = conversation.add_members(&alice, &[&key_package]).unwrap();
    conversation.merge_pending_commit(&alice).unwrap();

    let welcome = output.welcome.unwrap();
    assert!(matches!(inspect(&welcome), Ok(MessageKind::Welcome)));
    match inspect(&output.commit) {
        Ok(MessageKind::Group(group_id)) => assert_eq!(group_id, b"route-me"),
        _ => panic!("expected a group message"),
    }

    let mut bob_conversation = bob
        .join_conversation(&welcome, &output.ratchet_tree.unwrap())
        .unwrap();
    assert_eq!(
        inspect(b"\x00\x01garbage").err(),
        Some(ErrorKind::BadFormat)
    );
    assert_eq!(
        bob_conversation.process(&bob, b"garbage").err(),
        Some(ErrorKind::BadFormat)
    );
    assert_eq!(
        bob_conversation.process(&bob, &welcome).err(),
        Some(ErrorKind::UnexpectedMessage)
    );
    assert_eq!(
        bob.join_conversation(&key_package, &[]).err(),
        Some(ErrorKind::UnexpectedMessage)
    );

    let other = alice
        .create_conversation(None, 0)
        .unwrap()
        .encrypt(&alice, b"x");
    assert_eq!(
        bob_conversation.process(&bob, &other.unwrap()).err(),
        Some(ErrorKind::UnexpectedMessage)
    );
}

#[test]
fn exported_secrets_match() {
    let alice = client("alice");
    let bob = client("bob");

    let (alice_conversation, mut joined) = establish(&alice, &[&bob]);
    let bob_conversation = joined.pop().unwrap();

    let a = alice_conversation
        .export_secret(&alice, "file key", b"file-1", 32)
        .unwrap();
    let b = bob_conversation
        .export_secret(&bob, "file key", b"file-1", 32)
        .unwrap();
    assert_eq!(a, b);
    assert_eq!(a.len(), 32);

    let c = alice_conversation
        .export_secret(&alice, "file key", b"file-2", 32)
        .unwrap();
    assert_ne!(a, c);
}

fn decode_key_package(client: &MlsClient, key_package: &[u8]) -> KeyPackage {
    match MlsMessageIn::tls_deserialize_exact(key_package)
        .unwrap()
        .extract()
    {
        MlsMessageBodyIn::KeyPackage(key_package) => key_package
            .validate(client.provider().crypto(), ProtocolVersion::Mls10)
            .unwrap(),
        _ => panic!("expected a KeyPackage"),
    }
}

#[test]
fn validator_guards_proposals() {
    let lenient = client("lenient");
    let bob = MlsClient::new(
        b"bob",
        CIPHERSUITE,
        MlsConfig::default(),
        Box::new(AllowList(vec![b"bob", b"lenient"])),
    )
    .unwrap();
    let mallory = client("mallory");

    let (mut lenient_conversation, mut joined) = establish(&lenient, &[&bob]);
    let mut bob_conversation = joined.pop().unwrap();

    // proposals are not something this API creates, but other clients may
    let key_package = mallory.generate_key_package(false).unwrap();
    let key_package = decode_key_package(&lenient, &key_package);
    let (proposal, _) = lenient_conversation
        .mls_group()
        .propose_add_member(lenient.provider(), lenient.signer(), &key_package)
        .unwrap();

    assert_eq!(
        bob_conversation
            .process(&bob, &proposal.to_bytes().unwrap())
            .err(),
        Some(ErrorKind::InvalidCredential)
    );
    assert_eq!(bob_conversation.mls_group().pending_proposals().count(), 0);
}

#[test]
fn other_credential_types() {
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).unwrap();
    let alice = MlsClient::with_credential(
        Credential::new(CredentialType::X509, b"issued for alice".to_vec()),
        signer,
        CIPHERSUITE,
        MlsConfig::default(),
        Box::new(AllowAll),
    )
    .unwrap();
    let bob = client("bob");

    let (mut alice_conversation, mut joined) = establish(&alice, &[&bob]);
    let mut bob_conversation = joined.pop().unwrap();

    let message = alice_conversation.encrypt(&alice, b"hi").unwrap();
    match bob_conversation.process(&bob, &message).unwrap() {
        IncomingMessage::Application { sender, .. } => {
            assert_eq!(sender.credential_type(), CredentialType::X509)
        }
        _ => panic!("expected an application message"),
    }

    // bob can bring alice into a group of his own as well
    let key_package = alice.generate_key_package(false).unwrap();
    let mut conversation = bob.create_conversation(None, 0).unwrap();
    let output = conversation.add_members(&bob, &[&key_package]).unwrap();
    assert!(alice
        .join_conversation(&output.welcome.unwrap(), &output.ratchet_tree.unwrap())
        .is_ok());

    // the signature key has to match the ciphersuite
    let signer = SignatureKeyPair::new(SignatureScheme::ECDSA_SECP256R1_SHA256).unwrap();
    assert_eq!(
        MlsClient::with_credential(
            Credential::new(CredentialType::X509, b"cert".to_vec()),
            signer,
            CIPHERSUITE,
            MlsConfig::default(),
            Box::new(AllowAll),
        )
        .err(),
        Some(ErrorKind::Crypto)
    );
}
