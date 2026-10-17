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
use openmls::prelude::{MlsMessageBodyIn, MlsMessageIn};
use openmls_traits::OpenMlsProvider;
use sha2::{Digest, Sha256};

use crate::internet::parameter::ParameterParser;

use super::super::{
    Ciphersuite, CommitOutput, Credential, CredentialValidator, ErrorKind, IncomingMessage,
    MlsClient, MlsConfig, MlsConversation,
};
use super::proto::{
    client_mls_rcs_message, server_mls_rcs_message, AcceptedMlsRcsMessage, ClientMlsRcsMessage,
    EpochIdentifier, FileEncryptionInfo, FileInfo, FileMetadata, MlsGroupInfo, ServerCommitBundle,
    ServerMlsRcsMessage,
};
use super::wire::{
    AuthenticatedData, DeliveryNotificationStatus, DisplayNotificationStatus, SecretPayload,
    VerifiableDeliveryImdn, VerifiableDisplayImdn, VerifiableResentMessage,
};
use super::*;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

struct AllowAll;

impl CredentialValidator for AllowAll {
    fn validate(&self, _credential: &Credential, _signature_key: &[u8]) -> bool {
        true
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

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// What the Conversation Focus forwards once it accepted a Commit: the bundle
/// without GroupInfo and epoch authenticator, with the ratchet tree for joiners
/// (RCC.16 section 7.9.3)
fn accept(output: &CommitOutput) -> ServerCommitBundle {
    let message: ClientMlsRcsMessage =
        proto::decode(&output.to_client_message(None).unwrap()).unwrap();
    match message.payload.unwrap() {
        // the ratchet tree is either the one sent along or reconstructed
        client_mls_rcs_message::Payload::WelcomeCommitBundle(bundle) => ServerCommitBundle {
            commit_list: bundle.commit_list,
            welcome: bundle.welcome,
            private_message: Vec::new(),
            ratchet_tree: output.ratchet_tree.clone().unwrap(),
        },
        client_mls_rcs_message::Payload::CommitBundle(bundle) => ServerCommitBundle {
            commit_list: bundle.commit_list,
            welcome: Vec::new(),
            private_message: bundle.private_message,
            ratchet_tree: Vec::new(),
        },
        _ => panic!("expected a Commit"),
    }
}

fn commit_sender(events: &[IncomingMessage]) -> Vec<u8> {
    match events {
        [IncomingMessage::Commit { sender, .. }] => sender.serialized_content().to_vec(),
        _ => panic!("expected a single Commit"),
    }
}

/// Alice starts an Era 2 conversation with Bob; returns both sides once the
/// initial Commit came back to Alice, and the GroupInfo of that epoch
fn establish(alice: &MlsClient, bob: &MlsClient) -> (MlsConversation, MlsConversation, Vec<u8>) {
    let key_package = bob.generate_key_package(false).unwrap();
    let mut alice_conversation = alice.create_conversation(None, 2).unwrap();
    let output = alice_conversation
        .add_members(alice, &[&key_package])
        .unwrap();

    let bundle = accept(&output);
    let bob_conversation = bob
        .join_conversation(&bundle.welcome, &bundle.ratchet_tree)
        .unwrap();
    let events = alice_conversation
        .process_commit_bundle(alice, &bundle)
        .unwrap();
    assert_eq!(
        commit_sender(&events),
        alice.credential().serialized_content()
    );

    (alice_conversation, bob_conversation, output.group_info)
}

#[test]
fn capability_feature_tags() {
    let contact = b"+g.gsma.rcs.mls.mls-version=\"v1\";+g.gsma.rcs.mls.mls-kds=\"42\";+sip.instance=\"<urn:uuid:e283b49b-8999-475d-c708-0805e279b4d1>\"";
    let capability =
        MlsCapability::from_parameters(ParameterParser::new(contact, b';', false)).unwrap();
    assert_eq!(capability.version, b"v1");
    assert_eq!(capability.home_kds, Some(42));
    assert_eq!(
        capability.feature_tags(),
        vec![
            "+g.gsma.rcs.mls.mls-version=\"v1\"",
            "+g.gsma.rcs.mls.mls-kds=\"42\""
        ]
    );

    let contact = b"+g.gsma.rcs.botversion=\"#=1,#=2\";+g.gsma.rcs.mls.mls-kds=\"42\"";
    assert!(MlsCapability::from_parameters(ParameterParser::new(contact, b';', false)).is_none());
}

#[test]
fn unencrypted_cpim_headers() {
    for name in [
        &b"From"[..],
        b"datetime",
        b"<urn:ietf:params:imdn>.Message-ID",
        b"<urn:ietf:params:imdn>.disposition-notification",
        b"<http://www.gsma.com/rcs>.advised-action",
        b"<http://www.gsma.com/rcs>.User-Profile-Config-Data",
        b"<http://www.gsma.com/rcs/mls>.Epoch-Authenticator",
        b"<http://www.gsma.com/rcs/mls/>.Epoch-Authenticator",
    ] {
        assert!(is_unencrypted_cpim_header(name), "{:?}", name);
    }

    for name in [
        &b"Subject"[..],
        b"<http://www.openmobilealliance.org/cpm/>.Payload-Type",
        b"<http://www.gsma.com/rcs/mls>.Original-Message-ID",
        b"<urn:ietf:params:imdn>.Message-ID-Suffix",
    ] {
        assert!(!is_unencrypted_cpim_header(name), "{:?}", name);
    }
}

#[test]
fn failure_reasons() {
    assert_eq!(
        ServerFailureReason::IncorrectEpochAuthenticator.xml_name(),
        "incorrect-epoch-authenticator"
    );
    assert_eq!(
        ServerFailureReason::from_xml_name(b"pending-proposal"),
        Some(ServerFailureReason::PendingProposal)
    );
    assert_eq!(ServerFailureReason::from_xml_name(b"unknown"), None);

    assert_eq!(
        ClientFailureReason::FailureToDecrypt.xml_name(),
        Some("failed-to-decrypt")
    );
    assert_eq!(ClientFailureReason::Unset.xml_name(), None);
    assert_eq!(
        ClientFailureReason::from_xml_name(b"commit-in-privatemessage"),
        Some(ClientFailureReason::CommitInPrivateMessage)
    );

    // added by RCC.16 v4.0
    assert_eq!(
        ServerFailureReason::from_xml_name(b"missing-mls-control-message"),
        Some(ServerFailureReason::MissingMlsControlMessage)
    );
    assert_eq!(
        ServerFailureReason::EpochAdvancementQuotaReached.xml_name(),
        "epoch-advancement-quota-reached"
    );
    assert_eq!(
        ClientFailureReason::InnerResentMessageFailureToDecrypt.xml_name(),
        Some("inner-resent-message-failed-to-decrypt")
    );
    for name in [
        &b"inner-resent-message-failed-to-decrypt"[..],
        b"inner-resent-message-decrypt",
        b"hpke-fail-to-decrypt",
    ] {
        assert_eq!(
            ClientFailureReason::from_xml_name(name),
            Some(ClientFailureReason::InnerResentMessageFailureToDecrypt)
        );
    }
    assert_eq!(
        wire::encode(&ClientFailureReason::ControlMessageFailed).unwrap(),
        [0, 13]
    );
}

#[test]
fn wire_structures() {
    let payload = SecretPayload::new(SecretPayloadType::Application, 7, b"hi".to_vec());
    let encoded = wire::encode(&payload).unwrap();
    assert_eq!(encoded, [0, 1, 0, 1, 0, 0, 0, 7, 2, b'h', b'i']);
    assert_eq!(wire::decode::<SecretPayload>(&encoded).unwrap(), payload);

    let authenticated_data = AuthenticatedData::new(b"abc", b"", 3, VerifiableDerivedContent::None);
    let encoded = wire::encode(&authenticated_data).unwrap();
    assert_eq!(encoded, [0, 1, 3, b'a', b'b', b'c', 0, 0, 0, 0, 3, 0, 0]);
    assert_eq!(
        wire::decode::<AuthenticatedData>(&encoded).unwrap(),
        authenticated_data
    );

    // the FTD of the illustration in RCC.16 section 7.5.3.3
    let imdn = VerifiableDeliveryImdn::new(
        DeliveryNotificationStatus::Failed,
        b"7",
        b"",
        ClientFailureReason::FailureToDecrypt,
    );
    assert_eq!(wire::encode(&imdn).unwrap(), [0, 1, 0, 2, 1, b'7', 0, 0, 4]);
    let authenticated_data =
        AuthenticatedData::new(b"42", b"", 1, VerifiableDerivedContent::DeliveryImdn(imdn));
    let encoded = wire::encode(&authenticated_data).unwrap();
    assert_eq!(
        encoded,
        [0, 1, 2, b'4', b'2', 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 2, 1, b'7', 0, 0, 4]
    );
    assert_eq!(
        wire::decode::<AuthenticatedData>(&encoded).unwrap(),
        authenticated_data
    );

    let display = VerifiableDisplayImdn::new(DisplayNotificationStatus::Displayed, b"77", b"7");
    assert_eq!(
        wire::encode(&VerifiableDerivedContent::DisplayImdn(display)).unwrap(),
        [0, 2, 0, 1, 0, 1, 2, b'7', b'7', 1, b'7']
    );
    assert_eq!(
        wire::encode(&VerifiableDerivedContent::ResentMessage(
            VerifiableResentMessage::new(b"7")
        ))
        .unwrap(),
        [0, 3, 0, 1, 1, b'7']
    );

    // unknown version, deprecated type, unknown derived content, trailing data
    assert!(wire::decode::<SecretPayload>(&[0, 2, 0, 1, 0, 0, 0, 0, 0]).is_err());
    assert!(wire::decode::<SecretPayload>(&[0, 1, 0, 3, 0, 0, 0, 0, 0]).is_err());
    assert!(wire::decode::<AuthenticatedData>(&[0, 1, 0, 0, 0, 0, 0, 1, 0, 4]).is_err());
    assert!(wire::decode::<SecretPayload>(&[0, 1, 0, 1, 0, 0, 0, 0, 0, 0]).is_err());
}

#[test]
fn message_lists() {
    let alice = client("alice");
    let bob = client("bob");
    let first = alice.generate_key_package(false).unwrap();
    let second = bob.generate_key_package(false).unwrap();

    let list = wire::encode_message_list(&[&first, &second]).unwrap();
    assert_eq!(
        wire::decode_message_list(&list).unwrap(),
        vec![first.clone(), second]
    );
    assert!(
        wire::decode_message_list(&wire::encode_message_list(&[]).unwrap())
            .unwrap()
            .is_empty()
    );

    let truncated = wire::encode(&openmls::prelude::tls_codec::VLBytes::new(
        first[..first.len() - 1].to_vec(),
    ))
    .unwrap();
    assert!(wire::decode_message_list(&truncated).is_err());
}

#[test]
fn commitment() {
    let alice = client("alice");
    let value = b"encrypted icon key";

    let mut hash_content = vec![4];
    hash_content.extend_from_slice(b"icon");
    hash_content.push(value.len() as u8);
    hash_content.extend_from_slice(value);

    let commitment =
        wire::commitment(alice.provider().crypto(), CIPHERSUITE, b"icon", value).unwrap();
    assert_eq!(commitment, Sha256::digest(&hash_content).to_vec());
    assert_ne!(
        commitment,
        wire::commitment(alice.provider().crypto(), CIPHERSUITE, b"subject", value).unwrap()
    );
}

#[test]
fn protobuf_messages() {
    let info = FileEncryptionInfo {
        file_length_hint: 1,
        ..Default::default()
    };
    // field 5 as fixed32
    assert_eq!(proto::encode(&info), [0x2d, 1, 0, 0, 0]);

    let file_info = FileInfo {
        file: Some(FileMetadata {
            file_name: "a.jpg".to_string(),
            content_type: "image/jpeg".to_string(),
            encryption_info: Some(info),
        }),
        ..Default::default()
    };
    assert_eq!(
        proto::decode::<FileInfo>(&proto::encode(&file_info)).unwrap(),
        file_info
    );

    let message = ServerMlsRcsMessage {
        payload: Some(server_mls_rcs_message::Payload::MlsGroupInfo(
            MlsGroupInfo {
                group_info: vec![1, 2],
                ratchet_tree: vec![3],
                pending_proposals: Vec::new(),
            },
        )),
    };
    let encoded = proto::encode(&message);
    assert_eq!(encoded, [0x1a, 7, 0x0a, 2, 1, 2, 0x12, 1, 3]);
    assert_eq!(
        proto::decode::<ServerMlsRcsMessage>(&encoded).unwrap(),
        message
    );
    assert!(proto::decode::<ServerMlsRcsMessage>(&[0x1a, 9]).is_err());
}

#[test]
fn padme() {
    for (length, padded) in [
        (0, 0),
        (1, 1),
        (2, 2),
        (3, 3),
        (9, 10),
        (100, 104),
        (1000, 1024),
        (65537, 67584),
        ((1 << 31) - 2, 1 << 31),
    ] {
        assert_eq!(file::padme(length), padded, "{}", length);
    }
}

/// Reference output of an independent implementation of Annex C.2
#[test]
fn file_encryption_reference() {
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let iv: [u8; 12] = core::array::from_fn(|i| 100 + i as u8);
    let message = "The quick brown fox jumps over the lazy dog. ".repeat(3);

    let encrypted = file::encrypt(&key, &iv, message.as_bytes(), "holiday photo.jpg").unwrap();
    assert_eq!(
        encrypted.ciphertext,
        hex("f206a691765cb4dea2153cf4e6292c22db4fc474794d41ee3651063dab8b7ece9804e6276cbdaac178ea9838299c073e56d832ad6e5822fa25e3ff70fa8bef322cd25ed8a052a0689443c972dee672b66478648321d20f8e1630ddadafc4d11822767ab3557f220ef4b54c7d08432ad0fdd020b44e453eab16be2fe9e7bf9aae3075ca1947296bc42f60d022a22e3a7b0858075c37347a03")
    );
    assert_eq!(
        encrypted.encryption_info.hmac_tag,
        hex("2b07b62656e320cf95b357d25217e6150a35973ee67c55b86df26cb11769c794")
    );
    assert_eq!(encrypted.encryption_info.file_length_hint, 135);

    assert_eq!(
        file::decrypt_file(
            &encrypted.ciphertext,
            "holiday photo.jpg",
            &encrypted.encryption_info
        )
        .unwrap(),
        message.as_bytes()
    );
}

#[test]
fn file_encryption() {
    for length in [0usize, 1, 100, 5000] {
        let content: Vec<u8> = (0..length).map(|i| i as u8).collect();
        let encrypted = file::encrypt_file(&content, "file.bin").unwrap();
        assert_eq!(
            encrypted.ciphertext.len() as u64,
            file::padme(length as u64) + 8
        );
        assert_eq!(
            file::decrypt_file(
                &encrypted.ciphertext,
                "file.bin",
                &encrypted.encryption_info
            )
            .unwrap(),
            content
        );
    }

    let encrypted = file::encrypt_file(b"secret", GROUP_SUBJECT_FILE_NAME).unwrap();
    let info = &encrypted.encryption_info;

    // keys are bound to the file name
    assert_eq!(
        file::decrypt_file(&encrypted.ciphertext, GROUP_ICON_FILE_NAME, info).err(),
        Some(ErrorKind::Rejected)
    );

    let mut tampered = encrypted.ciphertext.clone();
    tampered[0] ^= 1;
    assert_eq!(
        file::decrypt_file(&tampered, GROUP_SUBJECT_FILE_NAME, info).err(),
        Some(ErrorKind::Rejected)
    );

    let mut wrong_hint = info.clone();
    wrong_hint.file_length_hint += 1;
    assert_eq!(
        file::decrypt_file(&encrypted.ciphertext, GROUP_SUBJECT_FILE_NAME, &wrong_hint).err(),
        Some(ErrorKind::BadFormat)
    );

    // RCC.16 v4.0 dropped the hint
    let mut no_hint = info.clone();
    no_hint.file_length_hint = 0;
    assert!(file::decrypt_file(&encrypted.ciphertext, GROUP_SUBJECT_FILE_NAME, &no_hint).is_ok());

    let mut unspecified = info.clone();
    unspecified.algorithm = proto::Algorithm::Unspecified as i32;
    assert_eq!(
        file::decrypt_file(&encrypted.ciphertext, GROUP_SUBJECT_FILE_NAME, &unspecified).err(),
        Some(ErrorKind::BadFormat)
    );

    assert_eq!(
        file::decrypt_file(&[0; 7], GROUP_SUBJECT_FILE_NAME, info).err(),
        Some(ErrorKind::BadFormat)
    );
}

#[test]
fn conversation_creation() {
    let alice = client("alice");
    let bob = client("bob");

    let key_package = bob.generate_key_package(false).unwrap();
    let mut alice_conversation = alice.create_conversation(None, 2).unwrap();
    assert_eq!(alice_conversation.era(), Some(2));
    assert_eq!(alice_conversation.epoch(), 0);

    let output = alice_conversation
        .add_members(&alice, &[&key_package])
        .unwrap();

    // the initial Commit carries the ratchet tree, and goes out as a PublicMessage
    let message: ClientMlsRcsMessage =
        proto::decode(&output.to_client_message(None).unwrap()).unwrap();
    let bundle = match message.payload {
        Some(client_mls_rcs_message::Payload::WelcomeCommitBundle(bundle)) => bundle,
        _ => panic!("expected a WelcomeCommitBundle"),
    };
    assert!(!bundle.ratchet_tree.is_empty());
    assert_eq!(bundle.epoch_authenticator, output.epoch_authenticator);
    let commits = wire::decode_message_list(&bundle.commit_list).unwrap();
    assert_eq!(commits, vec![output.commit.clone()]);
    assert!(matches!(
        MlsMessageIn::tls_deserialize_exact(&commits[0])
            .unwrap()
            .extract(),
        MlsMessageBodyIn::PublicMessage(_)
    ));
    assert!(matches!(
        MlsMessageIn::tls_deserialize_exact(&bundle.group_info)
            .unwrap()
            .extract(),
        MlsMessageBodyIn::GroupInfo(_)
    ));

    // applied once the Conversation Focus delivered it back
    assert_eq!(alice_conversation.epoch(), 0);
    let server_bundle = accept(&output);
    let mut bob_conversation = bob
        .join_conversation(&server_bundle.welcome, &server_bundle.ratchet_tree)
        .unwrap();
    match alice_conversation
        .process_commit_bundle(&alice, &server_bundle)
        .unwrap()
        .as_slice()
    {
        [IncomingMessage::Commit { added, .. }] => {
            assert_eq!(added.len(), 1);
            assert_eq!(added[0].serialized_content(), b"bob");
        }
        _ => panic!("expected a Commit"),
    }

    assert_eq!(alice_conversation.epoch(), 1);
    assert_eq!(bob_conversation.epoch(), 1);
    assert_eq!(bob_conversation.era(), Some(2));
    assert_eq!(
        alice_conversation.epoch_authenticator(),
        output.epoch_authenticator
    );
    assert_eq!(
        bob_conversation.epoch_authenticator(),
        output.epoch_authenticator
    );

    // later Commits come without ratchet tree and Welcome
    let output = bob_conversation.update_keys(&bob).unwrap();
    assert!(output.ratchet_tree.is_none());
    let message: ClientMlsRcsMessage =
        proto::decode(&output.to_client_message(Some(b"keys")).unwrap()).unwrap();
    match message.payload {
        Some(client_mls_rcs_message::Payload::CommitBundle(bundle)) => {
            assert_eq!(bundle.private_message, b"keys");
        }
        _ => panic!("expected a CommitBundle"),
    }

    let server_bundle = accept(&output);
    let body = proto::encode(&ServerMlsRcsMessage {
        payload: Some(server_mls_rcs_message::Payload::ServerCommitBundle(
            server_bundle,
        )),
    });
    for (conversation, client) in [
        (&mut alice_conversation, &alice),
        (&mut bob_conversation, &bob),
    ] {
        let events = conversation.process_server_message(client, &body).unwrap();
        assert_eq!(commit_sender(&events), b"bob");
        assert_eq!(conversation.epoch(), 2);
        assert_eq!(
            conversation.epoch_authenticator(),
            output.epoch_authenticator
        );
    }
}

#[test]
fn encrypted_messages() {
    let alice = client("alice");
    let bob = client("bob");
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);

    let cpim = b"NS: cpm <http://www.openmobilealliance.org/cpm/>\r\ncpm.Payload-Type: text\r\n\r\nContent-Type: text/plain\r\n\r\nhello";
    let message = alice_conversation
        .encrypt_cpim(&alice, cpim, b"msg-1", b"")
        .unwrap();
    assert!(matches!(
        MlsMessageIn::tls_deserialize_exact(&message)
            .unwrap()
            .extract(),
        MlsMessageBodyIn::PrivateMessage(_)
    ));

    let decrypted = bob_conversation.decrypt(&bob, &message, b"msg-1").unwrap();
    assert_eq!(decrypted.sender.serialized_content(), b"alice");
    assert_eq!(decrypted.payload_type, SecretPayloadType::Application);
    assert_eq!(decrypted.payload.as_deref(), Some(&cpim[..]));
    assert!(decrypted.original_message_id.is_empty());

    // the CPIM Message-ID is bound to the ciphertext
    let message = alice_conversation
        .encrypt_cpim(&alice, cpim, b"msg-2", b"")
        .unwrap();
    assert_eq!(
        bob_conversation.decrypt(&bob, &message, b"msg-3").err(),
        Some(ErrorKind::Rejected)
    );

    // re-sent messages carry the original Message-ID
    let message = bob_conversation
        .encrypt_cpim(&bob, b"again", b"msg-4", b"msg-2")
        .unwrap();
    let decrypted = alice_conversation
        .decrypt(&alice, &message, b"msg-4")
        .unwrap();
    assert_eq!(decrypted.original_message_id, b"msg-2");

    // Commits are no encrypted messages, and are left alone
    let output = alice_conversation.update_keys(&alice).unwrap();
    assert_eq!(
        bob_conversation
            .decrypt(&bob, &output.commit, b"msg-5")
            .err(),
        Some(ErrorKind::UnexpectedMessage)
    );
    assert_eq!(bob_conversation.epoch(), 1);

    // PADME padding: equal lengths within the same PADME range
    let short = bob_conversation
        .encrypt_cpim(&bob, &[b'a'; 2000], b"msg-6", b"")
        .unwrap();
    let long = bob_conversation
        .encrypt_cpim(&bob, &[b'a'; 2010], b"msg-7", b"")
        .unwrap();
    assert_eq!(short.len(), long.len());
}

#[test]
fn signed_messages() {
    let alice = client("alice");
    let bob = client("bob");
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);

    // signed content as in the illustration of RCC.16 section 7.5.3.3
    let delivered = wire::encode(&AuthenticatedData::new(
        b"imdn-1",
        b"",
        2,
        VerifiableDerivedContent::DeliveryImdn(VerifiableDeliveryImdn::new(
            DeliveryNotificationStatus::Delivered,
            b"msg-1",
            b"",
            ClientFailureReason::Unset,
        )),
    ))
    .unwrap();
    let signature = bob_conversation.sign(&bob, &delivered).unwrap();
    assert!(matches!(
        MlsMessageIn::tls_deserialize_exact(&signature)
            .unwrap()
            .extract(),
        MlsMessageBodyIn::PublicMessage(_)
    ));

    let signer = alice_conversation
        .verify_signature(&alice, &signature, &delivered)
        .unwrap();
    assert_eq!(signer.serialized_content(), b"bob");

    let displayed = wire::encode(&AuthenticatedData::new(
        b"imdn-2",
        b"",
        2,
        VerifiableDerivedContent::DisplayImdn(VerifiableDisplayImdn::new(
            DisplayNotificationStatus::Displayed,
            b"msg-1",
            b"",
        )),
    ))
    .unwrap();
    assert_eq!(
        alice_conversation
            .verify_signature(&alice, &signature, &displayed)
            .err(),
        Some(ErrorKind::Rejected)
    );

    // the signature proposal is not left behind, sending still works
    assert!(bob_conversation
        .mls_group()
        .pending_proposals()
        .next()
        .is_none());
    assert!(bob_conversation
        .encrypt_cpim(&bob, b"hi", b"msg-2", b"")
        .is_ok());

    // an encrypted message is no signature
    let message = bob_conversation
        .encrypt_cpim(&bob, b"hi", b"msg-3", b"")
        .unwrap();
    assert_eq!(
        alice_conversation
            .verify_signature(&alice, &message, &delivered)
            .err(),
        Some(ErrorKind::Rejected)
    );
}

#[test]
fn ending_encryption() {
    let alice = client("alice");
    let bob = client("bob");
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);
    assert!(!alice_conversation.is_encryption_ended());

    let output = alice_conversation
        .set_encryption_ended(
            &alice,
            Some(proto::EndMlsReason::GroupMemberFailsCapabilitiesCheck),
        )
        .unwrap();
    let bundle = accept(&output);
    alice_conversation
        .process_commit_bundle(&alice, &bundle)
        .unwrap();
    bob_conversation
        .process_commit_bundle(&bob, &bundle)
        .unwrap();

    for conversation in [&alice_conversation, &bob_conversation] {
        assert!(conversation.is_encryption_ended());
        assert_eq!(
            conversation.encryption_ended_reason(),
            Some(proto::EndMlsReason::GroupMemberFailsCapabilitiesCheck)
        );
        assert_eq!(conversation.era(), Some(2));
    }
    assert_eq!(
        bob_conversation
            .encrypt_cpim(&bob, b"hi", b"msg-1", b"")
            .err(),
        Some(ErrorKind::InvalidState)
    );

    let output = bob_conversation.set_encryption_ended(&bob, None).unwrap();
    let bundle = accept(&output);
    alice_conversation
        .process_commit_bundle(&alice, &bundle)
        .unwrap();
    bob_conversation
        .process_commit_bundle(&bob, &bundle)
        .unwrap();
    assert!(!alice_conversation.is_encryption_ended());
    assert_eq!(alice_conversation.encryption_ended_reason(), None);
    assert!(bob_conversation
        .encrypt_cpim(&bob, b"hi", b"msg-2", b"")
        .is_ok());
}

#[test]
fn self_heal() {
    let alice = client("alice");
    let bob = client("bob");
    let (mut alice_conversation, bob_conversation, group_info) = establish(&alice, &bob);
    let group_id = bob_conversation.group_id().to_vec();

    // bob's state of the group is lost
    bob_conversation.delete(&bob).unwrap();

    let (mut bob_conversation, output) = bob
        .rejoin_conversation(&MlsGroupInfo {
            group_info,
            ratchet_tree: alice_conversation.ratchet_tree().unwrap(),
            pending_proposals: Vec::new(),
        })
        .unwrap();
    assert_eq!(bob_conversation.group_id(), group_id);

    let bundle = accept(&output);
    match alice_conversation
        .process_commit_bundle(&alice, &bundle)
        .unwrap()
        .as_slice()
    {
        [IncomingMessage::Commit {
            sender,
            added,
            removed,
            ..
        }] => {
            assert_eq!(sender.serialized_content(), b"bob");
            // the old leaf of bob is replaced
            assert!(added.is_empty());
            assert_eq!(removed.len(), 1);
        }
        _ => panic!("expected a Commit"),
    }
    bob_conversation
        .process_commit_bundle(&bob, &bundle)
        .unwrap();

    assert_eq!(alice_conversation.members().len(), 2);
    assert_eq!(
        alice_conversation.epoch_authenticator(),
        bob_conversation.epoch_authenticator()
    );

    let message = alice_conversation
        .encrypt_cpim(&alice, b"welcome back", b"msg-1", b"")
        .unwrap();
    assert_eq!(
        bob_conversation
            .decrypt(&bob, &message, b"msg-1")
            .unwrap()
            .payload
            .as_deref(),
        Some(&b"welcome back"[..])
    );
}

#[test]
fn leaving_through_proposal_list() {
    let alice = client("alice");
    let bob = client("bob");
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);

    let proposal = bob_conversation.leave(&bob).unwrap();
    let body = proto::encode(&ServerMlsRcsMessage {
        payload: Some(server_mls_rcs_message::Payload::ProposalList(
            wire::encode_message_list(&[&proposal]).unwrap(),
        )),
    });

    match alice_conversation
        .process_server_message(&alice, &body)
        .unwrap()
        .as_slice()
    {
        [IncomingMessage::Proposal { sender }] => assert_eq!(sender.serialized_content(), b"bob"),
        _ => panic!("expected a Proposal"),
    }

    let output = alice_conversation.commit_pending_proposals(&alice).unwrap();
    let bundle = accept(&output);
    alice_conversation
        .process_commit_bundle(&alice, &bundle)
        .unwrap();
    match bob_conversation
        .process_commit_bundle(&bob, &bundle)
        .unwrap()
        .as_slice()
    {
        [IncomingMessage::Commit { self_removed, .. }] => assert!(*self_removed),
        _ => panic!("expected a Commit"),
    }
    assert_eq!(alice_conversation.members().len(), 1);
}

#[test]
fn one_to_one_group_id() {
    let alice = client("alice");

    // a GUID in hex digits, fitting the group_id[32] of RCC.16 Annex C.4.1 as it is
    let conversation = alice.create_conversation(None, 1).unwrap();
    assert_eq!(conversation.group_id().len(), 32);
    assert!(conversation
        .group_id()
        .iter()
        .all(|digit| digit.is_ascii_hexdigit()));
    assert_ne!(
        alice.create_conversation(None, 1).unwrap().group_id(),
        conversation.group_id()
    );

    let conversation = alice.create_conversation(Some(b"group"), 1).unwrap();
    assert_eq!(conversation.group_id(), b"group");
}

#[test]
fn resent_messages() {
    let alice = client("alice");
    let bob = client("bob");
    let carol = client("carol");

    let key_packages = [
        bob.generate_key_package(false).unwrap(),
        carol.generate_key_package(false).unwrap(),
    ];
    let mut alice_conversation = alice.create_conversation(None, 2).unwrap();
    let output = alice_conversation
        .add_members(&alice, &[&key_packages[0], &key_packages[1]])
        .unwrap();
    let bundle = accept(&output);
    let mut bob_conversation = bob
        .join_conversation(&bundle.welcome, &bundle.ratchet_tree)
        .unwrap();
    let mut carol_conversation = carol
        .join_conversation(&bundle.welcome, &bundle.ratchet_tree)
        .unwrap();
    alice_conversation
        .process_commit_bundle(&alice, &bundle)
        .unwrap();

    // Bob reported failing to decrypt msg-1, which Alice sends him again
    let original = b"NS: cpm <http://www.openmobilealliance.org/cpm/>\r\n\r\nContent-Type: text/plain\r\n\r\nhello";
    let message = alice_conversation
        .encrypt_resent(&alice, original, bob.credential(), b"msg-2", b"msg-1")
        .unwrap();

    let decrypted = bob_conversation.decrypt(&bob, &message, b"msg-2").unwrap();
    assert_eq!(decrypted.sender.serialized_content(), b"alice");
    assert_eq!(decrypted.payload_type, SecretPayloadType::Hpke1To1Message);
    assert_eq!(decrypted.payload.as_deref(), Some(&original[..]));
    assert_eq!(decrypted.original_message_id, b"msg-1");
    assert!(bob_conversation
        .resent_matches(&bob, &decrypted.original_message_hmac, original)
        .unwrap());

    // the rest of the group sees that a message was re-sent, but not which
    let decrypted = carol_conversation
        .decrypt(&carol, &message, b"msg-2")
        .unwrap();
    assert_eq!(decrypted.payload_type, SecretPayloadType::Hpke1To1Message);
    assert_eq!(decrypted.payload, None);
    assert_eq!(decrypted.original_message_id, b"msg-1");

    // members that decrypted the Original Message check they got the same one
    let hmac = &decrypted.original_message_hmac;
    assert!(carol_conversation
        .resent_matches(&carol, hmac, original)
        .unwrap());
    assert!(!carol_conversation
        .resent_matches(&carol, hmac, b"something else")
        .unwrap());
    assert_eq!(
        carol_conversation
            .resent_matches(&carol, &hmac[32..], original)
            .err(),
        Some(ErrorKind::BadFormat)
    );

    // padded as files are
    let short = alice_conversation
        .encrypt_resent(&alice, &[b'a'; 2000], bob.credential(), b"msg-3", b"msg-1")
        .unwrap();
    let long = alice_conversation
        .encrypt_resent(&alice, &[b'a'; 2010], bob.credential(), b"msg-4", b"msg-1")
        .unwrap();
    assert_eq!(short.len(), long.len());

    // sealed to the leaf key Bob has at the time; once he replaced it, a message
    // re-sent before can no longer be read
    let output = bob_conversation.update_keys(&bob).unwrap();
    let message = carol_conversation
        .encrypt_resent(&carol, b"again", bob.credential(), b"msg-5", b"msg-1")
        .unwrap();
    let bundle = accept(&output);
    for (conversation, client) in [
        (&mut alice_conversation, &alice),
        (&mut bob_conversation, &bob),
        (&mut carol_conversation, &carol),
    ] {
        conversation.process_commit_bundle(client, &bundle).unwrap();
    }
    let message_after = carol_conversation
        .encrypt_resent(&carol, b"later", bob.credential(), b"msg-6", b"msg-1")
        .unwrap();
    assert_eq!(
        bob_conversation
            .decrypt(&bob, &message_after, b"msg-6")
            .unwrap()
            .payload
            .as_deref(),
        Some(&b"later"[..])
    );
    assert_eq!(
        bob_conversation.decrypt(&bob, &message, b"msg-5").err(),
        Some(ErrorKind::Rejected)
    );

    // only to members
    let mallory = client("mallory");
    assert_eq!(
        alice_conversation
            .encrypt_resent(&alice, original, mallory.credential(), b"msg-7", b"msg-1")
            .err(),
        Some(ErrorKind::UnknownMember)
    );
}

#[test]
fn imdn_failure_reasons() {
    let imdn = br#"<?xml version="1.0" encoding="UTF-8"?>
<imdn xmlns="urn:ietf:params:xml:ns:imdn">
  <message-id>34jk324j</message-id>
  <datetime>2008-04-04T12:16:49-05:00</datetime>
  <delivery-notification>
    <status>
      <failed>
        <mls-server-failure-reason><incorrect-epoch/></mls-server-failure-reason>
      </failed>
    </status>
  </delivery-notification>
</imdn>"#;
    assert_eq!(
        imdn::failure_reason(imdn),
        Some(imdn::FailureReason::Server(
            ServerFailureReason::IncorrectEpoch
        ))
    );

    for reason in [
        ClientFailureReason::MessageFromNonMember,
        ClientFailureReason::InvalidCredential,
        ClientFailureReason::InvalidCommit,
        ClientFailureReason::FailureToDecrypt,
        ClientFailureReason::CommitInPrivateMessage,
    ] {
        let imdn = format!(
            "<imdn xmlns=\"urn:ietf:params:xml:ns:imdn\"><message-id>1</message-id><delivery-notification>{}</delivery-notification></imdn>",
            imdn::failed_status(reason)
        );
        assert_eq!(
            imdn::failure_reason(imdn.as_bytes()),
            Some(imdn::FailureReason::Client(reason))
        );
    }

    // prefixed elements, as with an extension namespace
    let imdn = br#"<imdn xmlns="urn:ietf:params:xml:ns:imdn" xmlns:m="urn:gsma:params:xml:ns:rcs:mls"><delivery-notification><status><failed><m:mls-client-failure-reason><m:failed-to-decrypt/></m:mls-client-failure-reason></failed></status></delivery-notification></imdn>"#;
    assert_eq!(
        imdn::failure_reason(imdn),
        Some(imdn::FailureReason::Client(
            ClientFailureReason::FailureToDecrypt
        ))
    );

    assert_eq!(
        imdn::failed_status(ClientFailureReason::Unset),
        "<status><failed/></status>"
    );
    for imdn in [
        &b"<imdn><delivery-notification><status><failed/></status></delivery-notification></imdn>"[..],
        b"<imdn><delivery-notification><status><delivered/></status></delivery-notification></imdn>",
        b"<imdn><status><failed><mls-server-failure-reason></mls-server-failure-reason></failed></status></imdn>",
        b"<imdn><status><failed><mls-server-failure-reason><unknown-reason/></mls-server-failure-reason></failed></status></imdn>",
        b"not xml <",
    ] {
        assert_eq!(imdn::failure_reason(imdn), None);
    }
}

#[test]
fn welcome_without_ratchet_tree() {
    let alice = client("alice");
    let bob = client("bob");

    // last resort, which a failed attempt to join does not use up
    let key_package = bob.generate_key_package(true).unwrap();
    let mut alice_conversation = alice.create_conversation(None, 2).unwrap();
    let output = alice_conversation
        .add_members(&alice, &[&key_package])
        .unwrap();

    // the tree only travels next to the Welcome (RCC.16 section 7.9.2)
    assert_eq!(
        bob.join_conversation(output.welcome.as_ref().unwrap(), &[])
            .err(),
        Some(ErrorKind::Rejected)
    );
    let bundle = accept(&output);
    assert!(bob
        .join_conversation(&bundle.welcome, &bundle.ratchet_tree)
        .is_ok());
    alice_conversation
        .process_commit_bundle(&alice, &bundle)
        .unwrap();

    // later additions leave it to the Conversation Focus to reconstruct the tree
    let carol = client("carol");
    let key_package = carol.generate_key_package(false).unwrap();
    let output = alice_conversation
        .add_members(&alice, &[&key_package])
        .unwrap();
    let message: ClientMlsRcsMessage =
        proto::decode(&output.to_client_message(None).unwrap()).unwrap();
    match message.payload {
        Some(client_mls_rcs_message::Payload::WelcomeCommitBundle(bundle)) => {
            assert!(bundle.ratchet_tree.is_empty())
        }
        _ => panic!("expected a WelcomeCommitBundle"),
    }
    let bundle = accept(&output);
    alice_conversation
        .process_commit_bundle(&alice, &bundle)
        .unwrap();
    assert_eq!(
        bundle.ratchet_tree,
        alice_conversation.ratchet_tree().unwrap()
    );
    assert!(carol
        .join_conversation(&bundle.welcome, &bundle.ratchet_tree)
        .is_ok());
}

#[test]
fn accepted_commits() {
    let alice = client("alice");
    let bob = client("bob");
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);

    let accepted = |epoch: EpochIdentifier| {
        proto::encode(&ServerMlsRcsMessage {
            payload: Some(server_mls_rcs_message::Payload::AcceptedMlsRcsMessage(
                AcceptedMlsRcsMessage {
                    message_id: "cpim-1".to_string(),
                    previous_epoch_identifier: Some(epoch),
                },
            )),
        })
    };

    // nothing to apply, e.g. for a ProposalList
    let before = alice_conversation.epoch_identifier();
    assert_eq!(before.era_id, 2);
    assert_eq!(before.epoch_id, 1);
    assert!(matches!(
        alice_conversation
            .process_server_message(&alice, &accepted(before.clone()))
            .unwrap()
            .as_slice(),
        [IncomingMessage::Own]
    ));

    let output = alice_conversation.update_keys(&alice).unwrap();

    // accepted in another epoch
    let mut other = before.clone();
    other.epoch_id += 1;
    assert_eq!(
        alice_conversation
            .process_server_message(&alice, &accepted(other))
            .err(),
        Some(ErrorKind::UnexpectedMessage)
    );
    assert!(alice_conversation.has_pending_commit());

    match alice_conversation
        .process_server_message(&alice, &accepted(before))
        .unwrap()
        .as_slice()
    {
        [IncomingMessage::Commit { sender, .. }] => {
            assert_eq!(sender.serialized_content(), b"alice")
        }
        _ => panic!("expected a Commit"),
    }
    assert!(!alice_conversation.has_pending_commit());
    assert_eq!(
        alice_conversation.epoch_authenticator(),
        output.epoch_authenticator
    );

    // should the Commit still be delivered back, it is recognised
    let bundle = accept(&output);
    assert!(matches!(
        alice_conversation
            .process_commit_bundle(&alice, &bundle)
            .unwrap()
            .as_slice(),
        [IncomingMessage::Own]
    ));
    bob_conversation
        .process_commit_bundle(&bob, &bundle)
        .unwrap();
    assert_eq!(
        bob_conversation.epoch_authenticator(),
        alice_conversation.epoch_authenticator()
    );
}

#[test]
fn key_generations() {
    let alice = client("alice");
    let bob = client("bob");
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);

    let key_generation =
        |conversation: &mut MlsConversation, client: &MlsClient, message: &[u8]| match conversation
            .process(client, message)
            .unwrap()
        {
            IncomingMessage::Application { data, .. } => {
                wire::decode::<SecretPayload>(&data).unwrap().key_generation
            }
            _ => panic!("expected an application message"),
        };

    for expected in 0..3 {
        let message = alice_conversation
            .encrypt_cpim(&alice, b"hi", b"msg", b"")
            .unwrap();
        assert_eq!(
            key_generation(&mut bob_conversation, &bob, &message),
            expected
        );
    }

    // other messages use up generations as well
    alice_conversation.encrypt(&alice, b"raw").unwrap();
    let message = alice_conversation
        .encrypt_cpim(&alice, b"hi", b"msg", b"")
        .unwrap();
    assert_eq!(key_generation(&mut bob_conversation, &bob, &message), 4);

    // the count is part of the snapshot
    let restored = MlsClient::restore(
        &alice.snapshot().unwrap(),
        MlsConfig::default(),
        Box::new(AllowAll),
    )
    .unwrap();
    let mut restored_conversation = restored
        .load_conversation(alice_conversation.group_id())
        .unwrap();
    let message = restored_conversation
        .encrypt_cpim(&restored, b"hi", b"msg", b"")
        .unwrap();
    assert_eq!(key_generation(&mut bob_conversation, &bob, &message), 5);

    // and starts over in every epoch
    let output = bob_conversation.update_keys(&bob).unwrap();
    let bundle = accept(&output);
    alice_conversation
        .process_commit_bundle(&alice, &bundle)
        .unwrap();
    bob_conversation
        .process_commit_bundle(&bob, &bundle)
        .unwrap();
    let message = alice_conversation
        .encrypt_cpim(&alice, b"hi", b"msg", b"")
        .unwrap();
    assert_eq!(key_generation(&mut bob_conversation, &bob, &message), 0);
}

#[test]
fn reserved_extension_types() {
    let alice = client("alice");
    let key_package = alice.generate_key_package(false).unwrap();
    let key_package = match MlsMessageIn::tls_deserialize_exact(&key_package)
        .unwrap()
        .extract()
    {
        MlsMessageBodyIn::KeyPackage(key_package) => key_package,
        _ => panic!("expected a KeyPackage"),
    };
    let key_package = key_package
        .validate(
            alice.provider().crypto(),
            openmls::prelude::ProtocolVersion::Mls10,
        )
        .unwrap();
    let capabilities = key_package.leaf_node().capabilities().clone();

    for code in [EXTENSION_CONTINUITY_TOKEN_COMMITMENT, 0xF012, 0xF030] {
        assert!(capabilities
            .extensions()
            .contains(&openmls::prelude::ExtensionType::from(code)));
    }
    assert!(capabilities
        .proposals()
        .contains(&openmls::prelude::ProposalType::from(0xF020)));
}
