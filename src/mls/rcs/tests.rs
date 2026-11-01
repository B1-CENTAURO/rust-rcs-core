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
use openmls_traits::storage::StorageProvider as _;
use openmls_traits::OpenMlsProvider;
use sha2::{Digest, Sha256};

use crate::internet::parameter::ParameterParser;

use super::super::{
    Ciphersuite, CommitOutput, Credential, CredentialValidator, ErrorKind, IncomingMessage,
    MlsClient, MlsConfig, MlsConversation,
};
use super::heal::SelfHealProgress;
use super::proto::{
    client_mls_rcs_message, server_mls_rcs_message, AcceptedMlsRcsMessage, ClientMlsRcsMessage,
    EpochControlMessages, EpochIdentifier, FileEncryptionInfo, FileInfo, FileMetadata,
    MlsEnhancedGroupInfo, MlsGroupInfo, ServerCommitBundle, ServerMlsRcsMessage,
};
use super::wire::{
    AuthenticatedData, DeliveryNotificationStatus, DisplayNotificationStatus,
    HpkeInnerEncapsulatedKeyAndCiphertext, SecretPayload, VerifiableDeliveryImdn,
    VerifiableDisplayImdn, VerifiableResentMessage,
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
    let message: ClientMlsRcsMessage = proto::decode(&output.to_client_message().unwrap()).unwrap();
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
    let message: ClientMlsRcsMessage = proto::decode(&output.to_client_message().unwrap()).unwrap();
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
    assert!(output.private_message.is_none());
    let message: ClientMlsRcsMessage = proto::decode(&output.to_client_message().unwrap()).unwrap();
    match message.payload {
        Some(client_mls_rcs_message::Payload::CommitBundle(bundle)) => {
            assert!(bundle.private_message.is_empty());
            assert_eq!(bundle.epoch_authenticator, output.epoch_authenticator);
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

    // a Commit not adding end_mls
    let (output, _) = alice_conversation
        .set_group_subject(&alice, "Team", b"msg-subject")
        .unwrap();
    assert_eq!(alice_conversation.pending_encryption_end(), None);
    let bundle = accept(&output);
    alice_conversation
        .process_commit_bundle(&alice, &bundle)
        .unwrap();
    bob_conversation
        .process_commit_bundle(&bob, &bundle)
        .unwrap();

    let output = alice_conversation
        .set_encryption_ended(
            &alice,
            Some(proto::EndMlsReason::GroupMemberFailsCapabilitiesCheck),
        )
        .unwrap();
    assert_eq!(
        alice_conversation.pending_encryption_end(),
        Some(proto::EndMlsReason::GroupMemberFailsCapabilitiesCheck)
    );
    assert!(!alice_conversation.is_encryption_ended());
    // not the first Commit of the Era
    let message: ClientMlsRcsMessage = proto::decode(&output.to_client_message().unwrap()).unwrap();
    assert!(matches!(
        message.payload,
        Some(client_mls_rcs_message::Payload::CommitBundle(_))
    ));
    let bundle = accept(&output);
    alice_conversation
        .process_commit_bundle(&alice, &bundle)
        .unwrap();
    bob_conversation
        .process_commit_bundle(&bob, &bundle)
        .unwrap();
    assert_eq!(alice_conversation.pending_encryption_end(), None);

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

    // nor one removing it, or giving another reason
    let output = bob_conversation
        .set_encryption_ended(&bob, Some(proto::EndMlsReason::InternalClientError))
        .unwrap();
    assert_eq!(bob_conversation.pending_encryption_end(), None);
    bob_conversation.discard_pending_commit(&bob).unwrap();
    drop(output);
    let output = bob_conversation.set_encryption_ended(&bob, None).unwrap();
    assert_eq!(bob_conversation.pending_encryption_end(), None);
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
fn leave_message() {
    let alice = client("alice");
    let bob = client("bob");
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);

    // not while a Commit of bob's own is pending
    let output = bob_conversation.update_keys(&bob).unwrap();
    assert_eq!(
        bob_conversation.leave_message(&bob).err(),
        Some(ErrorKind::InvalidState)
    );
    bob_conversation
        .process_commit_bundle(&bob, &accept(&output))
        .unwrap();
    alice_conversation
        .process_commit_bundle(&alice, &accept(&output))
        .unwrap();

    // the BYE's body holds the ProposalList, which the Focus forwards as it is
    let body = bob_conversation.leave_message(&bob).unwrap();
    let message: ClientMlsRcsMessage = proto::decode(&body).unwrap();
    let list = match message.payload {
        Some(client_mls_rcs_message::Payload::ProposalList(list)) => list,
        _ => panic!("expected a ProposalList"),
    };
    let proposals = wire::decode_message_list(&list).unwrap();
    assert_eq!(proposals.len(), 1);
    assert!(proposals[0].windows(3).any(|w| w == [2, 0xF0, 0x03]));

    let forwarded = proto::encode(&ServerMlsRcsMessage {
        payload: Some(server_mls_rcs_message::Payload::ProposalList(list)),
    });
    match alice_conversation
        .process_server_message(&alice, &forwarded)
        .unwrap()
        .as_slice()
    {
        [IncomingMessage::Proposal { sender }] => assert_eq!(sender.serialized_content(), b"bob"),
        _ => panic!("expected a Proposal"),
    }

    let output = alice_conversation.commit_pending_proposals(&alice).unwrap();
    deliver((&mut alice_conversation, &alice), vec![], &output);
    match bob_conversation
        .process_commit_bundle(&bob, &accept(&output))
        .unwrap()
        .as_slice()
    {
        [IncomingMessage::Commit { self_removed, .. }] => assert!(*self_removed),
        _ => panic!("expected a Commit"),
    }
    assert_eq!(alice_conversation.members().len(), 1);
}

#[test]
fn withdrawing_own_proposals() {
    let alice = client("alice");
    let bob = client("bob");
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);

    // a leave the Focus refused: bob's own self_remove would keep him from
    // committing anything
    bob_conversation.leave_message(&bob).unwrap();
    assert_eq!(
        bob_conversation.update_keys(&bob).err(),
        Some(ErrorKind::InvalidState)
    );
    bob_conversation.withdraw_own_proposals(&bob).unwrap();
    assert_eq!(bob_conversation.mls_group().pending_proposals().count(), 0);

    let output = bob_conversation.update_keys(&bob).unwrap();
    bob_conversation
        .process_commit_bundle(&bob, &accept(&output))
        .unwrap();
    alice_conversation
        .process_commit_bundle(&alice, &accept(&output))
        .unwrap();
    assert_eq!(alice_conversation.members().len(), 2);

    // those of others stay, for bob to commit
    bob_conversation.leave(&bob).unwrap();
    let proposal = alice_conversation.leave(&alice).unwrap();
    assert!(matches!(
        bob_conversation.process(&bob, &proposal).unwrap(),
        IncomingMessage::Proposal { .. }
    ));
    bob_conversation.withdraw_own_proposals(&bob).unwrap();
    let alice_leaf = alice_conversation.mls_group().own_leaf_index();
    let senders: Vec<_> = bob_conversation
        .mls_group()
        .pending_proposals()
        .map(|proposal| proposal.sender().clone())
        .collect();
    assert_eq!(senders, [openmls::prelude::Sender::Member(alice_leaf)]);

    let output = bob_conversation.commit_pending_proposals(&bob).unwrap();
    deliver((&mut bob_conversation, &bob), vec![], &output);
    match alice_conversation
        .process_commit_bundle(&alice, &accept(&output))
        .unwrap()
        .as_slice()
    {
        [IncomingMessage::Commit { self_removed, .. }] => assert!(*self_removed),
        _ => panic!("expected a Commit"),
    }
    assert_eq!(bob_conversation.members(), [bob.credential().clone()]);
}

#[test]
fn leaving_members() {
    let alice = client("alice");
    let bob = client("bob");
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);
    assert!(alice_conversation.leaving_members().is_empty());

    // bob's self_remove, but not alice's own
    let proposal = bob_conversation.leave(&bob).unwrap();
    alice_conversation.process(&alice, &proposal).unwrap();
    alice_conversation.leave(&alice).unwrap();
    assert_eq!(
        alice_conversation.leaving_members(),
        [bob.credential().clone()]
    );
    assert!(bob_conversation.leaving_members().is_empty());

    // no longer once committed
    alice_conversation.withdraw_own_proposals(&alice).unwrap();
    let output = alice_conversation.commit_pending_proposals(&alice).unwrap();
    deliver((&mut alice_conversation, &alice), vec![], &output);
    assert!(alice_conversation.leaving_members().is_empty());

    // a Remove of another is not a leave
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);
    let alice_leaf = alice_conversation.mls_group().own_leaf_index();
    let remove = bob_conversation
        .mls_group()
        .propose_remove_member(bob.provider(), bob.signer(), alice_leaf)
        .unwrap()
        .0
        .to_bytes()
        .unwrap();
    assert!(matches!(
        alice_conversation.process(&alice, &remove).unwrap(),
        IncomingMessage::Proposal { .. }
    ));
    assert!(alice_conversation.leaving_members().is_empty());
}

#[test]
fn a_leave_committed_with_the_other_clients_of_the_leaver() {
    let alice = client("alice");
    let bob = client("bob");
    let tablet = client("bob-tablet");
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);
    let key_package = tablet.generate_key_package(false).unwrap();
    let output = alice_conversation
        .add_members(&alice, &[&key_package])
        .unwrap();
    deliver(
        (&mut alice_conversation, &alice),
        vec![(&mut bob_conversation, &bob)],
        &output,
    );
    let bundle = accept(&output);
    let mut tablet_conversation = tablet
        .join_conversation(&bundle.welcome, &bundle.ratchet_tree)
        .unwrap();

    // bob leaves from his phone; his tablet is removed in the same Commit
    let proposal = bob_conversation.leave(&bob).unwrap();
    alice_conversation.process(&alice, &proposal).unwrap();
    tablet_conversation.process(&tablet, &proposal).unwrap();
    assert_eq!(
        alice_conversation.leaving_members(),
        [bob.credential().clone()]
    );
    let output = alice_conversation
        .remove_members(&alice, &[tablet.credential().clone()])
        .unwrap();
    deliver((&mut alice_conversation, &alice), vec![], &output);
    assert_eq!(alice_conversation.members(), [alice.credential().clone()]);
    for (conversation, client) in [
        (&mut bob_conversation, &bob),
        (&mut tablet_conversation, &tablet),
    ] {
        assert!(matches!(
            conversation
                .process_commit_bundle(client, &accept(&output))
                .unwrap()
                .as_slice(),
            [IncomingMessage::Commit {
                self_removed: true,
                ..
            }]
        ));
    }
}

#[test]
fn proposal_lists_apply_whole() {
    let alice = client("alice");
    let bob = client("bob");
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);
    let (_, mut other_conversation, _) = establish(&alice, &bob);

    // a Proposal of another group in the list voids all of it
    let proposal = bob_conversation.leave(&bob).unwrap();
    let other = other_conversation.leave(&bob).unwrap();
    let list = wire::encode_message_list(&[&proposal, &other]).unwrap();
    assert_eq!(
        alice_conversation.process_message_list(&alice, &list).err(),
        Some(ErrorKind::UnexpectedMessage)
    );
    assert_eq!(
        alice_conversation.mls_group().pending_proposals().count(),
        0
    );

    let list = wire::encode_message_list(&[&proposal]).unwrap();
    assert!(matches!(
        alice_conversation
            .process_message_list(&alice, &list)
            .unwrap()
            .as_slice(),
        [IncomingMessage::Proposal { .. }]
    ));
    assert_eq!(
        alice_conversation.mls_group().pending_proposals().count(),
        1
    );
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
    assert_eq!(decrypted.resent_failure, None);
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
    assert_eq!(decrypted.resent_failure, None);

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

    // a message that is not the one its HMAC is of is dropped, its sender not
    // told (Annex C.4.2); the others cannot tell
    let message = alice_conversation
        .encrypt_resent_mismatched(
            &alice,
            original,
            b"another",
            bob.credential(),
            b"msg-8",
            b"msg-1",
        )
        .unwrap();
    let decrypted = bob_conversation.decrypt(&bob, &message, b"msg-8").unwrap();
    assert_eq!(decrypted.sender.serialized_content(), b"alice");
    assert_eq!(decrypted.payload, None);
    assert_eq!(decrypted.original_message_id, b"msg-1");
    assert_eq!(decrypted.resent_failure, Some(ResentFailure::NotMatching));
    let decrypted = carol_conversation
        .decrypt(&carol, &message, b"msg-8")
        .unwrap();
    assert_eq!((decrypted.payload, decrypted.resent_failure), (None, None));

    // nor is one whose inner layer cannot be decrypted, which its sender is
    // told of (sections 10.2, 10.4)
    let era = alice_conversation.era().unwrap();
    let inner = wire::encode(&HpkeInnerEncapsulatedKeyAndCiphertext {
        receiver_leaf_index: bob_conversation.group.own_leaf_index().u32(),
        encapsulated_key: vec![1; 32].into(),
        ciphertext: vec![2; 48].into(),
        original_message_hmac: vec![3; 64].into(),
    })
    .unwrap();
    let message = alice_conversation
        .encrypt_secret_payload(
            &alice,
            SecretPayloadType::Hpke1To1Message,
            inner,
            &AuthenticatedData::new(
                b"msg-9",
                b"msg-1",
                era,
                VerifiableDerivedContent::ResentMessage(VerifiableResentMessage::new(b"msg-1")),
            ),
        )
        .unwrap();
    let decrypted = bob_conversation.decrypt(&bob, &message, b"msg-9").unwrap();
    assert_eq!(decrypted.sender.serialized_content(), b"alice");
    assert_eq!(decrypted.payload, None);
    assert_eq!(decrypted.original_message_id, b"msg-1");
    assert_eq!(decrypted.resent_failure, Some(ResentFailure::NotDecrypted));
    let decrypted = carol_conversation
        .decrypt(&carol, &message, b"msg-9")
        .unwrap();
    assert_eq!((decrypted.payload, decrypted.resent_failure), (None, None));

    // padded as files are
    let short = alice_conversation
        .encrypt_resent(&alice, &[b'a'; 2000], bob.credential(), b"msg-3", b"msg-1")
        .unwrap();
    let long = alice_conversation
        .encrypt_resent(&alice, &[b'a'; 2010], bob.credential(), b"msg-4", b"msg-1")
        .unwrap();
    assert_eq!(short.len(), long.len());

    // sealed to the leaf key Bob has at the time; once he replaced it, a message
    // re-sent before can no longer be read, which its sender is told of
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
    let decrypted = bob_conversation.decrypt(&bob, &message, b"msg-5").unwrap();
    assert_eq!(decrypted.sender.serialized_content(), b"carol");
    assert_eq!(decrypted.payload, None);
    assert_eq!(decrypted.resent_failure, Some(ResentFailure::NotDecrypted));

    // nor can one once the key pair of the leaf is no longer held
    bob.provider()
        .storage()
        .delete_encryption_epoch_key_pairs(
            bob_conversation.group.group_id(),
            &bob_conversation.group.epoch(),
            bob_conversation.group.own_leaf_index().u32(),
        )
        .unwrap();
    let message = carol_conversation
        .encrypt_resent(&carol, b"lost", bob.credential(), b"msg-10", b"msg-1")
        .unwrap();
    let decrypted = bob_conversation.decrypt(&bob, &message, b"msg-10").unwrap();
    assert_eq!(decrypted.payload, None);
    assert_eq!(decrypted.resent_failure, Some(ResentFailure::NotDecrypted));

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
fn negative_deliveries_of_clients() {
    use crate::imdn::notification::{Imdn, Notification, Status};

    // a failed delivery of the message, with the reason of the client
    // (RCC.16 sections 7.7.2.2, 7.7.2.3)
    for reason in [
        ClientFailureReason::FailureToDecrypt,
        ClientFailureReason::InnerResentMessageFailureToDecrypt,
    ] {
        let xml = imdn::negative_delivery("34jk324j", "2026-10-25T12:00:00.000Z", reason);
        assert_eq!(
            imdn::failure_reason(xml.as_bytes()),
            Some(imdn::FailureReason::Client(reason))
        );
        let notification = Imdn::from_xml(xml.as_bytes()).unwrap();
        assert_eq!(notification.message_id, "34jk324j");
        assert_eq!(notification.datetime, "2026-10-25T12:00:00.000Z");
        assert_eq!(notification.notification, Notification::Delivery);
        assert_eq!(notification.status, Status::Failed);
    }

    // with none, a failed delivery as any
    let xml = imdn::negative_delivery("1", "2026-10-25T12:00:00.000Z", ClientFailureReason::Unset);
    assert!(
        xml.contains("<delivery-notification><status><failed/></status></delivery-notification>")
    );
    assert_eq!(imdn::failure_reason(xml.as_bytes()), None);

    // the message ID escaped as any
    let xml = imdn::negative_delivery(
        "a<b",
        "2026-10-25T12:00:00.000Z",
        ClientFailureReason::FailureToDecrypt,
    );
    assert_eq!(Imdn::from_xml(xml.as_bytes()).unwrap().message_id, "a<b");
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
    let message: ClientMlsRcsMessage = proto::decode(&output.to_client_message().unwrap()).unwrap();
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

/// Types of the extensions of a GroupInfo for the Conversation Focus
fn group_info_extension_types(group_info: &[u8]) -> Vec<u16> {
    match MlsMessageIn::tls_deserialize_exact(group_info)
        .unwrap()
        .extract()
    {
        MlsMessageBodyIn::GroupInfo(group_info) => group_info
            .extensions()
            .iter()
            .map(|extension| u16::from(extension.extension_type()))
            .collect(),
        _ => panic!("expected a GroupInfo"),
    }
}

fn accepted(epoch: EpochIdentifier) -> Vec<u8> {
    proto::encode(&ServerMlsRcsMessage {
        payload: Some(server_mls_rcs_message::Payload::AcceptedMlsRcsMessage(
            AcceptedMlsRcsMessage {
                message_id: "cpim".to_string(),
                previous_epoch_identifier: Some(epoch),
            },
        )),
    })
}

/// Has the Conversation Focus accept a Commit of `committer` and deliver it to
/// the others; returns what each of the others got
fn deliver(
    committer: (&mut MlsConversation, &MlsClient),
    others: Vec<(&mut MlsConversation, &MlsClient)>,
    output: &CommitOutput,
) -> Vec<Vec<IncomingMessage>> {
    let (conversation, client) = committer;
    let before = conversation.epoch_identifier();
    conversation
        .process_server_message(client, &accepted(before))
        .unwrap();
    assert_eq!(
        conversation.epoch_authenticator(),
        output.epoch_authenticator
    );

    let bundle = accept(output);
    others
        .into_iter()
        .map(|(conversation, client)| {
            let events = conversation.process_commit_bundle(client, &bundle).unwrap();
            assert_eq!(
                conversation.epoch_authenticator(),
                output.epoch_authenticator
            );
            events
        })
        .collect()
}

#[test]
fn continuity_token() {
    let alice = client("alice");
    let bob = client("bob");
    let (alice_conversation, bob_conversation, group_info) = establish(&alice, &bob);
    let group_id = alice_conversation.group_id().to_vec();

    // made with the group, and sent along in the Welcome
    let token = alice.group_metadata(&group_id).unwrap().continuity_token;
    assert_eq!(token.len(), metadata::CONTINUITY_TOKEN_LENGTH);
    assert_eq!(
        bob.group_metadata(&group_id).unwrap().continuity_token,
        token
    );
    assert_eq!(
        bob_conversation
            .group_metadata(&bob)
            .unwrap()
            .continuity_token,
        token
    );

    // the GroupInfo for the Conversation Focus commits to it, at its epoch
    let epoch_authenticator = alice_conversation.epoch_authenticator().to_vec();
    for client in [&alice, &bob] {
        assert_eq!(
            client
                .continuity_token_matches(&group_info, &epoch_authenticator)
                .unwrap(),
            Some(true)
        );
        assert_eq!(
            client
                .continuity_token_matches(&group_info, b"another epoch")
                .unwrap(),
            Some(false)
        );
    }
    let carol = client("carol");
    assert_eq!(
        carol
            .continuity_token_matches(&group_info, &epoch_authenticator)
            .unwrap(),
        None
    );

    // kept for the next Era, unless renewed
    alice_conversation.delete(&alice).unwrap();
    let next_era = alice.create_conversation(Some(&group_id), 3).unwrap();
    assert_eq!(
        next_era.group_metadata(&alice).unwrap().continuity_token,
        token
    );
    let renewed = alice.renew_continuity_token(&group_id).unwrap();
    assert_ne!(renewed, token);
    assert_eq!(
        alice
            .continuity_token_matches(&group_info, &epoch_authenticator)
            .unwrap(),
        Some(false)
    );

    alice.forget_group_metadata(&group_id).unwrap();
    assert_eq!(
        alice.group_metadata(&group_id).unwrap(),
        proto::GroupMetadataKeys::default()
    );
}

#[test]
fn a_group_icon_encrypted_beforehand_is_committed_to() {
    let alice = client("alice");
    let bob = client("bob");
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);

    // encrypted, as it is to be uploaded before the Commit is made
    let icon = b"\x89PNG uploaded first";
    let encrypted = file::encrypt_file(icon, GROUP_ICON_FILE_NAME).unwrap();

    // a Commit not accepted, the same icon committed to again
    let output = alice_conversation
        .commit_group_icon(&alice, &encrypted.encryption_info, "image/png", b"msg-icon")
        .unwrap();
    assert!(output.private_message.is_some());
    alice_conversation.discard_pending_commit(&alice).unwrap();
    assert!(alice
        .group_metadata(alice_conversation.group_id())
        .unwrap()
        .group_subject_icon_keys
        .is_none());
    let output = alice_conversation
        .commit_group_icon(
            &alice,
            &encrypted.encryption_info,
            "image/png",
            b"msg-icon-2",
        )
        .unwrap();

    let events = deliver(
        (&mut alice_conversation, &alice),
        vec![(&mut bob_conversation, &bob)],
        &output,
    );
    assert!(matches!(
        events[0].as_slice(),
        [
            IncomingMessage::Commit { .. },
            IncomingMessage::GroupMetadataKeys {
                icon: true,
                subject: false,
                ..
            }
        ]
    ));
    for (conversation, client) in [(&alice_conversation, &alice), (&bob_conversation, &bob)] {
        assert!(conversation.group_metadata_in_sync(client).unwrap());
        let key = conversation
            .group_metadata(client)
            .unwrap()
            .group_subject_icon_keys
            .unwrap()
            .icon
            .unwrap();
        assert_eq!(key.file_name, GROUP_ICON_FILE_NAME);
        assert_eq!(key.content_type, "image/png");
        assert_eq!(
            key.encryption_info.as_ref(),
            Some(&encrypted.encryption_info)
        );
        assert_eq!(
            file::decrypt_file(
                &encrypted.ciphertext,
                GROUP_ICON_FILE_NAME,
                &key.encryption_info.unwrap()
            )
            .unwrap(),
            icon
        );
    }
}

#[test]
fn group_icon_and_subject() {
    let alice = client("alice");
    let bob = client("bob");
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);

    let icon = b"\x89PNG not really";
    let (output, encrypted) = alice_conversation
        .set_group_icon(&alice, icon, "image/png", b"msg-icon")
        .unwrap();
    assert!(output.private_message.is_some());

    // the GroupInfo of every Commit commits to the continuity token, at the new epoch
    assert_eq!(
        alice
            .continuity_token_matches(&output.group_info, &output.epoch_authenticator)
            .unwrap(),
        Some(true)
    );
    let message: ClientMlsRcsMessage = proto::decode(&output.to_client_message().unwrap()).unwrap();
    match message.payload {
        Some(client_mls_rcs_message::Payload::CommitBundle(bundle)) => {
            assert_eq!(Some(bundle.private_message), output.private_message)
        }
        _ => panic!("expected a CommitBundle"),
    }

    // the new key is only kept once the Commit is accepted
    assert!(alice
        .group_metadata(alice_conversation.group_id())
        .unwrap()
        .group_subject_icon_keys
        .is_none());

    let events = deliver(
        (&mut alice_conversation, &alice),
        vec![(&mut bob_conversation, &bob)],
        &output,
    );
    match events[0].as_slice() {
        [IncomingMessage::Commit { .. }, IncomingMessage::GroupMetadataKeys {
            sender,
            icon,
            subject,
            continuity_token_matches,
        }] => {
            assert_eq!(sender.serialized_content(), b"alice");
            assert!(*icon);
            assert!(!*subject);
            assert_eq!(*continuity_token_matches, None);
        }
        _ => panic!("expected a Commit with group metadata keys"),
    }

    for (conversation, client) in [(&alice_conversation, &alice), (&bob_conversation, &bob)] {
        assert!(conversation.group_metadata_in_sync(client).unwrap());
        let keys = conversation.group_metadata(client).unwrap();
        let key = keys.group_subject_icon_keys.unwrap().icon.unwrap();
        assert_eq!(key.file_name, GROUP_ICON_FILE_NAME);
        assert_eq!(key.content_type, "image/png");
        assert_eq!(
            file::decrypt_file(
                &encrypted.ciphertext,
                GROUP_ICON_FILE_NAME,
                &key.encryption_info.unwrap()
            )
            .unwrap(),
            icon
        );
    }

    // the key generation used for the keys is not used again
    let message = alice_conversation
        .encrypt_cpim(&alice, b"hi", b"msg-1", b"")
        .unwrap();
    match bob_conversation.process(&bob, &message).unwrap() {
        IncomingMessage::Application { data, .. } => {
            assert_eq!(
                wire::decode::<SecretPayload>(&data).unwrap().key_generation,
                1
            )
        }
        _ => panic!("expected an application message"),
    }

    // a subject from bob, delivered back to him as well
    let (output, encrypted) = bob_conversation
        .set_group_subject(&bob, "Holidays", b"msg-subject")
        .unwrap();
    let bundle = accept(&output);
    assert!(matches!(
        bob_conversation
            .process_commit_bundle(&bob, &bundle)
            .unwrap()
            .as_slice(),
        [IncomingMessage::Commit { .. }, IncomingMessage::Own]
    ));
    match alice_conversation
        .process_commit_bundle(&alice, &bundle)
        .unwrap()
        .as_slice()
    {
        [IncomingMessage::Commit { .. }, IncomingMessage::GroupMetadataKeys { icon, subject, .. }] =>
        {
            assert!(!*icon);
            assert!(*subject);
        }
        _ => panic!("expected a Commit with group metadata keys"),
    }
    let keys = alice_conversation.group_metadata(&alice).unwrap();
    let keys = keys.group_subject_icon_keys.unwrap();
    assert!(keys.icon.is_some());
    let subject = keys.subject.unwrap();
    assert_eq!(subject.content_type, metadata::SUBJECT_CONTENT_TYPE);
    assert_eq!(
        file::decrypt_file(
            &encrypted.ciphertext,
            GROUP_SUBJECT_FILE_NAME,
            &subject.encryption_info.unwrap()
        )
        .unwrap(),
        b"Holidays"
    );

    // deleting the icon drops its key everywhere
    let output = bob_conversation.delete_group_icon(&bob).unwrap();
    assert!(output.private_message.is_none());
    deliver(
        (&mut bob_conversation, &bob),
        vec![(&mut alice_conversation, &alice)],
        &output,
    );
    for (conversation, client) in [(&alice_conversation, &alice), (&bob_conversation, &bob)] {
        let keys = conversation.group_metadata(client).unwrap();
        let keys = keys.group_subject_icon_keys.unwrap();
        assert!(keys.icon.is_none());
        assert!(keys.subject.is_some());
        assert!(conversation.group_metadata_in_sync(client).unwrap());
    }
    assert_eq!(
        alice_conversation.delete_group_icon(&alice).err(),
        Some(ErrorKind::InvalidState)
    );
}

#[test]
fn group_metadata_keys_for_others() {
    let alice = client("alice");
    let bob = client("bob");
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);
    let group_id = alice_conversation.group_id().to_vec();

    let (output, _) = alice_conversation
        .set_group_icon(&alice, b"icon", "image/png", b"msg-icon")
        .unwrap();
    deliver(
        (&mut alice_conversation, &alice),
        vec![(&mut bob_conversation, &bob)],
        &output,
    );

    // a new member gets the keys and the token with the Welcome
    let carol = client("carol");
    let key_package = carol.generate_key_package(false).unwrap();
    let output = alice_conversation
        .add_members(&alice, &[&key_package])
        .unwrap();
    deliver(
        (&mut alice_conversation, &alice),
        vec![(&mut bob_conversation, &bob)],
        &output,
    );
    let mut carol_conversation = carol
        .join_conversation(
            output.welcome.as_ref().unwrap(),
            output.ratchet_tree.as_ref().unwrap(),
        )
        .unwrap();
    assert!(carol_conversation.group_metadata_in_sync(&carol).unwrap());

    // which never go in the GroupInfo for the Conversation Focus
    let extension_types = group_info_extension_types(&output.group_info);
    assert!(extension_types.contains(&EXTENSION_CONTINUITY_TOKEN_COMMITMENT));
    for secret in [
        EXTENSION_ICON_KEY,
        EXTENSION_SUBJECT_KEY,
        EXTENSION_CONTINUITY_TOKEN,
    ] {
        assert!(!extension_types.contains(&secret));
    }
    assert_eq!(
        carol.group_metadata(&group_id).unwrap(),
        alice.group_metadata(&group_id).unwrap()
    );

    // carol loses them, and asks for them
    carol.forget_group_metadata(&group_id).unwrap();
    assert!(!carol_conversation.group_metadata_in_sync(&carol).unwrap());
    assert_eq!(
        alice_conversation
            .send_group_metadata_keys(&alice, b"msg-keys")
            .err(),
        Some(ErrorKind::InvalidState)
    );

    let output = carol_conversation
        .request_group_metadata_keys(&carol)
        .unwrap();
    assert!(output.private_message.is_none());
    deliver(
        (&mut carol_conversation, &carol),
        vec![
            (&mut alice_conversation, &alice),
            (&mut bob_conversation, &bob),
        ],
        &output,
    );
    assert!(alice_conversation.group_metadata_keys_requested());
    assert_eq!(
        carol_conversation.request_group_metadata_keys(&carol).err(),
        Some(ErrorKind::InvalidState)
    );

    // bob answers
    let output = bob_conversation
        .send_group_metadata_keys(&bob, b"msg-keys")
        .unwrap();
    assert!(output.private_message.is_some());
    let events = deliver(
        (&mut bob_conversation, &bob),
        vec![
            (&mut carol_conversation, &carol),
            (&mut alice_conversation, &alice),
        ],
        &output,
    );
    match events[0].as_slice() {
        [IncomingMessage::Commit { .. }, IncomingMessage::GroupMetadataKeys {
            icon,
            continuity_token_matches,
            ..
        }] => {
            assert!(*icon);
            // carol had none left, and keeps it
            assert_eq!(*continuity_token_matches, Some(true));
        }
        _ => panic!("expected a Commit with group metadata keys"),
    }
    assert!(carol_conversation.group_metadata_in_sync(&carol).unwrap());
    assert_eq!(
        carol.group_metadata(&group_id).unwrap(),
        alice.group_metadata(&group_id).unwrap()
    );
    for conversation in [&alice_conversation, &bob_conversation, &carol_conversation] {
        assert!(!conversation.group_metadata_keys_requested());
    }

    // a continuity token that differs is reported, and the one kept stays
    let renewed = alice.renew_continuity_token(&group_id).unwrap();
    let output = carol_conversation
        .request_group_metadata_keys(&carol)
        .unwrap();
    deliver(
        (&mut carol_conversation, &carol),
        vec![
            (&mut alice_conversation, &alice),
            (&mut bob_conversation, &bob),
        ],
        &output,
    );
    let output = bob_conversation
        .send_group_metadata_keys(&bob, b"msg-keys-2")
        .unwrap();
    let events = deliver(
        (&mut bob_conversation, &bob),
        vec![(&mut alice_conversation, &alice)],
        &output,
    );
    match events[0].as_slice() {
        [IncomingMessage::Commit { .. }, IncomingMessage::GroupMetadataKeys {
            continuity_token_matches,
            ..
        }] => assert_eq!(*continuity_token_matches, Some(false)),
        _ => panic!("expected a Commit with group metadata keys"),
    }
    assert_eq!(
        alice.group_metadata(&group_id).unwrap().continuity_token,
        renewed
    );
}

#[test]
fn group_metadata_in_new_era() {
    let alice = client("alice");
    let bob = client("bob");
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);
    let group_id = alice_conversation.group_id().to_vec();

    let (output, _) = alice_conversation
        .set_group_subject(&alice, "Team", b"msg-subject")
        .unwrap();
    deliver(
        (&mut alice_conversation, &alice),
        vec![(&mut bob_conversation, &bob)],
        &output,
    );

    // the next Era commits to the subject kept, and sends its key along
    alice_conversation.delete(&alice).unwrap();
    bob_conversation.delete(&bob).unwrap();
    let mut alice_conversation = alice.create_conversation(Some(&group_id), 3).unwrap();
    assert!(alice_conversation.group_metadata_in_sync(&alice).unwrap());

    bob.forget_group_metadata(&group_id).unwrap();
    let key_package = bob.generate_key_package(false).unwrap();
    let output = alice_conversation
        .add_members(&alice, &[&key_package])
        .unwrap();
    let bob_conversation = bob
        .join_conversation(
            output.welcome.as_ref().unwrap(),
            output.ratchet_tree.as_ref().unwrap(),
        )
        .unwrap();
    assert_eq!(bob_conversation.era(), Some(3));
    assert!(bob_conversation.group_metadata_in_sync(&bob).unwrap());
    assert_eq!(
        bob.group_metadata(&group_id).unwrap(),
        alice.group_metadata(&group_id).unwrap()
    );
}

#[test]
fn commit_bundles_apply_whole() {
    let alice = client("alice");
    let bob = client("bob");
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);

    let (output, _) = alice_conversation
        .set_group_icon(&alice, b"icon", "image/png", b"msg-icon")
        .unwrap();

    // a private message that cannot be read voids the Commit with it
    let mut bundle = accept(&output);
    let mut broken = output.private_message.clone().unwrap();
    let last = broken.len() - 1;
    broken[last] ^= 1;
    bundle.private_message = broken;
    let epoch = bob_conversation.epoch_identifier();
    assert!(bob_conversation
        .process_commit_bundle(&bob, &bundle)
        .is_err());
    assert_eq!(bob_conversation.epoch_identifier(), epoch);
    assert!(bob
        .group_metadata(bob_conversation.group_id())
        .unwrap()
        .group_subject_icon_keys
        .is_none());

    deliver(
        (&mut alice_conversation, &alice),
        vec![(&mut bob_conversation, &bob)],
        &output,
    );
    assert!(bob_conversation.group_metadata_in_sync(&bob).unwrap());

    // a Commit discarded leaves the keys as they were
    let keys = alice_conversation.group_metadata(&alice).unwrap();
    alice_conversation
        .set_group_icon(&alice, b"other icon", "image/png", b"msg-icon-2")
        .unwrap();
    alice_conversation.discard_pending_commit(&alice).unwrap();
    assert_eq!(alice_conversation.group_metadata(&alice).unwrap(), keys);
    assert!(alice_conversation.group_metadata_in_sync(&alice).unwrap());

    // and so does a Commit of another member coming first
    alice_conversation
        .set_group_icon(&alice, b"other icon", "image/png", b"msg-icon-3")
        .unwrap();
    let output = bob_conversation.update_keys(&bob).unwrap();
    deliver(
        (&mut bob_conversation, &bob),
        vec![(&mut alice_conversation, &alice)],
        &output,
    );
    assert!(!alice_conversation.has_pending_commit());
    assert_eq!(alice_conversation.group_metadata(&alice).unwrap(), keys);
    let message = alice_conversation
        .encrypt_cpim(&alice, b"hi", b"msg-1", b"")
        .unwrap();
    assert!(bob_conversation.decrypt(&bob, &message, b"msg-1").is_ok());
}

fn control_messages(rcs_message_id: &str, output: &CommitOutput) -> EpochControlMessages {
    EpochControlMessages {
        rcs_message_id: rcs_message_id.to_string(),
        server_mls_rcs_message: Some(ServerMlsRcsMessage {
            payload: Some(server_mls_rcs_message::Payload::ServerCommitBundle(accept(
                output,
            ))),
        }),
    }
}

#[test]
fn enhanced_self_heal() {
    let alice = client("alice");
    let bob = client("bob");
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);

    // bob misses three Commits
    let request = bob_conversation.enhanced_group_info_request();
    assert_eq!(
        proto::decode::<EpochIdentifier>(&request).unwrap(),
        bob_conversation.epoch_identifier()
    );

    let mut outputs = Vec::new();
    let mut epochs = Vec::new();
    for i in 0..3 {
        let output = if i == 2 {
            alice_conversation
                .set_group_subject(&alice, "Missed", b"msg-subject")
                .unwrap()
                .0
        } else {
            alice_conversation.update_keys(&alice).unwrap()
        };
        deliver((&mut alice_conversation, &alice), vec![], &output);
        epochs.push(alice_conversation.epoch_identifier());
        outputs.push(output);
    }
    let group_info = MlsGroupInfo {
        group_info: outputs[2].group_info.clone(),
        ratchet_tree: alice_conversation.ratchet_tree().unwrap(),
        pending_proposals: Vec::new(),
    };

    // first page
    let page = MlsEnhancedGroupInfo {
        latest_epoch_identifier: Some(epochs[2].clone()),
        mls_group_info: Some(group_info.clone()),
        committed_control_messages: vec![
            control_messages("cpim-1", &outputs[0]),
            control_messages("cpim-2", &outputs[1]),
        ],
        paginated_epoch_identifier: Some(epochs[1].clone()),
    };
    let healed = bob_conversation
        .process_enhanced_group_info(&bob, &proto::encode(&page))
        .unwrap();
    assert_eq!(healed.progress, SelfHealProgress::NextPage);
    assert_eq!(healed.latest_epoch, epochs[2]);
    assert_eq!(healed.applied.len(), 2);
    assert_eq!(healed.applied[0].0, "cpim-1");
    assert!(matches!(
        healed.applied[1].1.as_slice(),
        [IncomingMessage::Commit { .. }]
    ));
    assert_eq!(bob_conversation.epoch_identifier(), epochs[1]);

    // second page, repeating a message bob already applied
    let page = MlsEnhancedGroupInfo {
        latest_epoch_identifier: Some(epochs[2].clone()),
        mls_group_info: Some(group_info.clone()),
        committed_control_messages: vec![
            control_messages("cpim-2", &outputs[1]),
            control_messages("cpim-3", &outputs[2]),
        ],
        paginated_epoch_identifier: Some(epochs[2].clone()),
    };
    let healed = bob_conversation
        .process_enhanced_group_info(&bob, &proto::encode(&page))
        .unwrap();
    assert_eq!(healed.progress, SelfHealProgress::UpToDate);
    assert!(matches!(
        healed.applied[0].1.as_slice(),
        [IncomingMessage::Duplicate]
    ));
    assert!(matches!(
        healed.applied[1].1.as_slice(),
        [
            IncomingMessage::Commit { .. },
            IncomingMessage::GroupMetadataKeys { subject: true, .. }
        ]
    ));
    assert!(bob_conversation.group_metadata_in_sync(&bob).unwrap());

    // the Commits applied that way, delivered late over MSRP
    for output in &outputs {
        assert!(matches!(
            bob_conversation
                .process_commit_bundle(&bob, &accept(output))
                .unwrap()
                .as_slice(),
            [IncomingMessage::Duplicate]
        ));
    }

    // nothing left to catch up on
    let page = MlsEnhancedGroupInfo {
        latest_epoch_identifier: Some(epochs[2].clone()),
        mls_group_info: Some(group_info),
        committed_control_messages: Vec::new(),
        paginated_epoch_identifier: None,
    };
    let healed = bob_conversation
        .process_enhanced_group_info(&bob, &proto::encode(&page))
        .unwrap();
    assert_eq!(healed.progress, SelfHealProgress::UpToDate);
    assert!(healed.applied.is_empty());

    let message = alice_conversation
        .encrypt_cpim(&alice, b"caught up", b"msg-1", b"")
        .unwrap();
    assert_eq!(
        bob_conversation
            .decrypt(&bob, &message, b"msg-1")
            .unwrap()
            .payload
            .as_deref(),
        Some(&b"caught up"[..])
    );
}

#[test]
fn enhanced_self_heal_falls_back() {
    let alice = client("alice");
    let bob = client("bob");
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);

    let first = alice_conversation.update_keys(&alice).unwrap();
    deliver((&mut alice_conversation, &alice), vec![], &first);
    let second = alice_conversation.update_keys(&alice).unwrap();
    deliver((&mut alice_conversation, &alice), vec![], &second);
    let group_info = MlsGroupInfo {
        group_info: second.group_info.clone(),
        ratchet_tree: alice_conversation.ratchet_tree().unwrap(),
        pending_proposals: Vec::new(),
    };
    let latest = alice_conversation.epoch_identifier();

    // the Conversation Focus does not offer the control messages
    let page = MlsEnhancedGroupInfo {
        latest_epoch_identifier: Some(latest.clone()),
        mls_group_info: Some(group_info.clone()),
        committed_control_messages: Vec::new(),
        paginated_epoch_identifier: None,
    };
    let healed = bob_conversation
        .process_enhanced_group_info(&bob, &proto::encode(&page))
        .unwrap();
    assert_eq!(
        healed.progress,
        SelfHealProgress::Rejoin(group_info.clone())
    );
    // the epoch of the GroupInfo, whose continuity token commitment is made
    // at its epoch authenticator (RCC.16 section 10.5.1)
    assert_eq!(healed.latest_epoch, latest);
    assert_eq!(
        bob.continuity_token_matches(
            &group_info.group_info,
            &healed.latest_epoch.epoch_authenticator
        )
        .unwrap(),
        Some(true)
    );
    let previous = bob_conversation.epoch_authenticator().to_vec();
    assert_eq!(
        bob.continuity_token_matches(&group_info.group_info, &previous)
            .unwrap(),
        Some(false)
    );

    // one of them fails: the ones before stay applied
    let mut broken = control_messages("cpim-2", &second);
    if let Some(ServerMlsRcsMessage {
        payload: Some(server_mls_rcs_message::Payload::ServerCommitBundle(bundle)),
    }) = &mut broken.server_mls_rcs_message
    {
        let last = bundle.commit_list.len() - 1;
        bundle.commit_list[last] ^= 1;
    }
    let page = MlsEnhancedGroupInfo {
        latest_epoch_identifier: Some(latest.clone()),
        mls_group_info: Some(group_info.clone()),
        committed_control_messages: vec![control_messages("cpim-1", &first), broken],
        paginated_epoch_identifier: Some(latest),
    };
    let healed = bob_conversation
        .process_enhanced_group_info(&bob, &proto::encode(&page))
        .unwrap();
    assert_eq!(
        healed.progress,
        SelfHealProgress::Rejoin(group_info.clone())
    );
    assert_eq!(healed.latest_epoch, alice_conversation.epoch_identifier());
    assert_eq!(healed.applied.len(), 1);
    assert_eq!(bob_conversation.epoch(), 2);

    // which the External Commit takes care of
    bob_conversation.delete(&bob).unwrap();
    let (mut bob_conversation, output) = bob.rejoin_conversation(&group_info).unwrap();
    alice_conversation
        .process_commit_bundle(&alice, &accept(&output))
        .unwrap();
    assert_eq!(
        bob_conversation.epoch_authenticator(),
        alice_conversation.epoch_authenticator()
    );
    let message = bob_conversation
        .encrypt_cpim(&bob, b"back", b"msg-1", b"")
        .unwrap();
    assert!(alice_conversation
        .decrypt(&alice, &message, b"msg-1")
        .is_ok());
}

#[test]
fn repeated_proposals() {
    let alice = client("alice");
    let bob = client("bob");
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);

    let proposal = bob_conversation.leave(&bob).unwrap();
    assert!(matches!(
        alice_conversation.process(&alice, &proposal).unwrap(),
        IncomingMessage::Proposal { .. }
    ));
    assert!(matches!(
        alice_conversation.process(&alice, &proposal).unwrap(),
        IncomingMessage::Duplicate
    ));

    let output = alice_conversation.commit_pending_proposals(&alice).unwrap();
    deliver((&mut alice_conversation, &alice), vec![], &output);
    assert_eq!(alice_conversation.members().len(), 1);

    // once committed, it belongs to a past epoch
    assert!(matches!(
        alice_conversation.process(&alice, &proposal).unwrap(),
        IncomingMessage::Duplicate
    ));
}

#[test]
fn self_remove() {
    let alice = client("alice");
    let bob = client("bob");
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);

    // a self_remove Proposal, under the type RCC.16 gives it
    let proposal = bob_conversation.leave(&bob).unwrap();
    assert!(proposal.windows(3).any(|w| w == [2, 0xF0, 0x03]));
    assert!(matches!(
        alice_conversation.process(&alice, &proposal).unwrap(),
        IncomingMessage::Proposal { .. }
    ));
    let pending: Vec<u16> = alice_conversation
        .mls_group()
        .pending_proposals()
        .map(|p| u16::from(p.proposal().proposal_type()))
        .collect();
    assert_eq!(pending, [PROPOSAL_SELF_REMOVE]);

    // bob, being removed, does not reach the new epoch
    let output = alice_conversation.commit_pending_proposals(&alice).unwrap();
    deliver((&mut alice_conversation, &alice), vec![], &output);
    match bob_conversation
        .process_commit_bundle(&bob, &accept(&output))
        .unwrap()
        .as_slice()
    {
        [IncomingMessage::Commit {
            removed,
            self_removed,
            ..
        }] => {
            assert_eq!(removed.len(), 1);
            assert_eq!(removed[0].serialized_content(), b"bob");
            assert!(*self_removed);
        }
        _ => panic!("expected a Commit"),
    }
    assert!(!bob_conversation.is_active());
    assert_eq!(alice_conversation.members().len(), 1);
}

#[test]
fn self_remove_in_external_commit() {
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
    let bob_conversation = bob
        .join_conversation(&bundle.welcome, &bundle.ratchet_tree)
        .unwrap();
    let mut carol_conversation = carol
        .join_conversation(&bundle.welcome, &bundle.ratchet_tree)
        .unwrap();
    alice_conversation
        .process_commit_bundle(&alice, &bundle)
        .unwrap();

    // carol leaves, while bob has lost the group
    let proposal = carol_conversation.leave(&carol).unwrap();
    alice_conversation.process(&alice, &proposal).unwrap();
    bob_conversation.delete(&bob).unwrap();

    // the External Commit of bob covers the pending Proposal
    let (mut bob_conversation, output) = bob
        .rejoin_conversation(&MlsGroupInfo {
            group_info: output.group_info.clone(),
            ratchet_tree: alice_conversation.ratchet_tree().unwrap(),
            pending_proposals: wire::encode_message_list(&[&proposal]).unwrap(),
        })
        .unwrap();
    let bundle = accept(&output);
    match alice_conversation
        .process_commit_bundle(&alice, &bundle)
        .unwrap()
        .as_slice()
    {
        [IncomingMessage::Commit { removed, .. }] => {
            let mut removed: Vec<&[u8]> = removed.iter().map(|c| c.serialized_content()).collect();
            removed.sort();
            assert_eq!(removed, [&b"bob"[..], b"carol"]);
        }
        _ => panic!("expected a Commit"),
    }
    match carol_conversation
        .process_commit_bundle(&carol, &bundle)
        .unwrap()
        .as_slice()
    {
        [IncomingMessage::Commit { self_removed, .. }] => assert!(*self_removed),
        _ => panic!("expected a Commit"),
    }

    assert_eq!(alice_conversation.members().len(), 2);
    assert_eq!(
        bob_conversation.epoch_authenticator(),
        alice_conversation.epoch_authenticator()
    );
    let message = bob_conversation
        .encrypt_cpim(&bob, b"back", b"msg-1", b"")
        .unwrap();
    assert!(alice_conversation
        .decrypt(&alice, &message, b"msg-1")
        .is_ok());
}

/// server_remove Proposals in a Commit: ProposalOrRef of type proposal, then
/// the type 0xF004 and a leaf index
fn server_removes(commit: &[u8]) -> usize {
    commit
        .windows(6)
        .filter(|w| w[..5] == [1, 0xF0, 0x04, 0, 0])
        .count()
}

#[test]
fn server_remove() {
    let alice = client("alice");
    let bob_phone = client("bob");
    let bob_tablet = client("bob");
    let carol = client("carol");

    let key_packages = [
        bob_phone.generate_key_package(false).unwrap(),
        bob_tablet.generate_key_package(false).unwrap(),
        carol.generate_key_package(false).unwrap(),
    ];
    let mut alice_conversation = alice.create_conversation(None, 2).unwrap();
    let output = alice_conversation
        .add_members(
            &alice,
            &[&key_packages[0], &key_packages[1], &key_packages[2]],
        )
        .unwrap();
    let bundle = accept(&output);
    let mut bob_conversation = bob_phone
        .join_conversation(&bundle.welcome, &bundle.ratchet_tree)
        .unwrap();
    let mut carol_conversation = carol
        .join_conversation(&bundle.welcome, &bundle.ratchet_tree)
        .unwrap();
    alice_conversation
        .process_commit_bundle(&alice, &bundle)
        .unwrap();
    assert_eq!(alice_conversation.members().len(), 4);

    // bob lost RCS: carol removes both his Clients, as the server asked
    let output = carol_conversation
        .remove_members_for_server(&carol, &[bob_phone.credential().clone()])
        .unwrap();
    assert_eq!(server_removes(&output.commit), 2);
    deliver((&mut carol_conversation, &carol), vec![], &output);

    match alice_conversation
        .process_commit_bundle(&alice, &accept(&output))
        .unwrap()
        .as_slice()
    {
        [IncomingMessage::Commit { removed, .. }] => {
            assert_eq!(removed.len(), 2);
            assert!(removed.iter().all(|c| c.serialized_content() == b"bob"));
        }
        _ => panic!("expected a Commit"),
    }
    assert_eq!(
        alice_conversation.epoch_authenticator(),
        carol_conversation.epoch_authenticator()
    );
    assert_eq!(alice_conversation.members().len(), 2);

    match bob_conversation
        .process_commit_bundle(&bob_phone, &accept(&output))
        .unwrap()
        .as_slice()
    {
        [IncomingMessage::Commit { self_removed, .. }] => assert!(*self_removed),
        _ => panic!("expected a Commit"),
    }
    assert!(!bob_conversation.is_active());

    assert_eq!(
        carol_conversation
            .remove_members_for_server(&carol, &[bob_phone.credential().clone()])
            .err(),
        Some(ErrorKind::UnknownMember)
    );
}

#[test]
fn self_heal_replacing_clients() {
    let alice = client("alice");
    let old_phone = client("bob-1");
    let old_tablet = client("bob-2");

    let key_packages = [
        old_phone.generate_key_package(false).unwrap(),
        old_tablet.generate_key_package(false).unwrap(),
    ];
    let mut alice_conversation = alice.create_conversation(None, 2).unwrap();
    let output = alice_conversation
        .add_members(&alice, &[&key_packages[0], &key_packages[1]])
        .unwrap();
    deliver((&mut alice_conversation, &alice), vec![], &output);

    // bob comes back with a new Client, under a new key: his old Clients go,
    // one with a Remove and the other with a server_remove
    let new_phone = client("bob-3");
    let (mut bob_conversation, output) = new_phone
        .rejoin_conversation_replacing(
            &MlsGroupInfo {
                group_info: output.group_info.clone(),
                ratchet_tree: alice_conversation.ratchet_tree().unwrap(),
                pending_proposals: Vec::new(),
            },
            &[
                old_phone.credential().clone(),
                old_tablet.credential().clone(),
            ],
        )
        .unwrap();
    assert_eq!(server_removes(&output.commit), 1);
    assert_eq!(
        output
            .commit
            .windows(6)
            .filter(|w| w[..5] == [1, 0x00, 0x03, 0, 0])
            .count(),
        1
    );

    match alice_conversation
        .process_commit_bundle(&alice, &accept(&output))
        .unwrap()
        .as_slice()
    {
        [IncomingMessage::Commit {
            sender, removed, ..
        }] => {
            assert_eq!(sender.serialized_content(), b"bob-3");
            let mut removed: Vec<&[u8]> = removed.iter().map(|c| c.serialized_content()).collect();
            removed.sort();
            assert_eq!(removed, [&b"bob-1"[..], b"bob-2"]);
        }
        _ => panic!("expected a Commit"),
    }

    let members: Vec<Vec<u8>> = alice_conversation
        .members()
        .iter()
        .map(|c| c.serialized_content().to_vec())
        .collect();
    assert_eq!(members.len(), 2);
    assert!(members.contains(&b"bob-3".to_vec()));
    assert_eq!(
        bob_conversation.epoch_authenticator(),
        alice_conversation.epoch_authenticator()
    );
    let message = bob_conversation
        .encrypt_cpim(&new_phone, b"new phone", b"msg-1", b"")
        .unwrap();
    assert!(alice_conversation
        .decrypt(&alice, &message, b"msg-1")
        .is_ok());
}

/// Lets a Client only replace Clients of the same Participant, named before the
/// dash of their identity
struct SameParticipant;

impl CredentialValidator for SameParticipant {
    fn validate(&self, _credential: &Credential, _signature_key: &[u8]) -> bool {
        true
    }

    fn validate_replacement(&self, old: &Credential, new: &Credential, _key: &[u8]) -> bool {
        let participant = |credential: &Credential| {
            credential
                .serialized_content()
                .split(|b| *b == b'-')
                .next()
                .map(|p| p.to_vec())
        };
        participant(old) == participant(new)
    }
}

#[test]
fn external_commit_removals_are_validated() {
    let alice = MlsClient::new(
        b"alice",
        CIPHERSUITE,
        MlsConfig::default(),
        Box::new(SameParticipant),
    )
    .unwrap();
    let old_phone = client("bob-1");
    let old_tablet = client("bob-2");

    let key_packages = [
        old_phone.generate_key_package(false).unwrap(),
        old_tablet.generate_key_package(false).unwrap(),
    ];
    let mut alice_conversation = alice.create_conversation(None, 2).unwrap();
    let output = alice_conversation
        .add_members(&alice, &[&key_packages[0], &key_packages[1]])
        .unwrap();
    deliver((&mut alice_conversation, &alice), vec![], &output);
    let group_info = MlsGroupInfo {
        group_info: output.group_info.clone(),
        ratchet_tree: alice_conversation.ratchet_tree().unwrap(),
        pending_proposals: Vec::new(),
    };
    let replaced = [
        old_phone.credential().clone(),
        old_tablet.credential().clone(),
    ];

    // another Participant may not take bob's Clients out
    let mallory = client("mallory-1");
    let (_, output) = mallory
        .rejoin_conversation_replacing(&group_info, &replaced)
        .unwrap();
    let epoch = alice_conversation.epoch_identifier();
    assert_eq!(
        alice_conversation
            .process_commit_bundle(&alice, &accept(&output))
            .err(),
        Some(ErrorKind::InvalidCredential)
    );
    assert_eq!(alice_conversation.epoch_identifier(), epoch);

    // bob may
    let new_phone = client("bob-3");
    let (_, output) = new_phone
        .rejoin_conversation_replacing(&group_info, &replaced)
        .unwrap();
    assert!(alice_conversation
        .process_commit_bundle(&alice, &accept(&output))
        .is_ok());
    assert_eq!(alice_conversation.members().len(), 2);
}

/// A key update of `client` in `conversation`, applied by it and by the
/// others in `members` as the Conversation Focus forwards it
fn key_update(
    client: &MlsClient,
    conversation: &mut MlsConversation,
    members: &mut [(&MlsClient, &mut MlsConversation)],
) {
    let bundle = accept(&conversation.update_keys(client).unwrap());
    conversation.process_commit_bundle(client, &bundle).unwrap();
    for (member, member_conversation) in members {
        member_conversation
            .process_commit_bundle(member, &bundle)
            .unwrap();
    }
}

fn send(client: &MlsClient, conversation: &mut MlsConversation, count: u32) {
    for _ in 0..count {
        conversation
            .encrypt_cpim(client, b"hi", b"msg", b"")
            .unwrap();
    }
}

/// The time the clients of a test tell, which it moves on
#[derive(Clone)]
struct TestClock(std::sync::Arc<std::sync::Mutex<std::time::SystemTime>>);

impl TestClock {
    fn new() -> TestClock {
        TestClock(std::sync::Arc::new(std::sync::Mutex::new(
            std::time::SystemTime::now(),
        )))
    }

    fn now(&self) -> std::time::SystemTime {
        *self.0.lock().unwrap()
    }

    fn set(&self, time: std::time::SystemTime) {
        *self.0.lock().unwrap() = time;
    }

    /// Has `client` tell this time
    fn keep(&self, client: &mut MlsClient) {
        let clock = self.clone();
        client.set_clock(std::sync::Arc::new(move || clock.now()));
    }
}

fn timed_client(identity: &str, clock: &TestClock) -> MlsClient {
    let mut client = client(identity);
    clock.keep(&mut client);
    client
}

const DAY: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);
const MINUTE: std::time::Duration = std::time::Duration::from_secs(60);

#[test]
fn key_updates_by_days_and_messages() {
    use std::time::Duration;

    let clock = TestClock::new();
    let start = clock.now();
    let alice = timed_client("alice", &clock);
    let bob = timed_client("bob", &clock);
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);
    let due = |conversation: &MlsConversation, client: &MlsClient, after: Duration| {
        clock.set(start + after);
        conversation.key_update_due(client).unwrap()
    };

    // after 30 days at most, not before 7 (RCC.16 section 9.5.2)
    for (conversation, client) in [(&alice_conversation, &alice), (&bob_conversation, &bob)] {
        assert!(!due(conversation, client, Duration::ZERO));
        assert!(!due(conversation, client, 30 * DAY - MINUTE));
        assert!(due(conversation, client, 30 * DAY + MINUTE));
    }
    // or after 50 messages
    send(&bob, &mut bob_conversation, 49);
    assert!(!due(&bob_conversation, &bob, 8 * DAY));
    send(&bob, &mut bob_conversation, 1);
    assert!(due(&bob_conversation, &bob, 7 * DAY + MINUTE));
    assert!(!due(&bob_conversation, &bob, 7 * DAY - MINUTE));
    // the count kept with the rest of the client
    let mut restored = MlsClient::restore(
        &bob.snapshot().unwrap(),
        MlsConfig::default(),
        Box::new(AllowAll),
    )
    .unwrap();
    clock.keep(&mut restored);
    let restored_conversation = restored
        .load_conversation(bob_conversation.group_id())
        .unwrap();
    assert!(due(&restored_conversation, &restored, 7 * DAY + MINUTE));

    // the Commits of others leave it as it is
    clock.set(start);
    key_update(
        &alice,
        &mut alice_conversation,
        &mut [(&bob, &mut bob_conversation)],
    );
    assert!(due(&bob_conversation, &bob, 7 * DAY + MINUTE));
    // as do those of this client without UpdatePath
    send(&alice, &mut alice_conversation, 50);
    let carol = client("carol");
    let key_package = carol.generate_key_package(false).unwrap();
    clock.set(start + DAY);
    let bundle = accept(
        &alice_conversation
            .add_members(&alice, &[&key_package])
            .unwrap(),
    );
    assert!(alice_conversation
        .mls_group()
        .pending_commit()
        .is_some_and(|commit| commit.update_path_leaf_node().is_none()));
    alice_conversation
        .process_commit_bundle(&alice, &bundle)
        .unwrap();
    bob_conversation
        .process_commit_bundle(&bob, &bundle)
        .unwrap();
    assert!(due(&alice_conversation, &alice, 7 * DAY + MINUTE));

    // a key update starts over, from when it is applied
    clock.set(start + 10 * DAY);
    key_update(
        &bob,
        &mut bob_conversation,
        &mut [(&alice, &mut alice_conversation)],
    );
    assert!(!due(&bob_conversation, &bob, 40 * DAY - MINUTE));
    assert!(due(&bob_conversation, &bob, 40 * DAY + MINUTE));
    send(&bob, &mut bob_conversation, 49);
    assert!(!due(&bob_conversation, &bob, 18 * DAY));
}

#[test]
fn key_updates_wanted_at_once() {
    let clock = TestClock::new();
    let start = clock.now();
    let alice = timed_client("alice", &clock);
    let bob = timed_client("bob", &clock);
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);
    assert!(!alice_conversation.key_update_due(&alice).unwrap());

    // as after a message re-sent (RCC.16 section 10.3), until there is one
    alice_conversation.want_key_update(&alice).unwrap();
    assert!(alice_conversation.key_update_due(&alice).unwrap());
    assert!(!bob_conversation.key_update_due(&bob).unwrap());
    // kept with the rest of the client
    let restored = MlsClient::restore(
        &alice.snapshot().unwrap(),
        MlsConfig::default(),
        Box::new(AllowAll),
    )
    .unwrap();
    let restored_conversation = restored
        .load_conversation(alice_conversation.group_id())
        .unwrap();
    assert!(restored_conversation.key_update_due(&restored).unwrap());

    clock.set(start + MINUTE);
    key_update(
        &alice,
        &mut alice_conversation,
        &mut [(&bob, &mut bob_conversation)],
    );
    assert!(!alice_conversation.key_update_due(&alice).unwrap());
    clock.set(start + 30 * DAY + 2 * MINUTE);
    assert!(alice_conversation.key_update_due(&alice).unwrap());
}

#[test]
fn key_updates_after_joining_with_a_last_resort_key_package() {
    use std::time::Duration;

    let clock = TestClock::new();
    let start = clock.now();
    let alice = timed_client("alice", &clock);
    let bob = timed_client("bob", &clock);
    let (mut alice_conversation, _, _) = establish(&alice, &bob);
    let carol = timed_client("carol", &clock);
    let key_package = carol.generate_key_package(true).unwrap();
    let bundle = accept(
        &alice_conversation
            .add_members(&alice, &[&key_package])
            .unwrap(),
    );
    let mut carol_conversation = carol
        .join_conversation(&bundle.welcome, &bundle.ratchet_tree)
        .unwrap();
    alice_conversation
        .process_commit_bundle(&alice, &bundle)
        .unwrap();
    let due = |conversation: &MlsConversation, after: Duration| {
        clock.set(start + after);
        conversation.key_update_due(&carol).unwrap()
    };

    // after a day at most, or 30 messages, at any time (RCC.16 section 9.5.2)
    assert!(!due(&carol_conversation, Duration::ZERO));
    assert!(!due(&carol_conversation, DAY - MINUTE));
    assert!(due(&carol_conversation, DAY + MINUTE));
    send(&carol, &mut carol_conversation, 29);
    assert!(!due(&carol_conversation, Duration::ZERO));
    send(&carol, &mut carol_conversation, 1);
    assert!(due(&carol_conversation, Duration::ZERO));

    // and as others after the first
    clock.set(start);
    key_update(
        &carol,
        &mut carol_conversation,
        &mut [(&alice, &mut alice_conversation)],
    );
    assert!(!due(&carol_conversation, 2 * DAY));
    send(&carol, &mut carol_conversation, 30);
    assert!(!due(&carol_conversation, 2 * DAY));
    send(&carol, &mut carol_conversation, 20);
    assert!(!due(&carol_conversation, 7 * DAY - MINUTE));
    assert!(due(&carol_conversation, 7 * DAY + MINUTE));
}

#[test]
fn no_key_updates_in_groups_unencrypted_or_left() {
    let clock = TestClock::new();
    let start = clock.now();
    let alice = timed_client("alice", &clock);
    let bob = timed_client("bob", &clock);
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);

    // nor in one with no record of when its leaf was last updated
    let carol = timed_client("carol", &clock);
    let carol_conversation = carol.create_conversation(None, 0).unwrap();
    assert!(!carol_conversation.key_update_due(&carol).unwrap());
    carol_conversation.forget_own_leaf(&carol).unwrap();
    assert!(carol_conversation.key_update_due(&carol).unwrap());

    let output = alice_conversation
        .remove_members(&alice, &[bob.credential().clone()])
        .unwrap();
    let bundle = accept(&output);
    alice_conversation
        .process_commit_bundle(&alice, &bundle)
        .unwrap();
    bob_conversation
        .process_commit_bundle(&bob, &bundle)
        .unwrap();
    assert!(!bob_conversation.is_active());
    assert!(!bob_conversation.is_encryption_ended());
    clock.set(start + 31 * DAY);
    assert!(!bob_conversation.key_update_due(&bob).unwrap());

    clock.set(start);
    let output = alice_conversation
        .set_encryption_ended(
            &alice,
            Some(proto::EndMlsReason::ClientFailureEncryptionNotAvailable),
        )
        .unwrap();
    alice_conversation
        .process_commit_bundle(&alice, &accept(&output))
        .unwrap();
    clock.set(start + 31 * DAY);
    assert!(!alice_conversation.key_update_due(&alice).unwrap());

    // nothing of it kept once the group is let go of
    let group_id = alice_conversation.group_id().to_vec();
    let kept = |client: &MlsClient| {
        client
            .provider()
            .read_value(&key_update::own_leaf_key(&group_id))
            .unwrap()
    };
    assert!(kept(&alice).is_some());
    alice_conversation.delete(&alice).unwrap();
    assert_eq!(kept(&alice), None);
}

#[test]
fn key_updates_start_over_on_rejoining() {
    let clock = TestClock::new();
    let start = clock.now();
    let alice = timed_client("alice", &clock);
    let bob = timed_client("bob", &clock);
    let (alice_conversation, mut bob_conversation, group_info) = establish(&alice, &bob);
    send(&bob, &mut bob_conversation, 50);
    clock.set(start + 8 * DAY);
    assert!(bob_conversation.key_update_due(&bob).unwrap());

    // the External Commit taking the place of the leaf of bob
    clock.set(start);
    let (bob_conversation, _) = bob
        .rejoin_conversation(&MlsGroupInfo {
            group_info,
            ratchet_tree: alice_conversation.ratchet_tree().unwrap(),
            pending_proposals: Vec::new(),
        })
        .unwrap();
    clock.set(start + 8 * DAY);
    assert!(!bob_conversation.key_update_due(&bob).unwrap());
}

#[test]
fn a_leaf_is_behind_a_client_renewed_with_another_credential_or_key() {
    use openmls::prelude::BasicCredential;
    use openmls_basic_credential::SignatureKeyPair;

    let bob = client("bob");

    // another credential, for the same key
    let mut alice = client("alice");
    let (alice_conversation, _, _) = establish(&alice, &bob);
    assert!(!alice_conversation.credential_outdated(&alice));
    let signer = alice.signer().clone();
    alice
        .renew(BasicCredential::new(b"alice 2".to_vec()).into(), signer)
        .unwrap();
    assert!(alice_conversation.credential_outdated(&alice));

    // the same credential, for another key
    let mut carol = client("carol");
    let (carol_conversation, _, _) = establish(&carol, &bob);
    let credential = carol.credential().clone();
    carol
        .renew(
            credential,
            SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).unwrap(),
        )
        .unwrap();
    assert!(carol_conversation.credential_outdated(&carol));
}

#[test]
fn leaves_not_updated_in_30_days_are_to_be_replaced() {
    use std::time::Duration;

    let clock = TestClock::new();
    let start = clock.now();
    let alice = timed_client("alice", &clock);
    let bob = timed_client("bob", &clock);
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);
    let stale = |conversation: &MlsConversation, client: &MlsClient, after: Duration| {
        clock.set(start + after);
        conversation.stale_members(client).unwrap()
    };

    // over 30 days since the client first saw them, never the client itself
    // (RCC.16 section 9.5.4)
    assert_eq!(stale(&alice_conversation, &alice, 30 * DAY - MINUTE), []);
    assert_eq!(
        stale(&alice_conversation, &alice, 30 * DAY + MINUTE),
        [bob.credential().clone()]
    );
    assert_eq!(
        stale(&bob_conversation, &bob, 30 * DAY + MINUTE),
        [alice.credential().clone()]
    );

    // a key update makes the leaf new, from when it is applied
    clock.set(start + 20 * DAY);
    key_update(
        &bob,
        &mut bob_conversation,
        &mut [(&alice, &mut alice_conversation)],
    );
    // and other leaves stay as old as they were
    assert_eq!(
        stale(&bob_conversation, &bob, 30 * DAY + MINUTE),
        [alice.credential().clone()]
    );
    // a leaf added is new too
    clock.set(start + 25 * DAY);
    let carol = timed_client("carol", &clock);
    let key_package = carol.generate_key_package(false).unwrap();
    let output = alice_conversation
        .add_members(&alice, &[&key_package])
        .unwrap();
    alice_conversation
        .process_commit_bundle(&alice, &accept(&output))
        .unwrap();
    assert_eq!(stale(&alice_conversation, &alice, 50 * DAY - MINUTE), []);
    assert_eq!(
        stale(&alice_conversation, &alice, 50 * DAY + MINUTE),
        [bob.credential().clone()]
    );
    assert_eq!(
        stale(&alice_conversation, &alice, 55 * DAY + MINUTE),
        [bob.credential().clone(), carol.credential().clone()]
    );

    // kept with the rest of the client
    let mut restored = MlsClient::restore(
        &alice.snapshot().unwrap(),
        MlsConfig::default(),
        Box::new(AllowAll),
    )
    .unwrap();
    clock.keep(&mut restored);
    let restored_conversation = restored
        .load_conversation(alice_conversation.group_id())
        .unwrap();
    assert_eq!(
        stale(&restored_conversation, &restored, 50 * DAY + MINUTE),
        [bob.credential().clone()]
    );

    // a client taking the place of another through an External Commit sees
    // the leaves from then on
    clock.set(start + 60 * DAY);
    let new_bob = timed_client("bob-2", &clock);
    let (new_bob_conversation, _) = new_bob
        .rejoin_conversation_replacing(
            &MlsGroupInfo {
                group_info: output.group_info,
                ratchet_tree: alice_conversation.ratchet_tree().unwrap(),
                pending_proposals: Vec::new(),
            },
            &[bob.credential().clone()],
        )
        .unwrap();
    assert_eq!(
        stale(&new_bob_conversation, &new_bob, 90 * DAY - MINUTE),
        []
    );
    assert_eq!(
        stale(&new_bob_conversation, &new_bob, 90 * DAY + MINUTE),
        [alice.credential().clone(), carol.credential().clone()]
    );
}

#[test]
fn no_leaves_are_replaced_of_members_leaving_nor_in_groups_unencrypted_or_left() {
    let clock = TestClock::new();
    let start = clock.now();
    let alice = timed_client("alice", &clock);
    let bob = timed_client("bob", &clock);
    let carol = timed_client("carol", &clock);
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);
    let key_package = carol.generate_key_package(false).unwrap();
    let bundle = accept(
        &alice_conversation
            .add_members(&alice, &[&key_package])
            .unwrap(),
    );
    let mut carol_conversation = carol
        .join_conversation(&bundle.welcome, &bundle.ratchet_tree)
        .unwrap();
    for (client, conversation) in [
        (&alice, &mut alice_conversation),
        (&bob, &mut bob_conversation),
    ] {
        conversation.process_commit_bundle(client, &bundle).unwrap();
    }
    let stale = |conversation: &MlsConversation, client: &MlsClient| {
        clock.set(start + 31 * DAY);
        let stale = conversation.stale_members(client).unwrap();
        clock.set(start);
        stale
    };

    // a member whose self_remove a Commit is to take
    let proposal = carol_conversation.leave(&carol).unwrap();
    for (client, conversation) in [
        (&alice, &mut alice_conversation),
        (&bob, &mut bob_conversation),
    ] {
        conversation.process(client, &proposal).unwrap();
    }
    assert_eq!(
        stale(&alice_conversation, &alice),
        [bob.credential().clone()]
    );

    // a group with no record of when the leaf keys were first seen
    let group_id = alice_conversation.group_id().to_vec();
    let kept = |client: &MlsClient| {
        client
            .provider()
            .read_value(&key_update::leaf_keys_key(&group_id))
            .unwrap()
    };
    assert!(kept(&bob).is_some());
    bob_conversation.forget_leaf_keys(&bob).unwrap();
    assert_eq!(stale(&bob_conversation, &bob), []);

    // a client removed
    let output = alice_conversation
        .remove_members(&alice, &[bob.credential().clone()])
        .unwrap();
    let bundle = accept(&output);
    alice_conversation
        .process_commit_bundle(&alice, &bundle)
        .unwrap();
    bob_conversation
        .process_commit_bundle(&bob, &bundle)
        .unwrap();
    assert!(!bob_conversation.is_active());
    assert_eq!(stale(&bob_conversation, &bob), []);

    // nothing of it kept once the group is let go of
    assert!(kept(&alice).is_some());
    alice_conversation.delete(&alice).unwrap();
    assert_eq!(kept(&alice), None);

    // a group moved to unencrypted
    let (mut alice_conversation, _, _) = establish(&alice, &bob);
    assert_eq!(
        stale(&alice_conversation, &alice),
        [bob.credential().clone()]
    );
    let output = alice_conversation
        .set_encryption_ended(
            &alice,
            Some(proto::EndMlsReason::ClientFailureEncryptionNotAvailable),
        )
        .unwrap();
    alice_conversation
        .process_commit_bundle(&alice, &accept(&output))
        .unwrap();
    assert_eq!(stale(&alice_conversation, &alice), []);
}

#[test]
fn a_key_package_update_replaces_stale_leaves_with_a_welcome() {
    use openmls::prelude::BasicCredential;
    use openmls_basic_credential::SignatureKeyPair;

    let clock = TestClock::new();
    let start = clock.now();
    let mut alice = timed_client("alice", &clock);
    let phone = timed_client("bob-1", &clock);
    let tablet = timed_client("bob-2", &clock);
    let (mut alice_conversation, mut phone_conversation, _) = establish(&alice, &phone);
    let key_package = tablet.generate_key_package(false).unwrap();
    let bundle = accept(
        &alice_conversation
            .add_members(&alice, &[&key_package])
            .unwrap(),
    );
    let mut tablet_conversation = tablet
        .join_conversation(&bundle.welcome, &bundle.ratchet_tree)
        .unwrap();
    for (client, conversation) in [
        (&alice, &mut alice_conversation),
        (&phone, &mut phone_conversation),
    ] {
        conversation.process_commit_bundle(client, &bundle).unwrap();
    }
    clock.set(start + 10 * DAY);
    key_update(
        &tablet,
        &mut tablet_conversation,
        &mut [
            (&alice, &mut alice_conversation),
            (&phone, &mut phone_conversation),
        ],
    );
    clock.set(start + 31 * DAY);
    let stale = alice_conversation.stale_members(&alice).unwrap();
    assert_eq!(stale, [phone.credential().clone()]);

    // alice renewed her certificate meanwhile
    alice
        .renew(
            BasicCredential::new(b"alice 2".to_vec()).into(),
            SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).unwrap(),
        )
        .unwrap();

    // what the Home KDS returns for the Participants: KeyPackages of the
    // phone, of the tablet, which stays, and of alice herself
    let from_phone = phone.generate_key_package(false).unwrap();
    let again_from_phone = phone.generate_key_package(false).unwrap();
    let from_tablet = tablet.generate_key_package(false).unwrap();
    let from_alice = alice.generate_key_package(false).unwrap();
    let output = alice_conversation
        .replace_members(
            &alice,
            &stale,
            &[&from_phone, &again_from_phone, &from_tablet, &from_alice],
        )
        .unwrap();
    let staged_commit = alice_conversation.mls_group().pending_commit().unwrap();
    let removed: Vec<_> = staged_commit
        .remove_proposals()
        .map(|p| p.remove_proposal().removed())
        .collect();
    assert_eq!(removed, [phone_conversation.mls_group().own_leaf_index()]);
    let added: Vec<_> = staged_commit
        .add_proposals()
        .map(|p| p.add_proposal().key_package().clone())
        .collect();
    assert_eq!(added.len(), 1);
    assert_eq!(
        added[0].leaf_node().signature_key().as_slice(),
        phone.signer().public()
    );
    // with the Welcome, and no ratchet tree for the Conversation Focus
    // (RCC.16 section 7.9.2)
    let message: ClientMlsRcsMessage = proto::decode(&output.to_client_message().unwrap()).unwrap();
    match message.payload.unwrap() {
        client_mls_rcs_message::Payload::WelcomeCommitBundle(bundle) => {
            assert!(!bundle.welcome.is_empty());
            assert!(bundle.ratchet_tree.is_empty());
        }
        _ => panic!("expected a WelcomeCommitBundle"),
    }

    // the tablet takes it
    let bundle = accept(&output);
    alice_conversation
        .process_commit_bundle(&alice, &bundle)
        .unwrap();
    assert!(!alice_conversation.credential_outdated(&alice));
    match tablet_conversation
        .process_commit_bundle(&tablet, &bundle)
        .unwrap()
        .as_slice()
    {
        [IncomingMessage::Commit {
            sender,
            added,
            removed,
            self_removed: false,
        }] => {
            assert_eq!(sender.serialized_content(), b"alice");
            assert_eq!(added, &[phone.credential().clone()]);
            assert_eq!(removed, &[phone.credential().clone()]);
        }
        _ => panic!("expected a Commit"),
    }
    // the phone is removed, and joins again with the Welcome
    phone_conversation
        .process_commit_bundle(&phone, &bundle)
        .unwrap();
    assert!(!phone_conversation.is_active());
    let mut phone_conversation = phone
        .join_conversation(&bundle.welcome, &bundle.ratchet_tree)
        .unwrap();
    assert!(phone_conversation.is_active());
    assert!(!phone_conversation.key_update_due(&phone).unwrap());

    let message = alice_conversation
        .encrypt_cpim(&alice, b"hi", b"msg-1", b"")
        .unwrap();
    for (client, conversation) in [
        (&phone, &mut phone_conversation),
        (&tablet, &mut tablet_conversation),
    ] {
        let decrypted = conversation.decrypt(client, &message, b"msg-1").unwrap();
        assert_eq!(&decrypted.sender, alice.credential());
    }
    assert_eq!(alice_conversation.stale_members(&alice).unwrap(), []);
}

/// The GroupContext extensions of `conversation`, but for the Era
fn extensions_besides_era(conversation: &mut MlsConversation) -> Vec<(u16, Vec<u8>)> {
    use openmls::prelude::{Extension, UnknownExtension};
    conversation
        .mls_group()
        .extensions()
        .iter()
        .filter_map(|extension| match extension {
            Extension::Unknown(extension_type, UnknownExtension(data))
                if *extension_type != EXTENSION_ERA =>
            {
                Some((*extension_type, data.clone()))
            }
            _ => None,
        })
        .collect()
}

#[test]
fn a_new_era_is_made_from_the_group_info_of_the_focus() {
    use super::era::EraBase;

    let alice = client("alice");
    let bob = client("bob");
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);
    let group_id = alice_conversation.group_id().to_vec();
    let (output, _) = alice_conversation
        .set_group_subject(&alice, "Team", b"msg-subject")
        .unwrap();
    deliver(
        (&mut alice_conversation, &alice),
        vec![(&mut bob_conversation, &bob)],
        &output,
    );
    let token = bob.group_metadata(&group_id).unwrap().continuity_token;

    // the Era after that of the GroupInfo, with its GroupContext extensions
    // (RCC.16 section 8.3.1)
    let base = EraBase::of_group_info(&MlsGroupInfo {
        group_info: output.group_info.clone(),
        ratchet_tree: alice_conversation.ratchet_tree().unwrap(),
        pending_proposals: Vec::new(),
    })
    .unwrap();
    assert_eq!(base.group_id(), group_id.as_slice());
    assert_eq!(base.era(), 2);
    assert_eq!(
        base.members(),
        [alice.credential().clone(), bob.credential().clone()]
    );
    let mut next = bob.create_next_era(&base, false).unwrap();
    assert_eq!((next.era(), next.epoch()), (Some(3), 0));
    assert_eq!(next.members(), [bob.credential().clone()]);
    assert_eq!(
        extensions_besides_era(&mut next),
        extensions_besides_era(&mut alice_conversation)
    );
    assert!(!extensions_besides_era(&mut next).is_empty());
    // in place of the group of the Era before, the continuity token kept
    assert_eq!(bob.load_conversation(&group_id).unwrap().era(), Some(3));
    assert_eq!(
        bob.group_metadata(&group_id).unwrap().continuity_token,
        token
    );

    // its first Commit gives the Conversation Focus the ratchet tree
    let key_package = alice.generate_key_package(false).unwrap();
    let output = next.add_members(&bob, &[&key_package]).unwrap();
    let message: ClientMlsRcsMessage = proto::decode(&output.to_client_message().unwrap()).unwrap();
    match message.payload.unwrap() {
        client_mls_rcs_message::Payload::WelcomeCommitBundle(bundle) => {
            assert!(!bundle.ratchet_tree.is_empty())
        }
        _ => panic!("expected a WelcomeCommitBundle"),
    }
    let bundle = accept(&output);
    next.process_commit_bundle(&bob, &bundle).unwrap();

    // a member joins it in place of its group of the Era before, still
    // active, with the key of the subject
    assert!(alice_conversation.is_active());
    let mut alice_next = alice
        .join_conversation(&bundle.welcome, &bundle.ratchet_tree)
        .unwrap();
    assert_eq!(alice_next.era(), Some(3));
    assert!(alice_next.group_metadata_in_sync(&alice).unwrap());
    let message = next.encrypt_cpim(&bob, b"hi", b"msg-1", b"").unwrap();
    let decrypted = alice_next.decrypt(&alice, &message, b"msg-1").unwrap();
    assert_eq!(&decrypted.sender, bob.credential());

    // a next Era from the group of the client, its token renewed
    let base = EraBase::of_conversation(&alice_next);
    assert_eq!(base.era(), 3);
    let mut renewed = alice.create_next_era(&base, true).unwrap();
    assert_eq!(renewed.era(), Some(4));
    assert_eq!(renewed.members(), [alice.credential().clone()]);
    assert_eq!(
        extensions_besides_era(&mut renewed),
        extensions_besides_era(&mut alice_next)
    );
    assert_ne!(
        alice.group_metadata(&group_id).unwrap().continuity_token,
        token
    );
}

/// The GroupInfo of `output`, in the MlsGroupInfo of a Conversation Focus,
/// with the ratchet tree of `conversation`
fn focus_group_info(output: &CommitOutput, conversation: &MlsConversation) -> MlsGroupInfo {
    MlsGroupInfo {
        group_info: output.group_info.clone(),
        ratchet_tree: conversation.ratchet_tree().unwrap(),
        pending_proposals: Vec::new(),
    }
}

#[test]
fn a_new_era_asks_the_members_for_what_its_client_misses() {
    use super::era::EraBase;

    let alice = client("alice");
    let bob = client("bob");
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);
    let group_id = alice_conversation.group_id().to_vec();
    let (output, _) = alice_conversation
        .set_group_icon(&alice, b"icon", "image/png", b"msg-icon")
        .unwrap();
    deliver(
        (&mut alice_conversation, &alice),
        vec![(&mut bob_conversation, &bob)],
        &output,
    );
    let (output, _) = alice_conversation
        .set_group_subject(&alice, "Team", b"msg-subject")
        .unwrap();
    deliver(
        (&mut alice_conversation, &alice),
        vec![(&mut bob_conversation, &bob)],
        &output,
    );
    let kept = alice.group_metadata(&group_id).unwrap();
    assert!(!kept.continuity_token.is_empty());
    let base = EraBase::of_group_info(&focus_group_info(&output, &alice_conversation)).unwrap();

    // keeping the key of the subject and the token, nothing is asked for
    let next = bob.create_next_era(&base, false).unwrap();
    assert!(!next.group_metadata_keys_requested());

    // keeping neither, the next Era asks for both in its GroupContext, and no
    // token is made (RCC.16 sections 8.3.1.3, 10.5.2)
    bob.forget_group_metadata(&group_id).unwrap();
    let mut next = bob.create_next_era(&base, false).unwrap();
    assert!(next.group_metadata_keys_requested());
    assert!(!next.group_metadata_in_sync(&bob).unwrap());
    assert!(bob
        .group_metadata(&group_id)
        .unwrap()
        .continuity_token
        .is_empty());
    let mut asked = extensions_besides_era(&mut alice_conversation);
    asked.push((
        EXTENSION_GROUP_METADATA_KEYS_REQUESTED,
        GROUP_METADATA_KEYS_REQUESTED.to_vec(),
    ));
    assert_eq!(extensions_besides_era(&mut next), asked);
    // nor do its GroupInfos commit to one
    let key_package = alice.generate_key_package(false).unwrap();
    let output = next.add_members(&bob, &[&key_package]).unwrap();
    assert_eq!(
        alice
            .continuity_token_matches(&output.group_info, &output.epoch_authenticator)
            .unwrap(),
        None
    );
    let bundle = accept(&output);
    next.process_commit_bundle(&bob, &bundle).unwrap();

    // a member joining it, its keys in sync, answers with what it kept
    // (section 10.5.3)
    let mut alice_next = alice
        .join_conversation(&bundle.welcome, &bundle.ratchet_tree)
        .unwrap();
    assert!(alice_next.group_metadata_keys_requested());
    assert!(alice_next.group_metadata_in_sync(&alice).unwrap());
    assert_eq!(alice.group_metadata(&group_id).unwrap(), kept);
    let output = alice_next
        .send_group_metadata_keys(&alice, b"msg-keys")
        .unwrap();
    let events = deliver((&mut alice_next, &alice), vec![(&mut next, &bob)], &output);
    match events[0].as_slice() {
        [IncomingMessage::Commit { .. }, IncomingMessage::GroupMetadataKeys {
            icon,
            subject,
            continuity_token_matches,
            ..
        }] => {
            assert!(*icon && *subject);
            assert_eq!(*continuity_token_matches, Some(true));
        }
        _ => panic!("expected a Commit with group metadata keys"),
    }
    // which the client of the Era keeps (section 10.5.4)
    assert!(!next.group_metadata_keys_requested());
    assert!(next.group_metadata_in_sync(&bob).unwrap());
    assert_eq!(bob.group_metadata(&group_id).unwrap(), kept);

    // the token alone missing, it alone is asked for; the token renewed, a
    // new one is made, and nothing is asked for
    let base = EraBase::of_conversation(&next);
    let mut metadata = kept.clone();
    metadata.continuity_token.clear();
    super::metadata::store(&bob, &group_id, &metadata).unwrap();
    let renewed = bob.create_next_era(&base, true).unwrap();
    assert!(!renewed.group_metadata_keys_requested());
    let token = bob.group_metadata(&group_id).unwrap().continuity_token;
    assert!(!token.is_empty());
    assert_ne!(token, kept.continuity_token);
    super::metadata::store(&bob, &group_id, &metadata).unwrap();
    let next = bob.create_next_era(&base, false).unwrap();
    assert!(next.group_metadata_keys_requested());
    assert!(next.group_metadata_in_sync(&bob).unwrap());

    // the key of the subject or of the icon alone missing, it is asked for,
    // the token kept going on
    for missing in ["subject", "icon"] {
        let mut metadata = kept.clone();
        let keys = metadata.group_subject_icon_keys.as_mut().unwrap();
        match missing {
            "subject" => keys.subject = None,
            _ => keys.icon = None,
        }
        super::metadata::store(&bob, &group_id, &metadata).unwrap();
        let next = bob.create_next_era(&base, false).unwrap();
        assert!(next.group_metadata_keys_requested(), "{} missing", missing);
        assert!(!next.group_metadata_in_sync(&bob).unwrap());
        assert_eq!(
            bob.group_metadata(&group_id).unwrap().continuity_token,
            kept.continuity_token
        );
    }
}

#[test]
fn a_request_of_the_era_before_is_not_copied() {
    use super::era::EraBase;

    let alice = client("alice");
    let bob = client("bob");
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);
    let group_id = alice_conversation.group_id().to_vec();
    let (output, _) = alice_conversation
        .set_group_icon(&alice, b"icon", "image/png", b"msg-icon")
        .unwrap();
    deliver(
        (&mut alice_conversation, &alice),
        vec![(&mut bob_conversation, &bob)],
        &output,
    );

    // bob asks for the keys, which alice keeps
    bob.forget_group_metadata(&group_id).unwrap();
    let output = bob_conversation.request_group_metadata_keys(&bob).unwrap();
    deliver(
        (&mut bob_conversation, &bob),
        vec![(&mut alice_conversation, &alice)],
        &output,
    );
    assert!(alice_conversation.group_metadata_keys_requested());

    // the next Era alice makes, her keys in sync, asks for nothing
    let base = EraBase::of_group_info(&focus_group_info(&output, &bob_conversation)).unwrap();
    let mut next = alice.create_next_era(&base, false).unwrap();
    assert!(!next.group_metadata_keys_requested());
    let mut copied = extensions_besides_era(&mut alice_conversation);
    copied.retain(|(extension_type, _)| *extension_type != EXTENSION_GROUP_METADATA_KEYS_REQUESTED);
    assert_eq!(extensions_besides_era(&mut next), copied);
    assert!(copied
        .iter()
        .any(|(extension_type, _)| *extension_type == EXTENSION_ICON_COMMITMENT));
}

#[test]
fn an_unencrypted_singleton_era_gives_the_focus_its_ratchet_tree_without_a_welcome() {
    use super::era::EraBase;

    let alice = client("alice");
    let bob = client("bob");
    let (mut alice_conversation, _, _) = establish(&alice, &bob);
    let group_id = alice_conversation.group_id().to_vec();
    // a GroupContext extension other than end_mls
    let (output, _) = alice_conversation
        .set_group_subject(&alice, "Team", b"msg-subject")
        .unwrap();
    alice_conversation
        .process_commit_bundle(&alice, &accept(&output))
        .unwrap();
    let base = EraBase::of_conversation(&alice_conversation);
    assert!(!base.is_encryption_ended());

    // the next Era with the client alone, moved to unencrypted (RCC.16
    // section 11.2.1)
    let mut singleton = alice.create_next_era(&base, false).unwrap();
    assert_eq!(singleton.pending_encryption_end(), None);
    let output = singleton
        .set_encryption_ended(&alice, Some(proto::EndMlsReason::OutgoingCommitFailed))
        .unwrap();
    assert_eq!(
        singleton.pending_encryption_end(),
        Some(proto::EndMlsReason::OutgoingCommitFailed)
    );
    assert!(!singleton.is_encryption_ended());

    // its first Commit, adding no one, gives the Conversation Focus the
    // ratchet tree all the same (sections 7.9.2, 7.9.3)
    assert_eq!(output.welcome, None);
    let message: ClientMlsRcsMessage = proto::decode(&output.to_client_message().unwrap()).unwrap();
    let bundle = match message.payload.unwrap() {
        client_mls_rcs_message::Payload::WelcomeCommitBundle(bundle) => bundle,
        _ => panic!("expected a WelcomeCommitBundle"),
    };
    assert!(bundle.welcome.is_empty());
    assert_eq!(Some(&bundle.ratchet_tree), output.ratchet_tree.as_ref());
    assert!(!bundle.ratchet_tree.is_empty());
    assert_eq!(bundle.group_info, output.group_info);
    // its GroupInfo telling the group unencrypted, in the next Era, with the
    // client alone
    let next = EraBase::of_group_info(&MlsGroupInfo {
        group_info: bundle.group_info,
        ratchet_tree: bundle.ratchet_tree,
        pending_proposals: Vec::new(),
    })
    .unwrap();
    assert!(next.is_encryption_ended());
    assert_eq!(next.group_id(), group_id.as_slice());
    assert_eq!(next.era(), 3);
    assert_eq!(next.members(), [alice.credential().clone()]);

    // applied once accepted
    singleton
        .process_commit_bundle(&alice, &accept(&output))
        .unwrap();
    assert!(singleton.is_encryption_ended());
    assert_eq!(
        singleton.encryption_ended_reason(),
        Some(proto::EndMlsReason::OutgoingCommitFailed)
    );
    assert_eq!(singleton.pending_encryption_end(), None);
    assert_eq!((singleton.era(), singleton.epoch()), (Some(3), 1));
    assert!(EraBase::of_conversation(&singleton).is_encryption_ended());

    // the next Era moving it back to encrypted copies its GroupContext
    // extensions but end_mls (section 8.3.1)
    let base = EraBase::of_conversation(&singleton).without_encryption_end();
    assert!(!base.is_encryption_ended());
    assert_eq!(base.era(), 3);
    assert_eq!(base.members(), [alice.credential().clone()]);
    let mut next = alice.create_next_era(&base, false).unwrap();
    assert!(!next.is_encryption_ended());
    assert_eq!(next.era(), Some(4));
    let mut kept = extensions_besides_era(&mut singleton);
    kept.retain(|(extension_type, _)| *extension_type != EXTENSION_END_MLS);
    assert!(!kept.is_empty());
    assert_eq!(extensions_besides_era(&mut next), kept);
    // nor does it change a base without end_mls
    let base = EraBase::of_conversation(&alice_conversation);
    assert_eq!(
        format!("{:?}", base.clone().without_encryption_end()),
        format!("{:?}", base)
    );
}

#[test]
fn a_group_moved_to_unencrypted_is_resurrected_with_one_commit() {
    let alice = client("alice");
    let bob = client("bob");
    let carol = client("carol");
    let dave = client("dave");
    let (mut alice_conversation, mut bob_conversation, _) = establish(&alice, &bob);
    let key_package = dave.generate_key_package(false).unwrap();
    let output = alice_conversation
        .add_members(&alice, &[&key_package])
        .unwrap();
    let bundle = accept(&output);
    alice_conversation
        .process_commit_bundle(&alice, &bundle)
        .unwrap();
    bob_conversation
        .process_commit_bundle(&bob, &bundle)
        .unwrap();
    let mut dave_conversation = dave
        .join_conversation(&bundle.welcome, &bundle.ratchet_tree)
        .unwrap();

    // not while encrypted
    assert_eq!(
        alice_conversation.resurrect(&alice, &[], &[]).err(),
        Some(ErrorKind::InvalidState)
    );
    let output = alice_conversation
        .set_encryption_ended(
            &alice,
            Some(proto::EndMlsReason::GroupMemberFailsCapabilitiesCheck),
        )
        .unwrap();
    let bundle = accept(&output);
    for (client, conversation) in [
        (&alice, &mut alice_conversation),
        (&bob, &mut bob_conversation),
        (&dave, &mut dave_conversation),
    ] {
        conversation.process_commit_bundle(client, &bundle).unwrap();
        assert!(conversation.is_encryption_ended());
    }

    // back to encrypted with one Commit (RCC.16 section 11.1.2): Dave no
    // longer a Participant, Carol one now, and Bob's KeyPackage left out,
    // as he stays a member
    let carols = carol.generate_key_package(false).unwrap();
    let bobs = bob.generate_key_package(false).unwrap();
    let output = alice_conversation
        .resurrect(&alice, &[dave.credential().clone()], &[&carols, &bobs])
        .unwrap();
    assert!(alice_conversation.is_encryption_ended());
    assert_eq!(alice_conversation.pending_encryption_end(), None);
    let message: ClientMlsRcsMessage = proto::decode(&output.to_client_message().unwrap()).unwrap();
    match message.payload.unwrap() {
        client_mls_rcs_message::Payload::WelcomeCommitBundle(bundle) => {
            assert!(!bundle.welcome.is_empty());
            // not the first Commit of the Era
            assert!(bundle.ratchet_tree.is_empty());
        }
        _ => panic!("expected a WelcomeCommitBundle"),
    }

    let bundle = accept(&output);
    for (client, conversation) in [
        (&alice, &mut alice_conversation),
        (&bob, &mut bob_conversation),
        (&dave, &mut dave_conversation),
    ] {
        conversation.process_commit_bundle(client, &bundle).unwrap();
    }
    assert!(!dave_conversation.is_active());
    let mut carol_conversation = carol
        .join_conversation(&bundle.welcome, &bundle.ratchet_tree)
        .unwrap();
    for conversation in [&alice_conversation, &bob_conversation, &carol_conversation] {
        assert!(!conversation.is_encryption_ended());
        assert_eq!(conversation.era(), Some(2));
        let members = conversation.members();
        assert_eq!(members.len(), 3);
        for member in [&alice, &bob, &carol] {
            assert!(members.contains(member.credential()));
        }
    }

    // its messages encrypted again
    let message = alice_conversation
        .encrypt_cpim(&alice, b"hi", b"msg-1", b"")
        .unwrap();
    for (client, conversation) in [
        (&bob, &mut bob_conversation),
        (&carol, &mut carol_conversation),
    ] {
        let decrypted = conversation.decrypt(client, &message, b"msg-1").unwrap();
        assert_eq!(&decrypted.sender, alice.credential());
    }
}

#[test]
fn a_welcome_takes_the_place_of_a_group_still_active_for_a_later_era_only() {
    let alice = client("alice");
    let bob = client("bob");
    let (alice_conversation, _, _) = establish(&alice, &bob);
    let group_id = alice_conversation.group_id().to_vec();
    let carol = client("carol");
    let welcome_of_era = |era: u32| {
        if let Ok(old) = carol.load_conversation(&group_id) {
            old.delete(&carol).unwrap();
        }
        let mut carols = carol.create_conversation(Some(&group_id), era).unwrap();
        let key_package = alice.generate_key_package(false).unwrap();
        let output = carols.add_members(&carol, &[&key_package]).unwrap();
        (output.welcome.unwrap(), output.ratchet_tree.unwrap())
    };
    let kept = || {
        let conversation = alice.load_conversation(&group_id).unwrap();
        (conversation.era(), conversation.members().len())
    };

    // not of the same Era, nor of an earlier one
    for era in [2, 1] {
        let (welcome, ratchet_tree) = welcome_of_era(era);
        assert!(alice.join_conversation(&welcome, &ratchet_tree).is_err());
        assert_eq!(kept(), (Some(2), 2));
    }

    // of a later one
    let (welcome, ratchet_tree) = welcome_of_era(3);
    let joined = alice.join_conversation(&welcome, &ratchet_tree).unwrap();
    assert_eq!(joined.era(), Some(3));
    assert_eq!(kept(), (Some(3), 2));
    assert!(joined.members().contains(carol.credential()));
}
