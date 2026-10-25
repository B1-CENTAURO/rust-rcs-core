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

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::types::SignatureScheme;

use super::super::{
    Ciphersuite, Credential, CredentialType, ErrorKind, IncomingMessage, MlsClient, MlsConfig,
};
use super::certificate::{
    check_participant_information, credential_tel_uris, same_tel_uri, x509_credential,
    CertificateError, ClientIdentity, ParticipantKey, RcsCredentialValidator,
};

#[allow(dead_code)]
#[path = "testdata/certificates.rs"]
mod certificates;

use certificates::*;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256;

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn time(date: &str) -> SystemTime {
    chrono::DateTime::parse_from_rfc3339(&format!("{}T00:00:00Z", date))
        .unwrap()
        .into()
}

fn credential(chain: &[&str]) -> Credential {
    let chain: Vec<Vec<u8>> = chain.iter().map(|c| bytes(c)).collect();
    let chain: Vec<&[u8]> = chain.iter().map(|c| c.as_slice()).collect();
    x509_credential(&chain)
}

fn validator(date: &str) -> RcsCredentialValidator {
    let now = time(date);
    RcsCredentialValidator::new(&[&bytes(ROOT)])
        .unwrap()
        .with_clock(move || now)
}

fn check(chain: &[&str], key: &str, date: &str) -> Result<(), CertificateError> {
    validator(date)
        .validate_credential(&credential(chain), &bytes(key))
        .map(|_| ())
}

#[test]
fn valid_client_certificates() {
    let certificate = validator("2026-10-15")
        .validate_credential(&credential(&[ALICE, CA]), &bytes(ALICE_PUBLIC_KEY))
        .unwrap();
    assert_eq!(certificate.tel_uris, vec!["tel:+491701234567"]);
    assert_eq!(certificate.vendor_id, 42);
    assert_eq!(certificate.not_before, time("2026-09-01"));
    assert_eq!(certificate.not_after, time("2026-11-01"));

    // Alice's certificate carries a separate Participant Key, Bob's chains two older ones
    let bob = validator("2026-10-15")
        .validate_credential(&credential(&[BOB, CA]), &bytes(BOB_PUBLIC_KEY))
        .unwrap();
    assert_ne!(certificate.participant_key, bob.participant_key);

    // root to leaf order, and roots sent along
    assert_eq!(check(&[CA, ALICE], ALICE_PUBLIC_KEY, "2026-10-15"), Ok(()));
    assert_eq!(
        check(&[ALICE, CA, ROOT], ALICE_PUBLIC_KEY, "2026-10-15"),
        Ok(())
    );
}

#[test]
fn chain_of_trust() {
    // issued under a root that is not trusted
    assert_eq!(
        check(&[MALLORY, OTHER_CA], MALLORY_PUBLIC_KEY, "2026-10-15"),
        Err(CertificateError::Untrusted)
    );
    assert_eq!(
        check(
            &[MALLORY, OTHER_CA, OTHER_ROOT],
            MALLORY_PUBLIC_KEY,
            "2026-10-15"
        ),
        Err(CertificateError::Untrusted)
    );
    // presented with a CA that did not issue it
    assert_eq!(
        check(&[MALLORY, CA], MALLORY_PUBLIC_KEY, "2026-10-15"),
        Err(CertificateError::Untrusted)
    );
    // no intermediate CA
    assert_eq!(
        check(&[ALICE], ALICE_PUBLIC_KEY, "2026-10-15"),
        Err(CertificateError::Untrusted)
    );
    assert_eq!(
        check(&[ALICE, ROOT], ALICE_PUBLIC_KEY, "2026-10-15"),
        Err(CertificateError::Untrusted)
    );

    // a modified Client Certificate
    let mut alice = bytes(ALICE);
    let uri = alice.windows(4).position(|w| w == b"tel:").unwrap();
    alice[uri + 6] ^= 1;
    let chain = [alice.as_slice(), &bytes(CA)];
    assert_eq!(
        validator("2026-10-15")
            .validate_credential(&x509_credential(&chain), &bytes(ALICE_PUBLIC_KEY))
            .err(),
        Some(CertificateError::BadSignature)
    );
}

#[test]
fn certificate_profile() {
    assert_eq!(
        check(&[ALICE, CA], BOB_PUBLIC_KEY, "2026-10-15"),
        Err(CertificateError::KeyMismatch)
    );
    assert_eq!(
        check(&[SERVER_AUTH, CA], ALICE_PUBLIC_KEY, "2026-10-15"),
        Err(CertificateError::Usage)
    );
    assert_eq!(
        validator("2026-10-15")
            .validate_credential(&credential(&[OTHER_VENDOR, CA]), &leaf_key(OTHER_VENDOR))
            .err(),
        Some(CertificateError::VendorId)
    );
    // 80 days of validity, more than the 76 allowed
    assert_eq!(
        validator("2026-10-15")
            .validate_credential(&credential(&[LONG_LIVED, CA]), &leaf_key(LONG_LIVED))
            .err(),
        Some(CertificateError::Lifetime)
    );
    // a critical extension the validator does not know
    assert_eq!(
        validator("2026-10-15")
            .validate_credential(
                &credential(&[UNKNOWN_CRITICAL, CA]),
                &leaf_key(UNKNOWN_CRITICAL)
            )
            .err(),
        Some(CertificateError::Malformed)
    );

    assert_eq!(
        validator("2026-10-15")
            .validate_credential(
                &Credential::new(CredentialType::Basic, b"alice".to_vec()),
                &bytes(ALICE_PUBLIC_KEY)
            )
            .err(),
        Some(CertificateError::Malformed)
    );
}

/// Public key of a fixture certificate, for the ones without a private key alongside
fn leaf_key(certificate: &str) -> Vec<u8> {
    use der::Decode;
    let certificate = x509_cert::Certificate::from_der(&bytes(certificate)).unwrap();
    certificate
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes()
        .to_vec()
}

#[test]
fn validity_and_revocation() {
    assert_eq!(
        check(&[ALICE, CA], ALICE_PUBLIC_KEY, "2026-08-31"),
        Err(CertificateError::Expired)
    );
    assert_eq!(
        check(&[ALICE, CA], ALICE_PUBLIC_KEY, "2026-11-02"),
        Err(CertificateError::Expired)
    );

    let ca = bytes(CA);
    let revoking = validator("2026-10-15").with_revocation_check(move |c| c == ca.as_slice());
    assert_eq!(
        revoking
            .validate_credential(&credential(&[ALICE, CA]), &bytes(ALICE_PUBLIC_KEY))
            .err(),
        Some(CertificateError::Revoked)
    );
}

#[test]
fn query_validation() {
    let alice = credential(&[ALICE, CA]);
    let key = bytes(ALICE_PUBLIC_KEY);

    for tel_uri in ["tel:+491701234567", "+491701234567"] {
        assert!(validator("2026-09-15")
            .validate_query(&alice, &key, tel_uri)
            .is_ok());
    }
    assert_eq!(
        validator("2026-09-15")
            .validate_query(&alice, &key, "tel:+491707654321")
            .err(),
        Some(CertificateError::Identity)
    );
    // less than 30 days left
    assert_eq!(
        validator("2026-10-15")
            .validate_query(&alice, &key, "tel:+491701234567")
            .err(),
        Some(CertificateError::Expired)
    );
}

#[test]
fn replacement_validation() {
    let alice = credential(&[ALICE, CA]);
    let renewed = credential(&[ALICE_RENEWED, CA]);
    let renewed_key = bytes(ALICE_RENEWED_PUBLIC_KEY);

    // the old certificate may have expired by then
    assert!(validator("2026-11-15")
        .validate_replacement(&alice, &renewed, &renewed_key)
        .is_ok());

    assert_eq!(
        validator("2026-10-15")
            .validate_replacement(&renewed, &alice, &bytes(ALICE_PUBLIC_KEY))
            .err(),
        Some(CertificateError::NotNewer)
    );
    assert_eq!(
        validator("2026-10-15")
            .validate_replacement(&credential(&[BOB, CA]), &renewed, &renewed_key)
            .err(),
        Some(CertificateError::Identity)
    );

    // the same certificate has to be valid still
    assert!(validator("2026-10-15")
        .validate_replacement(&alice, &alice, &bytes(ALICE_PUBLIC_KEY))
        .is_ok());
    assert_eq!(
        validator("2026-11-15")
            .validate_replacement(&alice, &alice, &bytes(ALICE_PUBLIC_KEY))
            .err(),
        Some(CertificateError::Expired)
    );
}

#[test]
fn trusted_roots() {
    assert_eq!(
        RcsCredentialValidator::new(&[&bytes(CA)]).err(),
        Some(CertificateError::Usage)
    );
    assert_eq!(
        RcsCredentialValidator::new(&[b"not a certificate"]).err(),
        Some(CertificateError::Malformed)
    );
}

fn x509_client(chain: &[&str], key: &str, public_key: &str, now: Arc<AtomicU64>) -> MlsClient {
    let signer = SignatureKeyPair::from_raw(
        SignatureScheme::ECDSA_SECP256R1_SHA256,
        bytes(key),
        bytes(public_key),
    );
    let validator = RcsCredentialValidator::new(&[&bytes(ROOT)])
        .unwrap()
        .with_clock(move || {
            SystemTime::UNIX_EPOCH + Duration::from_secs(now.load(Ordering::Relaxed))
        });

    MlsClient::with_credential(
        credential(chain),
        signer,
        CIPHERSUITE,
        MlsConfig::default(),
        Box::new(validator),
    )
    .unwrap()
}

fn seconds(date: &str) -> u64 {
    time(date)
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn groups_of_rcs_clients() {
    let now = Arc::new(AtomicU64::new(seconds("2026-09-15")));
    let alice = x509_client(&[ALICE, CA], ALICE_KEY, ALICE_PUBLIC_KEY, now.clone());
    let bob = x509_client(&[BOB, CA], BOB_KEY, BOB_PUBLIC_KEY, now.clone());
    let mallory = x509_client(
        &[MALLORY, OTHER_CA],
        MALLORY_KEY,
        MALLORY_PUBLIC_KEY,
        now.clone(),
    );

    let mut alice_conversation = alice.create_conversation(None, 0).unwrap();
    let key_package = bob.generate_key_package(false).unwrap();
    let output = alice_conversation
        .add_members(&alice, &[&key_package])
        .unwrap();
    alice_conversation.merge_pending_commit(&alice).unwrap();
    let mut bob_conversation = bob
        .join_conversation(&output.welcome.unwrap(), &output.ratchet_tree.unwrap())
        .unwrap();

    let message = alice_conversation
        .encrypt_cpim(&alice, b"hi", b"msg-1", b"")
        .unwrap();
    let decrypted = bob_conversation.decrypt(&bob, &message, b"msg-1").unwrap();
    assert_eq!(decrypted.sender.credential_type(), CredentialType::X509);

    // a certificate not chaining to the trusted root is refused
    let key_package = mallory.generate_key_package(false).unwrap();
    assert_eq!(
        alice_conversation
            .add_members(&alice, &[&key_package])
            .err(),
        Some(ErrorKind::InvalidCredential)
    );

    // so is adding one with less than 30 days left, while accepting such
    // members added by others is fine
    now.store(seconds("2026-10-15"), Ordering::Relaxed);
    let mut other = bob.create_conversation(None, 0).unwrap();
    let key_package = alice.generate_key_package(false).unwrap();
    assert_eq!(
        other.add_members(&bob, &[&key_package]).err(),
        Some(ErrorKind::InvalidCredential)
    );

    // a key update by a member whose certificate expired is refused
    let output = alice_conversation.update_keys(&alice).unwrap();
    now.store(seconds("2026-11-05"), Ordering::Relaxed);
    assert_eq!(
        bob_conversation.process(&bob, &output.commit).err(),
        Some(ErrorKind::InvalidCredential)
    );

    now.store(seconds("2026-10-16"), Ordering::Relaxed);
    match bob_conversation.process(&bob, &output.commit).unwrap() {
        IncomingMessage::Commit { sender, .. } => {
            assert_eq!(sender, *alice.credential())
        }
        _ => panic!("expected a Commit"),
    }
}

#[test]
fn a_key_package_from_the_kds_is_checked_for_the_participant_asked_for() {
    let now = Arc::new(AtomicU64::new(seconds("2026-09-15")));
    let bob = x509_client(&[BOB, CA], BOB_KEY, BOB_PUBLIC_KEY, now);
    let info = super::super::key_package_info(&bob.generate_key_package(false).unwrap()).unwrap();
    let validator = validator("2026-09-15");

    assert!(validator
        .validate_query(&info.credential, &info.signature_key, "tel:+491707654321")
        .is_ok());
    assert_eq!(
        validator
            .validate_query(&info.credential, &info.signature_key, "tel:+491701234567")
            .err(),
        Some(CertificateError::Identity),
        "Bob's, asked for Alice's"
    );
}

/// Alice's Client Certificate, with the Participant Information `info` in
/// place of the one it was issued with
fn alice_with(info: &[u8]) -> x509_cert::Certificate {
    use der::Decode;
    let mut alice = x509_cert::Certificate::from_der(&bytes(ALICE)).unwrap();
    let extension = alice
        .tbs_certificate
        .extensions
        .iter_mut()
        .flatten()
        .find(|extension| extension.extn_id.to_string() == "2.23.146.2.1.4")
        .unwrap();
    extension.extn_value = der::asn1::OctetString::new(info).unwrap();
    alice
}

/// Alice's Client Certificate, as the Participant signs it
fn alice_identity(sign: impl FnOnce(&ClientIdentity) -> Vec<u8>) -> Vec<u8> {
    use der::Decode;
    let alice = x509_cert::Certificate::from_der(&bytes(ALICE)).unwrap();
    let common_name = &alice.tbs_certificate.subject.0[0].0.get(0).unwrap().value;
    sign(&ClientIdentity {
        client_id: common_name
            .decode_as::<der::asn1::Utf8StringRef>()
            .unwrap()
            .as_str(),
        vendor_id: 42,
        signature_key: &bytes(ALICE_PUBLIC_KEY),
        tel_uris: &["tel:+491701234567"],
    })
}

#[test]
fn a_participant_signs_the_client_certificate_the_kds_is_to_issue() {
    let participant = ParticipantKey::generate();
    let now = time("2026-09-15");
    let info = alice_identity(|alice| participant.participant_information(alice, now).unwrap());

    // the certificate issued with it holds as the validator checks it
    assert_eq!(
        check_participant_information(&alice_with(&info), now),
        Ok((42, participant.public_key()))
    );
}

#[test]
fn a_participant_signature_is_for_that_client_only() {
    let participant = ParticipantKey::generate();
    let now = time("2026-09-15");
    let alice = |client_id: Option<&str>, signature_key: &str, tel_uri: &str| -> Vec<u8> {
        alice_identity(|identity| {
            participant
                .participant_information(
                    &ClientIdentity {
                        client_id: client_id.unwrap_or(identity.client_id),
                        signature_key: &bytes(signature_key),
                        tel_uris: &[tel_uri],
                        ..*identity
                    },
                    now,
                )
                .unwrap()
        })
    };

    for (info, signed_for) in [
        (
            alice(
                Some("3f0a6a4e-2d6c-4b8e-9b38-2b1f0d6f2c11"),
                ALICE_PUBLIC_KEY,
                "tel:+491701234567",
            ),
            "another client",
        ),
        (
            alice(None, BOB_PUBLIC_KEY, "tel:+491701234567"),
            "another key",
        ),
        (
            alice(None, ALICE_PUBLIC_KEY, "tel:+491707654321"),
            "another number",
        ),
    ] {
        assert_eq!(
            check_participant_information(&alice_with(&info), now),
            Err(CertificateError::ParticipantInformation),
            "signed for {}",
            signed_for
        );
    }
}

#[test]
fn a_participant_signature_is_valid_from_an_hour_before_for_76_days() {
    let participant = ParticipantKey::generate();
    let signed = time("2026-09-15") + Duration::from_millis(1500);
    let info = alice_identity(|alice| participant.participant_information(alice, signed).unwrap());
    let alice = alice_with(&info);

    // from the whole second signed in
    let from = time("2026-09-15") + Duration::from_secs(1) - Duration::from_secs(3600);
    let until = from + Duration::from_secs(6_566_340);
    for (at, valid) in [
        (from - Duration::from_secs(1), false),
        (from, true),
        (until, true),
        (until + Duration::from_secs(1), false),
    ] {
        assert_eq!(
            check_participant_information(&alice, at).is_ok(),
            valid,
            "at {:?}",
            at
        );
    }
    assert!(until.duration_since(from).unwrap() > Duration::from_secs(45 * 86400));
}

#[test]
fn after_2049_a_participant_signature_ends_in_generalized_time() {
    use der::Decode;
    use x509_cert::time::{Time, Validity};

    let participant = ParticipantKey::generate();
    let info = alice_identity(|alice| {
        participant
            .participant_information(alice, time("2049-12-01"))
            .unwrap()
    });
    let fields = Vec::<der::Any>::from_der(&info).unwrap();
    let validity: Validity = fields[1].decode_as().unwrap();
    assert!(matches!(validity.not_before, Time::UtcTime(_)));
    assert!(matches!(validity.not_after, Time::GeneralTime(_)));
}

#[test]
fn a_participant_key_is_kept_as_its_bytes() {
    use der::Decode;

    let participant = ParticipantKey::generate();
    let kept = ParticipantKey::from_bytes(&participant.to_bytes()).unwrap();
    assert_eq!(kept.public_key(), participant.public_key());
    assert_ne!(
        ParticipantKey::generate().public_key(),
        participant.public_key()
    );
    assert_eq!(
        ParticipantKey::from_bytes(b"not a key").err(),
        Some(CertificateError::Malformed)
    );

    // an EC P-256 SubjectPublicKeyInfo
    let public_key = spki::SubjectPublicKeyInfoOwned::from_der(&participant.public_key()).unwrap();
    assert_eq!(public_key.algorithm.oid.to_string(), "1.2.840.10045.2.1");
    assert_eq!(
        public_key
            .algorithm
            .parameters
            .unwrap()
            .decode_as::<der::asn1::ObjectIdentifier>()
            .unwrap()
            .to_string(),
        "1.2.840.10045.3.1.7"
    );
    assert_eq!(public_key.subject_public_key.raw_bytes().len(), 65);
}

#[test]
fn clients_are_signed_for_with_p256_or_p384_keys() {
    use der::Decode;

    let participant = ParticipantKey::generate();
    let now = time("2026-09-15");
    let p384 = p384::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    let point = p384.verifying_key().to_encoded_point(false);

    // Alice's certificate, issued for a P-384 key
    let info = alice_identity(|alice| {
        participant
            .participant_information(
                &ClientIdentity {
                    signature_key: point.as_bytes(),
                    ..*alice
                },
                now,
            )
            .unwrap()
    });
    let mut alice = alice_with(&info);
    let p384_key_info = [
        bytes("3076301006072a8648ce3d020106052b81040022036200"),
        point.as_bytes().to_vec(),
    ]
    .concat();
    alice.tbs_certificate.subject_public_key_info =
        spki::SubjectPublicKeyInfoOwned::from_der(&p384_key_info).unwrap();
    assert!(check_participant_information(&alice, now).is_ok());

    let compressed = &bytes(ALICE_PUBLIC_KEY)[..33];
    let signing = alice_identity(|alice| {
        participant
            .participant_information(
                &ClientIdentity {
                    signature_key: compressed,
                    ..*alice
                },
                now,
            )
            .err()
            .map(|e| vec![e as u8])
            .unwrap_or_default()
    });
    assert_eq!(signing, vec![CertificateError::UnsupportedAlgorithm as u8]);
}

#[test]
fn the_identity_of_a_credential_is_the_tel_uris_of_its_client_certificate() {
    assert_eq!(
        credential_tel_uris(&credential(&[ALICE, CA])),
        Ok(vec![String::from("tel:+491701234567")])
    );
    assert_eq!(
        credential_tel_uris(&credential(&[BOB, CA, ROOT])),
        Ok(vec![String::from("tel:+491707654321")])
    );
    // taken without validation, which joining the group did
    assert_eq!(
        credential_tel_uris(&credential(&[MALLORY])),
        Ok(vec![String::from("tel:+491701234567")])
    );

    // nor any for what is not one
    assert_eq!(
        credential_tel_uris(&Credential::new(CredentialType::Basic, b"alice".to_vec())),
        Err(CertificateError::Malformed)
    );
    assert_eq!(
        credential_tel_uris(&credential(&[])),
        Err(CertificateError::Malformed)
    );
    assert_eq!(
        credential_tel_uris(&x509_credential(&[b"not a certificate"])),
        Err(CertificateError::Malformed)
    );
    // a CA names no one
    assert_eq!(
        credential_tel_uris(&credential(&[CA])),
        Err(CertificateError::Identity)
    );
}

#[test]
fn tel_uris_are_the_same_by_their_number() {
    assert!(same_tel_uri("tel:+491701234567", "tel:+491701234567"));
    assert!(same_tel_uri("TEL:+491701234567", "tel:+491701234567"));
    assert!(same_tel_uri("tel:+491701234567", "+491701234567"));
    assert!(!same_tel_uri("tel:+491701234567", "tel:+491707654321"));
}
