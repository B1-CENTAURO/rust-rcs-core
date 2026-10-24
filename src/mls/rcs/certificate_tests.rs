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
use super::certificate::{x509_credential, CertificateError, RcsCredentialValidator};

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
