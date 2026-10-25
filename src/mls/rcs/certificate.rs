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

//! RCS Client Certificates (RCC.16 Annex A): their validation, and the
//! Participant signature a client has them carry
//!
//! In RCS, every MLS Client presents an X.509 credential: a Client Certificate
//! issued by its Home KDS, chained through intermediate CAs to a root that all
//! client vendors agreed to trust (RCC.16 section 3.3).

use std::time::{Duration, SystemTime};

use der::asn1::{
    Any, BitString, GeneralizedTime, Ia5String, ObjectIdentifier, SetOfVec, Uint, UtcTime,
    Utf8StringRef,
};
use der::oid::AssociatedOid;
use der::{Decode, Encode, Header, Length, Sequence, Tag};
use openmls::prelude::tls_codec::{DeserializeBytes, Serialize as _, VLByteSlice, VLBytes};
use openmls::prelude::{Credential, CredentialType};
use p256::ecdsa::signature::{Signer, Verifier};
use rand::rngs::OsRng;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    BasicConstraints, CertificatePolicies, ExtendedKeyUsage, KeyUsage, SubjectAltName,
};
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};
use x509_cert::time::{Time, Validity};
use x509_cert::{Certificate, Version};

use super::super::client::CredentialValidator;

/// id-kp-rcsMlsClient, { id-gsmaRCSE2EE 3 }
const KP_RCS_MLS_CLIENT: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.146.2.1.3");
/// id-participantInformation, { id-gsmaRCSE2EE 4 }
const PARTICIPANT_INFORMATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.146.2.1.4");
/// id-rcsVendorId, { id-gsmaRCSE2EE 6 }
const VENDOR_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.146.2.1.6");

const COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const SECP521R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");
const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const ECDSA_WITH_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const ECDSA_WITH_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

const DAY: u64 = 86400;
/// Maximum validity of Client Certificates and Participant signatures (A.3.5, A.3.8.9)
const CLIENT_MAX_LIFETIME: Duration = Duration::from_secs(76 * DAY);
/// Maximum validity of intermediate CA certificates (A.4.1.1 2e)
const CA_MAX_LIFETIME: Duration = Duration::from_secs(1827 * DAY);
/// Validity left on certificates returned by the Home KDS (A.4.1.2)
const MIN_REMAINING_LIFETIME: Duration = Duration::from_secs(30 * DAY);
/// How long before its creation a Participant signature is valid from (A.3.8.9)
const PARTICIPANT_SIGNATURE_BACKDATING: Duration = Duration::from_secs(3600);
/// Validity of Participant signatures, 76 days as RCC.16 counts them (A.3.5, A.3.8.9)
const PARTICIPANT_SIGNATURE_LIFETIME: Duration = Duration::from_secs(6_566_340);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateError {
    /// Not an X.509 credential, or not decodable
    Malformed,
    /// A key or signature algorithm outside of the RCC.16 profiles
    UnsupportedAlgorithm,
    /// A signature does not verify
    BadSignature,
    /// The chain does not lead to a trusted root
    Untrusted,
    /// A certificate or Participant signature is not valid at this time
    Expired,
    /// A validity period exceeds the profile's maximum
    Lifetime,
    /// Key usage, extended key usage or basic constraints don't fit the profile
    Usage,
    /// The ParticipantInformation extension is missing or does not verify
    ParticipantInformation,
    /// The Vendor ID asserted for the Participant is not the one of the root
    VendorId,
    /// The Client Certificate is not for the MLS signature key
    KeyMismatch,
    /// An intermediate CA certificate was revoked
    Revoked,
    /// The certificate is not for the expected Participant
    Identity,
    /// A replacing certificate was not issued after the one it replaces
    NotNewer,
}

type Result<T> = std::result::Result<T, CertificateError>;

/// Facts established by validating a Client Certificate
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientCertificate {
    /// tel URIs of the Subject Alternative Name
    pub tel_uris: Vec<String>,
    pub vendor_id: u64,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
    /// The Participant Key, as DER encoded SubjectPublicKeyInfo
    pub participant_key: Vec<u8>,
}

/// ParticipantInformation extension (A.3.8.9)
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct ParticipantInformation {
    vendor_id: Uint,
    participant_signature_validity: Validity,
    participant_signature_algorithm: AlgorithmIdentifierOwned,
    participant_signature_value: BitString,
    #[asn1(optional = "true")]
    participant_key: Option<SubjectPublicKeyInfoOwned>,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    participant_key_rolls: Option<Vec<ParticipantKeyRoll>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct ParticipantKeyRoll {
    participant_roll_signature_algorithm: AlgorithmIdentifierOwned,
    participant_roll_signature_value: BitString,
    old_participant_key: SubjectPublicKeyInfoOwned,
}

/// Tells whether a DER encoded CA certificate was revoked
type RevocationCheck = Box<dyn Fn(&[u8]) -> bool + Send + Sync>;

struct TrustedRoot {
    certificate: Certificate,
    vendor_id: u64,
}

/// `CredentialValidator` for RCS, applying the client validation of RCC.16 Annex A.4.1
pub struct RcsCredentialValidator {
    roots: Vec<TrustedRoot>,
    clock: Box<dyn Fn() -> SystemTime + Send + Sync>,
    revoked: RevocationCheck,
}

impl RcsCredentialValidator {
    /// Trusts the DER encoded `roots`, the Root Certificates all interconnected
    /// client vendors agreed on (RCC.16 section 3.3)
    pub fn new(roots: &[&[u8]]) -> Result<RcsCredentialValidator> {
        let mut trusted = Vec::with_capacity(roots.len());

        for root in roots {
            let certificate =
                Certificate::from_der(root).map_err(|_| CertificateError::Malformed)?;

            if certificate.tbs_certificate.issuer != certificate.tbs_certificate.subject
                || !extension::<BasicConstraints>(&certificate)?.is_some_and(|b| b.ca)
            {
                return Err(CertificateError::Usage);
            }
            verify_certificate(
                &certificate,
                &certificate.tbs_certificate.subject_public_key_info,
            )?;

            let vendor_id = raw_extension(&certificate, VENDOR_ID)
                .ok_or(CertificateError::VendorId)
                .and_then(|value| Uint::from_der(value).map_err(|_| CertificateError::Malformed))
                .and_then(|vendor_id| to_u64(&vendor_id))?;

            trusted.push(TrustedRoot {
                certificate,
                vendor_id,
            });
        }

        Ok(RcsCredentialValidator {
            roots: trusted,
            clock: Box::new(SystemTime::now),
            revoked: Box::new(|_| false),
        })
    }

    /// Time to validate against, the system time by default
    pub fn with_clock(mut self, clock: impl Fn() -> SystemTime + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    /// Decides whether a DER encoded intermediate CA certificate was revoked,
    /// from the CRLs of its CRL Distribution Points (A.4.1.1 2a)
    ///
    /// Fetching CRLs is left to the caller; without this, nothing counts as revoked.
    pub fn with_revocation_check(
        mut self,
        revoked: impl Fn(&[u8]) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.revoked = Box::new(revoked);
        self
    }

    /// Default Validation Requirements (A.4.1.1) for the credential of an MLS
    /// leaf whose signature key is `signature_key`
    pub fn validate_credential(
        &self,
        credential: &Credential,
        signature_key: &[u8],
    ) -> Result<ClientCertificate> {
        let now = (self.clock)();
        let chain = certificate_chain(credential)?;
        let (leaf, rest) = chain.split_first().ok_or(CertificateError::Malformed)?;

        // roots sent along in the chain are not needed
        let cas: Vec<&Certificate> = rest
            .iter()
            .filter(|c| !self.roots.iter().any(|r| r.certificate == **c))
            .collect();
        if cas.is_empty() {
            return Err(CertificateError::Untrusted);
        }

        let mut subject = leaf;
        for ca in cas {
            // a root, but none of the trusted ones
            if ca.tbs_certificate.issuer == ca.tbs_certificate.subject
                || subject.tbs_certificate.issuer != ca.tbs_certificate.subject
            {
                return Err(CertificateError::Untrusted);
            }
            verify_certificate(subject, &ca.tbs_certificate.subject_public_key_info)?;
            self.check_ca(ca, now)?;
            subject = ca;
        }

        let root = self
            .roots
            .iter()
            .find(|r| r.certificate.tbs_certificate.subject == subject.tbs_certificate.issuer)
            .ok_or(CertificateError::Untrusted)?;
        verify_certificate(
            subject,
            &root.certificate.tbs_certificate.subject_public_key_info,
        )?;
        check_time(&root.certificate.tbs_certificate.validity, now)?;

        let leaf_info = self.check_leaf(leaf, signature_key, now)?;
        if leaf_info.vendor_id != root.vendor_id {
            return Err(CertificateError::VendorId);
        }

        Ok(leaf_info)
    }

    /// Query Validation (A.4.1.2) of a KeyPackage credential the Home KDS
    /// returned for the Participant with tel URI `tel_uri`
    pub fn validate_query(
        &self,
        credential: &Credential,
        signature_key: &[u8],
        tel_uri: &str,
    ) -> Result<ClientCertificate> {
        let certificate = self.validate_credential(credential, signature_key)?;

        if !certificate
            .tel_uris
            .iter()
            .any(|uri| same_tel_uri(uri, tel_uri))
        {
            return Err(CertificateError::Identity);
        }

        let now = (self.clock)();
        if certificate.not_after < now + MIN_REMAINING_LIFETIME {
            return Err(CertificateError::Expired);
        }

        Ok(certificate)
    }

    /// Validation of a certificate replacing `old`, through a self update or a
    /// resync Commit (A.4.1.5, A.4.1.6), or an External Commit removing further
    /// Clients of the Participant (RCC.16 section 10.1.1)
    ///
    /// The old certificate may have expired; the new one has to be for one of
    /// its tel URIs and issued after it.
    pub fn validate_replacement(
        &self,
        old: &Credential,
        new: &Credential,
        signature_key: &[u8],
    ) -> Result<ClientCertificate> {
        let certificate = self.validate_credential(new, signature_key)?;
        if old == new {
            return Ok(certificate);
        }

        let old_chain = certificate_chain(old)?;
        let old_leaf = old_chain.first().ok_or(CertificateError::Malformed)?;

        let old_uris = tel_uris(old_leaf)?;
        if !certificate
            .tel_uris
            .iter()
            .any(|uri| old_uris.iter().any(|old_uri| same_tel_uri(uri, old_uri)))
        {
            return Err(CertificateError::Identity);
        }

        if certificate.not_before
            <= old_leaf
                .tbs_certificate
                .validity
                .not_before
                .to_system_time()
        {
            return Err(CertificateError::NotNewer);
        }

        Ok(certificate)
    }

    fn check_leaf(
        &self,
        leaf: &Certificate,
        signature_key: &[u8],
        now: SystemTime,
    ) -> Result<ClientCertificate> {
        check_version(leaf)?;

        let extended_key_usage =
            extension::<ExtendedKeyUsage>(leaf)?.ok_or(CertificateError::Usage)?;
        if extended_key_usage.0 != [KP_RCS_MLS_CLIENT] {
            return Err(CertificateError::Usage);
        }
        if !extension::<KeyUsage>(leaf)?.is_some_and(|k| k.digital_signature()) {
            return Err(CertificateError::Usage);
        }
        if extension::<BasicConstraints>(leaf)?.is_some_and(|b| b.ca) {
            return Err(CertificateError::Usage);
        }

        let validity = &leaf.tbs_certificate.validity;
        check_lifetime(validity, CLIENT_MAX_LIFETIME)?;
        check_time(validity, now)?;

        let subject_public_key_info = &leaf.tbs_certificate.subject_public_key_info;
        check_client_key(subject_public_key_info)?;
        if subject_public_key_info.subject_public_key.raw_bytes() != signature_key {
            return Err(CertificateError::KeyMismatch);
        }

        let tel_uris = tel_uris(leaf)?;
        if tel_uris.is_empty() {
            return Err(CertificateError::Identity);
        }

        let (vendor_id, participant_key) = check_participant_information(leaf, now)?;

        Ok(ClientCertificate {
            tel_uris,
            vendor_id,
            not_before: validity.not_before.to_system_time(),
            not_after: validity.not_after.to_system_time(),
            participant_key,
        })
    }

    fn check_ca(&self, ca: &Certificate, now: SystemTime) -> Result<()> {
        check_version(ca)?;

        if !extension::<BasicConstraints>(ca)?.is_some_and(|b| b.ca)
            || !extension::<KeyUsage>(ca)?.is_some_and(|k| k.key_cert_sign())
            || !extension::<ExtendedKeyUsage>(ca)?.is_some_and(|e| e.0 == [KP_RCS_MLS_CLIENT])
        {
            return Err(CertificateError::Usage);
        }

        check_lifetime(&ca.tbs_certificate.validity, CA_MAX_LIFETIME)?;
        check_time(&ca.tbs_certificate.validity, now)?;

        let der = ca.to_der().map_err(|_| CertificateError::Malformed)?;
        if (self.revoked)(&der) {
            return Err(CertificateError::Revoked);
        }

        Ok(())
    }
}

impl CredentialValidator for RcsCredentialValidator {
    fn validate(&self, credential: &Credential, signature_key: &[u8]) -> bool {
        self.validate_credential(credential, signature_key).is_ok()
    }

    /// Clients must not add credentials with less than 30 days left (A.4.1.3)
    fn validate_addition(&self, credential: &Credential, signature_key: &[u8]) -> bool {
        self.validate_credential(credential, signature_key)
            .is_ok_and(|c| c.not_after >= (self.clock)() + MIN_REMAINING_LIFETIME)
    }

    fn validate_replacement(
        &self,
        old: &Credential,
        new: &Credential,
        signature_key: &[u8],
    ) -> bool {
        RcsCredentialValidator::validate_replacement(self, old, new, signature_key).is_ok()
    }
}

/// The Participant Key of the user of the device (RCC.16 sections 3.1, 4.1),
/// a P-256 ECDSA key: ACS binds it to the user's MSISDN, and it signs the
/// Participant Information of each Client Certificate of the user (A.3.8.9)
pub struct ParticipantKey(p256::ecdsa::SigningKey);

/// What a Participant signs of the Client Certificate the Home KDS is to issue
/// for one of its Clients, which the certificate must carry exactly
pub struct ClientIdentity<'a> {
    /// The commonName of the Subject, a UUIDv4 (A.3.6)
    pub client_id: &'a str,
    /// The Vendor ID asserted by the root the Home KDS issues under (A.3.8.9)
    pub vendor_id: u64,
    /// The MLS signature key of the Client, an uncompressed P-256 or P-384
    /// point (A.3.7)
    pub signature_key: &'a [u8],
    /// The tel URIs of the Subject Alternative Name (A.3.8.5)
    pub tel_uris: &'a [&'a str],
}

impl ParticipantKey {
    pub fn generate() -> ParticipantKey {
        ParticipantKey(p256::ecdsa::SigningKey::random(&mut OsRng))
    }

    /// The key to_bytes() gave
    pub fn from_bytes(bytes: &[u8]) -> Result<ParticipantKey> {
        p256::ecdsa::SigningKey::from_slice(bytes)
            .map(ParticipantKey)
            .map_err(|_| CertificateError::Malformed)
    }

    /// The private key, to be kept as secret as the MLS state
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    /// The public key, as a DER encoded SubjectPublicKeyInfo: base64url
    /// encoded, the participant_public_key of the configuration request
    /// (RCC.07 section 2.3.2.2)
    pub fn public_key(&self) -> Vec<u8> {
        let point = self.0.verifying_key().to_encoded_point(false);
        // a P-256 point always encodes
        ec_public_key(point.as_bytes())
            .and_then(|key| key.to_der().map_err(|_| CertificateError::Malformed))
            .unwrap_or_default()
    }

    /// The ParticipantInformation extension, DER encoded, for the Home KDS to
    /// issue the Client Certificate of `client` with (A.3.8.9)
    ///
    /// The signature is valid from an hour before `now`, for 76 days.
    pub fn participant_information(
        &self,
        client: &ClientIdentity,
        now: SystemTime,
    ) -> Result<Vec<u8>> {
        // in whole seconds, as certificates count time
        let now = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| CertificateError::Malformed)?;
        let not_before = Duration::from_secs(now.as_secs())
            .checked_sub(PARTICIPANT_SIGNATURE_BACKDATING)
            .ok_or(CertificateError::Malformed)?;
        let validity = Validity {
            not_before: certificate_time(not_before)?,
            not_after: certificate_time(not_before + PARTICIPANT_SIGNATURE_LIFETIME)?,
        };

        let vendor_id =
            Uint::new(&client.vendor_id.to_be_bytes()).map_err(|_| CertificateError::Malformed)?;
        let subject = RdnSequence(vec![RelativeDistinguishedName(
            SetOfVec::try_from(vec![AttributeTypeAndValue {
                oid: COMMON_NAME,
                value: Any::encode_from(
                    &Utf8StringRef::new(client.client_id)
                        .map_err(|_| CertificateError::Malformed)?,
                )
                .map_err(|_| CertificateError::Malformed)?,
            }])
            .map_err(|_| CertificateError::Malformed)?,
        )]);
        let subject_alt_name = SubjectAltName(
            client
                .tel_uris
                .iter()
                .map(|uri| Ia5String::new(uri).map(GeneralName::UniformResourceIdentifier))
                .collect::<der::Result<_>>()
                .map_err(|_| CertificateError::Malformed)?,
        )
        .to_der()
        .map_err(|_| CertificateError::Malformed)?;

        let tbs_participant_info = encode_tbs_participant_info(
            &subject,
            &vendor_id,
            &validity,
            &ec_public_key(client.signature_key)?,
            &subject_alt_name,
        )?;
        let signature: p256::ecdsa::Signature = self.0.sign(&tbs_participant_info);

        ParticipantInformation {
            vendor_id,
            participant_signature_validity: validity,
            participant_signature_algorithm: AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA256,
                parameters: None,
            },
            participant_signature_value: BitString::from_bytes(signature.to_der().as_bytes())
                .map_err(|_| CertificateError::Malformed)?,
            participant_key: Some(
                SubjectPublicKeyInfoOwned::from_der(&self.public_key())
                    .map_err(|_| CertificateError::Malformed)?,
            ),
            participant_key_rolls: None,
        }
        .to_der()
        .map_err(|_| CertificateError::Malformed)
    }
}

/// The SubjectPublicKeyInfo of an uncompressed P-256 or P-384 point (A.3.7.1)
fn ec_public_key(point: &[u8]) -> Result<SubjectPublicKeyInfoOwned> {
    let curve = match point.len() {
        65 => SECP256R1,
        97 => SECP384R1,
        _ => return Err(CertificateError::UnsupportedAlgorithm),
    };
    Ok(SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: EC_PUBLIC_KEY,
            parameters: Some(Any::encode_from(&curve).map_err(|_| CertificateError::Malformed)?),
        },
        subject_public_key: BitString::from_bytes(point)
            .map_err(|_| CertificateError::Malformed)?,
    })
}

/// UTCTime through 2049, GeneralizedTime from 2050 (RFC 5280, Section 4.1.2.5)
fn certificate_time(since_epoch: Duration) -> Result<Time> {
    UtcTime::from_unix_duration(since_epoch)
        .map(Time::UtcTime)
        .or_else(|_| GeneralizedTime::from_unix_duration(since_epoch).map(Time::GeneralTime))
        .map_err(|_| CertificateError::Malformed)
}

/// Builds the MLS credential of a Client from its DER encoded certificate chain,
/// Client Certificate first (RFC 9420, Section 5.3)
pub fn x509_credential(chain: &[&[u8]]) -> Credential {
    let mut content = Vec::new();
    for certificate in chain {
        // only fails for certificates over 2^30 bytes
        if let Ok(encoded) = VLByteSlice(certificate).tls_serialize_detached() {
            content.extend_from_slice(&encoded);
        }
    }
    Credential::new(CredentialType::X509, content)
}

/// Certificates of an X.509 credential, Client Certificate first
///
/// RFC 9420 puts the Client Certificate first while RCC.16 describes chains from
/// the root down, so chains starting with a CA certificate are turned around.
fn certificate_chain(credential: &Credential) -> Result<Vec<Certificate>> {
    if credential.credential_type() != CredentialType::X509 {
        return Err(CertificateError::Malformed);
    }

    let mut chain = Vec::new();
    let mut rest = credential.serialized_content();
    while !rest.is_empty() {
        let (certificate, remainder) =
            VLBytes::tls_deserialize_bytes(rest).map_err(|_| CertificateError::Malformed)?;
        chain.push(
            Certificate::from_der(certificate.as_slice())
                .map_err(|_| CertificateError::Malformed)?,
        );
        rest = remainder;
    }

    if chain.first().map(is_ca).transpose()? == Some(true)
        && chain.last().map(is_ca).transpose()? == Some(false)
    {
        chain.reverse();
    }

    Ok(chain)
}

fn is_ca(certificate: &Certificate) -> Result<bool> {
    Ok(extension::<BasicConstraints>(certificate)?.is_some_and(|b| b.ca))
}

fn raw_extension(certificate: &Certificate, oid: ObjectIdentifier) -> Option<&[u8]> {
    certificate
        .tbs_certificate
        .extensions
        .as_ref()?
        .iter()
        .find(|extension| extension.extn_id == oid)
        .map(|extension| extension.extn_value.as_bytes())
}

fn extension<'a, T>(certificate: &'a Certificate) -> Result<Option<T>>
where
    T: AssociatedOid + Decode<'a>,
{
    raw_extension(certificate, T::OID)
        .map(|value| T::from_der(value).map_err(|_| CertificateError::Malformed))
        .transpose()
}

/// Version, and no critical extension left unprocessed (RFC 5280, Section 4.2)
fn check_version(certificate: &Certificate) -> Result<()> {
    if certificate.tbs_certificate.version != Version::V3
        || certificate.signature_algorithm != certificate.tbs_certificate.signature
    {
        return Err(CertificateError::Malformed);
    }

    let understood = [
        KeyUsage::OID,
        BasicConstraints::OID,
        ExtendedKeyUsage::OID,
        SubjectAltName::OID,
        CertificatePolicies::OID,
        PARTICIPANT_INFORMATION,
    ];
    if certificate
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .any(|extension| extension.critical && !understood.contains(&extension.extn_id))
    {
        return Err(CertificateError::Malformed);
    }

    Ok(())
}

/// The validity period counts from notBefore through notAfter inclusive (A.3.5)
fn check_lifetime(validity: &Validity, max: Duration) -> Result<()> {
    let period = validity
        .not_after
        .to_system_time()
        .duration_since(validity.not_before.to_system_time())
        .map_err(|_| CertificateError::Lifetime)?;
    if period >= max {
        return Err(CertificateError::Lifetime);
    }
    Ok(())
}

fn check_time(validity: &Validity, now: SystemTime) -> Result<()> {
    if now < validity.not_before.to_system_time() || now > validity.not_after.to_system_time() {
        return Err(CertificateError::Expired);
    }
    Ok(())
}

/// Client Certificates and Participant Keys are P-256 or P-384 (A.3.7)
fn check_client_key(key: &SubjectPublicKeyInfoOwned) -> Result<()> {
    match curve(key)? {
        SECP256R1 | SECP384R1 => Ok(()),
        _ => Err(CertificateError::UnsupportedAlgorithm),
    }
}

fn curve(key: &SubjectPublicKeyInfoOwned) -> Result<ObjectIdentifier> {
    if key.algorithm.oid != EC_PUBLIC_KEY {
        return Err(CertificateError::UnsupportedAlgorithm);
    }
    key.algorithm
        .parameters
        .as_ref()
        .ok_or(CertificateError::UnsupportedAlgorithm)?
        .decode_as()
        .map_err(|_| CertificateError::UnsupportedAlgorithm)
}

fn tel_uris(certificate: &Certificate) -> Result<Vec<String>> {
    let names = extension::<SubjectAltName>(certificate)?.ok_or(CertificateError::Identity)?;
    Ok(names
        .0
        .iter()
        .filter_map(|name| match name {
            GeneralName::UniformResourceIdentifier(uri) if uri.as_str().starts_with("tel:") => {
                Some(uri.as_str().to_string())
            }
            _ => None,
        })
        .collect())
}

/// The tel URIs of the Subject Alternative Name of the Client Certificate in
/// `credential`, the MLS identity of a member, as validated when its leaf
/// joined the group (RCC.16 section 9.1.1)
pub fn credential_tel_uris(credential: &Credential) -> Result<Vec<String>> {
    let chain = certificate_chain(credential)?;
    tel_uris(chain.first().ok_or(CertificateError::Malformed)?)
}

/// Whether the tel URIs `uri` and `expected` are of the same number
pub fn same_tel_uri(uri: &str, expected: &str) -> bool {
    let number = |s: &str| {
        s.strip_prefix("tel:")
            .or_else(|| s.strip_prefix("TEL:"))
            .unwrap_or(s)
            .to_string()
    };
    number(uri) == number(expected)
}

/// Verifies the Participant signature and key rolls (A.4.1.1 1c), returning the
/// asserted Vendor ID and the Participant Key
pub(super) fn check_participant_information(
    leaf: &Certificate,
    now: SystemTime,
) -> Result<(u64, Vec<u8>)> {
    let value = raw_extension(leaf, PARTICIPANT_INFORMATION)
        .ok_or(CertificateError::ParticipantInformation)?;
    let info = ParticipantInformation::from_der(value)
        .map_err(|_| CertificateError::ParticipantInformation)?;

    check_lifetime(&info.participant_signature_validity, CLIENT_MAX_LIFETIME)?;
    check_time(&info.participant_signature_validity, now)?;

    let tbs_participant_info = tbs_participant_info(leaf, &info)?;
    let subject_public_key_info = &leaf.tbs_certificate.subject_public_key_info;
    let participant_key = info
        .participant_key
        .as_ref()
        .unwrap_or(subject_public_key_info);
    check_client_key(participant_key)?;

    verify(
        participant_key,
        &info.participant_signature_algorithm,
        &tbs_participant_info,
        info.participant_signature_value.raw_bytes(),
    )
    .map_err(|_| CertificateError::ParticipantInformation)?;

    // each older key vouches for the key that replaced it
    let mut newer = participant_key;
    for roll in info.participant_key_rolls.iter().flatten() {
        check_client_key(&roll.old_participant_key)?;
        let newer_der = newer.to_der().map_err(|_| CertificateError::Malformed)?;
        verify(
            &roll.old_participant_key,
            &roll.participant_roll_signature_algorithm,
            &newer_der,
            roll.participant_roll_signature_value.raw_bytes(),
        )
        .map_err(|_| CertificateError::ParticipantInformation)?;
        newer = &roll.old_participant_key;
    }

    let participant_key = participant_key
        .to_der()
        .map_err(|_| CertificateError::Malformed)?;

    Ok((to_u64(&info.vendor_id)?, participant_key))
}

/// tbsParticipantInfo ::= SEQUENCE { subject, vendorId, participantSignatureValidity,
/// subjectPublicKeyInfo, subjectAltName }, from the fields of the certificate
fn tbs_participant_info(leaf: &Certificate, info: &ParticipantInformation) -> Result<Vec<u8>> {
    let subject_alt_name =
        raw_extension(leaf, SubjectAltName::OID).ok_or(CertificateError::Identity)?;

    encode_tbs_participant_info(
        &leaf.tbs_certificate.subject,
        &info.vendor_id,
        &info.participant_signature_validity,
        &leaf.tbs_certificate.subject_public_key_info,
        subject_alt_name,
    )
}

/// tbsParticipantInfo, `subject_alt_name` being the DER encoded GeneralNames
fn encode_tbs_participant_info(
    subject: &Name,
    vendor_id: &Uint,
    validity: &Validity,
    subject_public_key_info: &SubjectPublicKeyInfoOwned,
    subject_alt_name: &[u8],
) -> Result<Vec<u8>> {
    let mut content = Vec::new();
    subject
        .encode_to_vec(&mut content)
        .and_then(|_| vendor_id.encode_to_vec(&mut content))
        .and_then(|_| validity.encode_to_vec(&mut content))
        .and_then(|_| subject_public_key_info.encode_to_vec(&mut content))
        .map_err(|_| CertificateError::Malformed)?;
    content.extend_from_slice(subject_alt_name);

    let mut tbs = Header::new(
        Tag::Sequence,
        Length::try_from(content.len()).map_err(|_| CertificateError::Malformed)?,
    )
    .and_then(|header| header.to_der())
    .map_err(|_| CertificateError::Malformed)?;
    tbs.extend_from_slice(&content);
    Ok(tbs)
}

fn verify_certificate(
    certificate: &Certificate,
    issuer_key: &SubjectPublicKeyInfoOwned,
) -> Result<()> {
    let tbs = certificate
        .tbs_certificate
        .to_der()
        .map_err(|_| CertificateError::Malformed)?;
    verify(
        issuer_key,
        &certificate.signature_algorithm,
        &tbs,
        certificate.signature.raw_bytes(),
    )
}

/// ECDSA with the hash matching the curve, as the profiles of Annex A require
fn verify(
    key: &SubjectPublicKeyInfoOwned,
    algorithm: &AlgorithmIdentifierOwned,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    if algorithm.parameters.is_some() {
        return Err(CertificateError::UnsupportedAlgorithm);
    }

    let point = key.subject_public_key.raw_bytes();
    let verified = match (curve(key)?, algorithm.oid) {
        (SECP256R1, ECDSA_WITH_SHA256) => {
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
                .map_err(|_| CertificateError::Malformed)?;
            let signature = p256::ecdsa::Signature::from_der(signature)
                .map_err(|_| CertificateError::BadSignature)?;
            key.verify(message, &signature).is_ok()
        }
        (SECP384R1, ECDSA_WITH_SHA384) => {
            let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(point)
                .map_err(|_| CertificateError::Malformed)?;
            let signature = p384::ecdsa::Signature::from_der(signature)
                .map_err(|_| CertificateError::BadSignature)?;
            key.verify(message, &signature).is_ok()
        }
        (SECP521R1, ECDSA_WITH_SHA512) => {
            let key = p521::ecdsa::VerifyingKey::from_sec1_bytes(point)
                .map_err(|_| CertificateError::Malformed)?;
            let signature = p521::ecdsa::Signature::from_der(signature)
                .map_err(|_| CertificateError::BadSignature)?;
            key.verify(message, &signature).is_ok()
        }
        _ => return Err(CertificateError::UnsupportedAlgorithm),
    };

    if verified {
        Ok(())
    } else {
        Err(CertificateError::BadSignature)
    }
}

fn to_u64(value: &Uint) -> Result<u64> {
    let bytes = value.as_bytes();
    if bytes.len() > 8 {
        return Err(CertificateError::VendorId);
    }
    Ok(bytes.iter().fold(0, |n, b| n << 8 | *b as u64))
}
