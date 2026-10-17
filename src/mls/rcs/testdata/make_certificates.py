#!/usr/bin/env python3
# Generates the certificate fixtures of src/mls/rcs/testdata/certificates.rs
#
# An implementation of the certificate profiles of GSMA RCC.16 v3.0 Annex A that is
# independent from the Rust code validating them. Needs the `cryptography` package:
#
#     python3 make_certificates.py > certificates.rs && rustfmt --edition 2021 certificates.rs

import datetime
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID, ObjectIdentifier

RCS_E2EE = "2.23.146.2.1"
CLIENT_IDENTIFIER = ObjectIdentifier(RCS_E2EE + ".1")
POLICY = ObjectIdentifier(RCS_E2EE + ".2")
KP_RCS_MLS_CLIENT = ObjectIdentifier(RCS_E2EE + ".3")
PARTICIPANT_INFORMATION = ObjectIdentifier(RCS_E2EE + ".4")
ACS_PARTICIPANT_INFORMATION = ObjectIdentifier(RCS_E2EE + ".5")
VENDOR_ID = ObjectIdentifier(RCS_E2EE + ".6")

ECDSA_WITH_SHA256 = bytes.fromhex("300a06082a8648ce3d040302")


def der(tag, content):
    length = len(content)
    if length < 0x80:
        header = bytes([length])
    else:
        encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
        header = bytes([0x80 | len(encoded)]) + encoded
    return bytes([tag]) + header + content


def integer(value):
    return der(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big"))


def utc_time(t):
    return der(0x17, t.strftime("%y%m%d%H%M%SZ").encode())


def validity(not_before, not_after):
    return der(0x30, utc_time(not_before) + utc_time(not_after))


def spki(key):
    return key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def sign(key, message):
    return key.sign(message, ec.ECDSA(hashes.SHA256()))


def bit_string(data):
    return der(0x03, b"\x00" + data)


def day(text):
    return datetime.datetime.fromisoformat(text).replace(tzinfo=datetime.timezone.utc)


def ca_name(common_name):
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Vendor"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def root(name, key, vendor_id):
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(day("2025-01-01"))
        .not_valid_after(day("2034-12-01"))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(ca_key_usage(), True)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .add_extension(x509.UnrecognizedExtension(VENDOR_ID, integer(vendor_id)), False)
        .sign(key, hashes.SHA384())
    )


def ca_key_usage():
    return x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )


def intermediate(name, key, issuer, issuer_key):
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(day("2025-06-01"))
        .not_valid_after(day("2029-06-01"))
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(ca_key_usage(), True)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        [x509.UniformResourceIdentifier("http://crl.example.com/ca.crl")],
                        None,
                        None,
                        None,
                    )
                ]
            ),
            False,
        )
        .add_extension(x509.ExtendedKeyUsage([KP_RCS_MLS_CLIENT]), False)
        .sign(issuer_key, hashes.SHA384())
    )


def client(
    key,
    issuer,
    issuer_key,
    tel,
    not_before,
    not_after,
    vendor_id=42,
    participant_key=None,
    old_participant_keys=(),
    extended_key_usage=(KP_RCS_MLS_CLIENT,),
    unknown_critical=False,
):
    subject = x509.Name([x509.NameAttribute(CLIENT_IDENTIFIER, str(uuid.uuid4()))])
    san = x509.SubjectAlternativeName([x509.UniformResourceIdentifier(tel)])
    signature_validity = validity(not_before, not_after)

    # Annex A.3.8.9: the Participant Key signs fields of the certificate itself
    signer = participant_key or key
    tbs_participant_info = der(
        0x30,
        subject.public_bytes()
        + integer(vendor_id)
        + signature_validity
        + spki(key)
        + san.public_bytes(),
    )
    participant_information = (
        integer(vendor_id)
        + signature_validity
        + ECDSA_WITH_SHA256
        + bit_string(sign(signer, tbs_participant_info))
    )
    if participant_key is not None:
        participant_information += spki(participant_key)
    if old_participant_keys:
        rolls = b""
        newer = signer
        for older in old_participant_keys:
            rolls += der(
                0x30, ECDSA_WITH_SHA256 + bit_string(sign(older, spki(newer))) + spki(older)
            )
            newer = older
        participant_information += der(0xA0, rolls)

    builder = x509.CertificateBuilder()
    if unknown_critical:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.4.1.99999.1"), der(0x05, b"")),
            True,
        )

    return (
        builder
        .subject_name(subject)
        .issuer_name(issuer.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            True,
        )
        .add_extension(x509.CertificatePolicies([x509.PolicyInformation(POLICY, None)]), False)
        .add_extension(san, False)
        .add_extension(x509.ExtendedKeyUsage(list(extended_key_usage)), False)
        .add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.CA_ISSUERS,
                        x509.UniformResourceIdentifier("http://ca.example.com/ca.crt"),
                    )
                ]
            ),
            False,
        )
        .add_extension(
            x509.UnrecognizedExtension(
                PARTICIPANT_INFORMATION, der(0x30, participant_information)
            ),
            True,
        )
        .add_extension(
            x509.UnrecognizedExtension(ACS_PARTICIPANT_INFORMATION, der(0x04, b"acs proof")),
            False,
        )
        .sign(issuer_key, hashes.SHA256())
    )


def certificate_hex(certificate):
    return certificate.public_bytes(serialization.Encoding.DER).hex()


def private_hex(key):
    return key.private_numbers().private_value.to_bytes(32, "big").hex()


def public_hex(key):
    return key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    ).hex()


root_key = ec.generate_private_key(ec.SECP384R1())
root_certificate = root(ca_name("Example RCS E2EE Root"), root_key, 42)
ca_key = ec.generate_private_key(ec.SECP256R1())
ca_certificate = intermediate(ca_name("Example RCS E2EE CA"), ca_key, root_certificate, root_key)

other_root_key = ec.generate_private_key(ec.SECP384R1())
other_root_certificate = root(ca_name("Untrusted Root"), other_root_key, 42)
other_ca_key = ec.generate_private_key(ec.SECP256R1())
other_ca_certificate = intermediate(
    ca_name("Untrusted CA"), other_ca_key, other_root_certificate, other_root_key
)

ALICE = "tel:+491701234567"
BOB = "tel:+491707654321"
SEPTEMBER = day("2026-09-01")
NOVEMBER = day("2026-11-01")

alice_key = ec.generate_private_key(ec.SECP256R1())
alice_participant_key = ec.generate_private_key(ec.SECP256R1())
alice = client(alice_key, ca_certificate, ca_key, ALICE, SEPTEMBER, NOVEMBER,
               participant_key=alice_participant_key)

alice_renewed_key = ec.generate_private_key(ec.SECP256R1())
alice_renewed = client(alice_renewed_key, ca_certificate, ca_key, ALICE, day("2026-10-01"),
                       day("2026-12-01"), participant_key=alice_participant_key)

bob_key = ec.generate_private_key(ec.SECP256R1())
older_participant_keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(2)]
bob = client(bob_key, ca_certificate, ca_key, BOB, SEPTEMBER, NOVEMBER,
             old_participant_keys=older_participant_keys)

mallory_key = ec.generate_private_key(ec.SECP256R1())
mallory = client(mallory_key, other_ca_certificate, other_ca_key, ALICE, SEPTEMBER, NOVEMBER)

server_auth = client(ec.generate_private_key(ec.SECP256R1()), ca_certificate, ca_key, ALICE,
                     SEPTEMBER, NOVEMBER,
                     extended_key_usage=(x509.ExtendedKeyUsageOID.SERVER_AUTH,))
other_vendor = client(ec.generate_private_key(ec.SECP256R1()), ca_certificate, ca_key, ALICE,
                      SEPTEMBER, NOVEMBER, vendor_id=7)
unknown_critical = client(ec.generate_private_key(ec.SECP256R1()), ca_certificate, ca_key,
                          ALICE, SEPTEMBER, NOVEMBER, unknown_critical=True)
long_lived = client(ec.generate_private_key(ec.SECP256R1()), ca_certificate, ca_key, ALICE,
                    SEPTEMBER, day("2026-11-20"))

print("// Generated by make_certificates.py, do not edit")
print()
for name, value in [
    ("ROOT", certificate_hex(root_certificate)),
    ("CA", certificate_hex(ca_certificate)),
    ("OTHER_ROOT", certificate_hex(other_root_certificate)),
    ("OTHER_CA", certificate_hex(other_ca_certificate)),
    ("ALICE", certificate_hex(alice)),
    ("ALICE_KEY", private_hex(alice_key)),
    ("ALICE_PUBLIC_KEY", public_hex(alice_key)),
    ("ALICE_RENEWED", certificate_hex(alice_renewed)),
    ("ALICE_RENEWED_KEY", private_hex(alice_renewed_key)),
    ("ALICE_RENEWED_PUBLIC_KEY", public_hex(alice_renewed_key)),
    ("BOB", certificate_hex(bob)),
    ("BOB_KEY", private_hex(bob_key)),
    ("BOB_PUBLIC_KEY", public_hex(bob_key)),
    ("MALLORY", certificate_hex(mallory)),
    ("MALLORY_KEY", private_hex(mallory_key)),
    ("MALLORY_PUBLIC_KEY", public_hex(mallory_key)),
    ("SERVER_AUTH", certificate_hex(server_auth)),
    ("OTHER_VENDOR", certificate_hex(other_vendor)),
    ("LONG_LIVED", certificate_hex(long_lived)),
    ("UNKNOWN_CRITICAL", certificate_hex(unknown_critical)),
]:
    print(f'pub const {name}: &str = "{value}";')
