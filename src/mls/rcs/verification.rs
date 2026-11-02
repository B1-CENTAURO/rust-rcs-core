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

//! The identity verification code of a pair of Participants, which their
//! users compare (RCC.16 section 5.5, Annex C.5)
//!
//! Annex C.5 hashes the two Participants, each its MSISDN and Participant
//! Key, with SHA-512, then calls HASH_TO_DIGITS(80, hash), which it leaves
//! undefined. Its pseudo-code also sorts the Participants descending, where
//! its struct says ascending. This module takes:
//! - the Participants ascending by MSISDN, as the struct says, compared byte
//!   by byte;
//! - the MSISDN as the UTF-8 E.164 number with its leading `+`;
//! - the Participant Key as its DER encoded SubjectPublicKeyInfo, as Client
//!   Certificates carry it (Annex A.3.8.9);
//! - the 80 digits as the 64 bytes of the hash read as one big-endian
//!   integer, reduced modulo 10^80, zero-padded on the left.

use sha2::{Digest, Sha512};
use tls_codec::{Serialize as _, TlsSerialize, TlsSize, VLByteSlice};

use super::super::{fail, ErrorKind, Result};

/// How many digits the code has
pub const CODE_DIGITS: usize = 80;

/// A Participant whose identity is verified
#[derive(Clone, Copy, Debug)]
pub struct VerifiedParticipant<'a> {
    /// Its MSISDN, the E.164 number with its leading `+`
    pub msisdn: &'a str,
    /// Its Participant Key, as a DER encoded SubjectPublicKeyInfo
    pub participant_key: &'a [u8],
}

#[derive(TlsSerialize, TlsSize)]
struct User<'a> {
    msisdn: VLByteSlice<'a>,
    participant_identity_public_key: VLByteSlice<'a>,
}

/// The User of `participant`
fn user<'a>(participant: &VerifiedParticipant<'a>) -> User<'a> {
    User {
        msisdn: VLByteSlice(participant.msisdn.as_bytes()),
        participant_identity_public_key: VLByteSlice(participant.participant_key),
    }
}

#[derive(TlsSerialize, TlsSize)]
struct UserPairKeys<'a> {
    first_user: User<'a>,
    second_user: User<'a>,
}

/// The identity verification code of `a` and `b`, as both of their users are
/// shown it, whichever is given first: CODE_DIGITS decimal digits (Annex C.5)
///
/// Fails with BadFormat for an MSISDN not an E.164 number with its `+`, or a
/// Participant Key that is empty.
pub fn identity_verification_code(
    a: &VerifiedParticipant,
    b: &VerifiedParticipant,
) -> Result<String> {
    for participant in [a, b] {
        let digits = participant.msisdn.strip_prefix('+').unwrap_or_default();
        if digits.is_empty()
            || !digits.bytes().all(|b| b.is_ascii_digit())
            || participant.participant_key.is_empty()
        {
            return Err(ErrorKind::BadFormat);
        }
    }

    // ascending by MSISDN
    let (first, second) = match b.msisdn.as_bytes() < a.msisdn.as_bytes() {
        true => (b, a),
        false => (a, b),
    };
    let pair = UserPairKeys {
        first_user: user(first),
        second_user: user(second),
    }
    .tls_serialize_detached()
    .map_err(fail("UserPairKeys encoding", ErrorKind::BadFormat))?;

    Ok(hash_to_digits(CODE_DIGITS, &Sha512::digest(&pair)))
}

/// `hash` read as one big-endian integer, reduced modulo 10^`digit_count`,
/// in decimal, zero-padded on the left to `digit_count` digits
fn hash_to_digits(digit_count: usize, hash: &[u8]) -> String {
    // the integer in base 10^9, least significant limb first
    const BASE: u64 = 1_000_000_000;
    let mut limbs: Vec<u64> = Vec::new();
    for byte in hash {
        let mut carry = u64::from(*byte);
        for limb in limbs.iter_mut() {
            let value = *limb * 256 + carry;
            *limb = value % BASE;
            carry = value / BASE;
        }
        while carry > 0 {
            limbs.push(carry % BASE);
            carry /= BASE;
        }
    }

    let mut decimal: String = limbs
        .iter()
        .rev()
        .enumerate()
        .map(|(i, limb)| match i {
            0 => limb.to_string(),
            _ => format!("{:09}", limb),
        })
        .collect();
    if decimal.is_empty() {
        decimal.push('0');
    }
    match decimal.len() >= digit_count {
        true => decimal.split_off(decimal.len() - digit_count),
        false => format!("{:0>width$}", decimal, width = digit_count),
    }
}

#[cfg(test)]
mod tests {
    use super::{hash_to_digits, identity_verification_code, VerifiedParticipant, CODE_DIGITS};
    use crate::mls::ErrorKind;

    const ALICE: VerifiedParticipant = VerifiedParticipant {
        msisdn: "+491701234567",
        participant_key: b"alice's key",
    };
    const BOB: VerifiedParticipant = VerifiedParticipant {
        msisdn: "+491707654321",
        participant_key: b"bob's key",
    };

    #[test]
    fn the_hash_is_read_as_an_integer_modulo_10_to_the_digits() {
        assert_eq!(hash_to_digits(4, &[]), "0000");
        assert_eq!(hash_to_digits(4, &[0x01, 0x00]), "0256");
        assert_eq!(hash_to_digits(3, &[0x01, 0x00]), "256");
        assert_eq!(hash_to_digits(2, &[0x01, 0x00]), "56");
        // 2^64 - 1, across limbs
        assert_eq!(hash_to_digits(20, &[0xff; 8]), "18446744073709551615");
        assert_eq!(hash_to_digits(10, &[0xff; 8]), "3709551615");
        // 10^9 exactly, a limb carried
        assert_eq!(
            hash_to_digits(12, &[0x3b, 0x9a, 0xca, 0x00]),
            "001000000000"
        );
        // 2^512 - 1, its last 80 digits
        assert_eq!(
            hash_to_digits(80, &[0xff; 64]),
            "73546976801874298166903427690031858186486050853753882811946569946433649006084095"
        );
    }

    #[test]
    fn the_code_is_the_same_whichever_participant_is_given_first() {
        let code = identity_verification_code(&ALICE, &BOB).unwrap();
        assert_eq!(code.len(), CODE_DIGITS);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
        assert_eq!(identity_verification_code(&BOB, &ALICE), Ok(code.clone()));
        // as computed apart (make_verification_vector.py)
        assert_eq!(
            code,
            "10228792907200051702399020311546714557220808115095806255028839405573025577758546"
        );

        // another for another key, or another number
        let other_key = VerifiedParticipant {
            participant_key: b"bob's other key",
            ..BOB
        };
        assert_ne!(
            identity_verification_code(&ALICE, &other_key),
            Ok(code.clone())
        );
        let other_number = VerifiedParticipant {
            msisdn: "+491707654320",
            ..BOB
        };
        assert_ne!(identity_verification_code(&ALICE, &other_number), Ok(code));
    }

    #[test]
    fn the_code_is_not_made_of_what_is_no_number_or_no_key() {
        for msisdn in ["491701234567", "+", "+49 170", "tel:+491701234567", ""] {
            let not_one = VerifiedParticipant { msisdn, ..ALICE };
            assert_eq!(
                identity_verification_code(&not_one, &BOB),
                Err(ErrorKind::BadFormat),
                "{}",
                msisdn
            );
            assert_eq!(
                identity_verification_code(&BOB, &not_one),
                Err(ErrorKind::BadFormat)
            );
        }
        let no_key = VerifiedParticipant {
            participant_key: b"",
            ..ALICE
        };
        assert_eq!(
            identity_verification_code(&no_key, &BOB),
            Err(ErrorKind::BadFormat)
        );
    }
}
