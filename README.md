# rust-rcs-core
Core libraries that provide basic RCS capabilities.

This library itself should prove a suitable base for building a SIP/RCS client. It is used by rust-rcs-client to create a functional RCS client under areas that had neccessary network support.

### What's Missing

SIP sessions and MSRP had not gone through any testing and we should re-work FFI functions since they are heavily Android-biased now.

Also, some code are half way through the sync-async conversion and require clean ups.

### End-to-End Encryption (Universal Profile 3.0)

The `e2ee` feature adds the `mls` module, an MLS (RFC 9420) engine built on OpenMLS that covers identities, KeyPackages, group lifecycle, message protection and state persistence. It needs rustc 1.91 or newer.

Groups are set up as GSMA PRD RCC.16 (v4.0) requires: Era extension, Commits and Proposals as PublicMessages, Welcomes without ratchet tree, past epochs kept until pruned, PADME padding. `mls::rcs` adds what RCC.16 and RCC.07 (v15.0) define on top:

- content types, CPIM headers, SIP headers, capability feature tags, ACS parameters, extension and proposal code points (including the range reserved for future use, which KeyPackages advertise), unencrypted CPIM header rules, failure reasons
- the TLS structures (SecretPayload, AuthenticatedData with its Verifiable* content, Re-Sent Message, Commit and Proposal lists, commitments) and protobuf messages (FileInfo, `message/mls-rcs-client`, `message/mls-rcs-server` with AcceptedMlsRcsMessage, MlsEnhancedGroupInfo, EndMlsMetadata)
- encrypted CPIM messages bound to their Message-ID, signed IMDNs (`rcs_signature`), Commit bundles for the Conversation Focus, Commits applied once accepted, moving to unencrypted (`end_mls` with its reason), self-healing through External Commits
- file, thumbnail, icon and subject encryption (Annex C.2, C.3)
- Client Certificate validation (Annex A.4.1): `RcsCredentialValidator` checks X.509 credentials against the agreed roots, the certificate profiles, the ParticipantInformation signature and key rolls, and the Vendor ID, and applies the rules for KDS query results, additions and certificate updates. Revocation of intermediate CAs is checked through a callback, fetching CRLs is left to the caller.
- Re-Sent Messages after a Fail to Decrypt (sections 10.3, 10.4, Annex C.4): the Original Message is sealed with HPKE to the leaf key of the client that failed, then encrypted to the group with its HMAC, which the members that decrypted the Original Message check with `resent_matches()`. 1-to-1 group ids are GUIDs in 32 hex digits so they fill `group_id[32]` as they are; other group ids are hashed with SHA-256 to fit, which RCC.16 does not define. A Re-Sent Message can only be read with the leaf key it was sealed to, so before a key update of the receiver.
- the failure reasons of Negative-Delivery IMDNs (section 7.7.2), which are also how an FTD is sent: reading the server or client reason out of an IMDN, and building the `<status>` of a client generated one
- encrypted group icon and subject, the continuity token and the recovery of their keys (sections 7.11.3 to 7.11.12, 7.13.4, 8.3.1, 9.7.1, 10.5): setting and deleting the icon and subject, their keys and the continuity token in Welcomes, the commitment to the token in every GroupInfo, asking for and sending missing keys, and checking the token against a GroupInfo of the Conversation Focus. The keys and the token are kept per group id and carry over from one Era to the next.

Where RCC.16 v4.0 is silent or contradicts itself, this library:

- numbers VerifiableDerivedContentType, which has no code points, in the order of its select: none 0, delivery_imdn 1, display_imdn 2, resent_message 3
- signs IMDNs with an AuthenticatedData carrying the Verifiable* content, as the illustration of section 7.5.3.3 shows, and lays out VerifiableDeliveryImdn and VerifiableDisplayImdn as section 7.5.3.2 does rather than as sections 7.6.3.2 and 7.6.3.3 still do
- keeps the v3.0 values of failed_to_decrypt (4) and of the delivery and display statuses the enums of v4.0 leave out, and recognises every spelling of the inner Re-Sent Message failure
- fills the key_generation of SecretPayloads by counting the messages it encrypted in the epoch, but does not check it on receipt, as OpenMLS does not tell the generation of a received message
- still checks the file_length_hint of Annex C.3 when present, though v4.0 dropped it from FileEncryptionInfo
- applies a Commit of its own when the Conversation Focus accepts it, and also takes it being delivered back, as sections 6.2.4 and 9.5.1 differ on which happens
- puts the commitments, the keys and the continuity token in extension_data as they are, without a further length prefix, and the icon key, like the subject key, as a FileInfo with its field set (section 9.7.1.1.2 has a bare FileMetadata, which is accepted too)
- computes the continuity token commitment as RFC 9420's RefHash with the label as given, "Continuity Token GroupInfo Commitment"
- does not check the Message-ID bound to a PrivateMessage bundled with a Commit, as the CPIM message the Conversation Focus delivers it in is not known

OpenMLS puts the same extensions in the GroupInfo of a Welcome and in the one for the Conversation Focus, and has no way to encrypt in the epoch a pending Commit leads to. The GroupInfo for the Conversation Focus and a bundled PrivateMessage are therefore made on a copy of the client with the Commit applied; once the Commit is applied for real, the key generations the copy used are skipped. Commit bundles with more than one message are tried out on a copy too, so that they apply whole or not at all.

Not covered yet:

- asking for group metadata keys within the External Commit of a self-heal or the GroupInfo of a new Era (section 10.5.2); `request_group_metadata_keys()` makes a Commit of its own. `GroupMetadataKeys` is cut off in RCC.16 v4.0 and taken to end after its two fields; `GroupMetadataKeysRequested` is not defined, and not sent.
- the XML of CPM group data requests and of conference-info NOTIFYs for the encrypted subject and icon (section 7.13)
- enhanced self-healing from an MlsEnhancedGroupInfo (section 10.1.2)
- the `self_remove` and `server_remove` proposals: OpenMLS knows SelfRemove only under its IETF code, not RCC.16's 0xF003, and cannot apply proposal types it doesn't know. Leaving still uses a Remove proposal, which a Conversation Focus following v4.0 refuses (section 6.2.3).
- the identity verification code (Annex C.5): `HASH_TO_DIGITS` is not defined
- the interface to the KDS, which RCC.16 leaves vendor specific

### FAQ

Q: Why are you re-writing so many basic things like HTTP, why not use genuine, proven Libraries like reqwest?

A: Well, the GBA algorithm dictates that we know the cipher-suite used in the underlying ssl connection before calculating the credentials for the Authorization header, this function I could not find in any of the popular HTTP libraries at the time of writing.

Q: Why use Rust? Isn't Java a more suitable choice if your code is going to run mostly on mobile devices?

A: First of all, I had already written an Android RCS library for my company but that is proprietary. Secondly, Rust is fun. And it forces you to be clear on what you are writing, which is perfect for protocols and stuff.

### Note

Part of the code were written when I was fairly new with the Rust programming language. I expect those would need serious overhaul to look decent.
