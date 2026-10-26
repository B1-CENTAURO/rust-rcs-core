# rust-rcs-core
Core libraries that provide basic RCS capabilities.

This library itself should prove a suitable base for building a SIP/RCS client. It is used by rust-rcs-client to create a functional RCS client under areas that had neccessary network support.

### What's Missing

SIP sessions had not gone through any testing and we should re-work FFI functions since they are heavily Android-biased now.

MSRP is tested in `src/msrp/tests.rs` (wire format, chunking, reports, sessions over an in-memory connection, SDP), and against msrplib, AG Projects' implementation, in `tests/msrp_interop.rs`: both ways of connecting, chunked messages, success REPORTs and refusals; see `interop/README.md`. A failure REPORT fails the session, as RFC 4975 section 7.3.2 requires: every message on it ends with the REPORT's status, `MsrpDemuxer::session_failure` tells it, and sending again takes negotiating a new session. That goes too for a failure REPORT on one of the last 1024 messages that ended, as a gateway may send after accepting all of a message. For the passive side, `MsrpChannelManager::accept` takes connections the remote end opens; listening for them is left to the caller. For CEMA (RFC 6714), `MsrpInfo` reads and writes `a=msrp-cema`. `MsrpInfo::connection_address` gives the address a `socket_factory` should connect to: the remote c= address and m= port when this end's SDP carries `a=msrp-cema`, the remote `a=path` otherwise. `MsrpInfo::connection_matches_path` compares the two (section 4.4), so that the caller can reject an offer, or offer again without CEMA, when a middlebox that does not do CEMA rewrote c= and m= (sections 4.2 and 4.3); when either side is a domain name, telling takes DNS, which is left to the caller. MSRP relays (RFC 4976: AUTH, Use-Path, a shared connection to the relay) are not supported, by choice: RCS over IMS does not use them, as the network anchors MSRP at its border elements instead (CEMA, above). Paths of several URIs, as a peer behind a relay may give, are still parsed and routed (responses go to the first hop, sessions are matched on the endpoints), but this has not been tried with a relay.

Also, some code are half way through the sync-async conversion and require clean ups.

### End-to-End Encryption (Universal Profile 3.0)

The `e2ee` feature adds the `mls` module, an MLS (RFC 9420) engine built on OpenMLS that covers identities, KeyPackages, group lifecycle, message protection and state persistence. It needs rustc 1.91 or newer.

OpenMLS 0.9.1 is vendored under `vendor/openmls` with two changes for RCC.16 (see `vendor/openmls/VENDORED.md`): its SelfRemove proposal goes by 0xF003, the code RCC.16 gives `self_remove`, instead of the 0x000a of draft-ietf-mls-extensions, and it knows `server_remove` (0xF004), a Remove by another name that External Commits may carry next to their one Remove.

Groups are set up as GSMA PRD RCC.16 (v4.0) requires: Era extension, Commits and Proposals as PublicMessages, Welcomes without ratchet tree, past epochs kept until pruned, PADME padding. `mls::rcs` adds what RCC.16 and RCC.07 (v15.0) define on top:

- content types, CPIM headers, SIP headers, capability feature tags, ACS parameters, extension and proposal code points (including the range reserved for future use, which KeyPackages advertise), unencrypted CPIM header rules, failure reasons
- the TLS structures (SecretPayload, AuthenticatedData with its Verifiable* content, Re-Sent Message, Commit and Proposal lists, commitments) and protobuf messages (FileInfo, `message/mls-rcs-client`, `message/mls-rcs-server` with AcceptedMlsRcsMessage, MlsEnhancedGroupInfo, EndMlsMetadata)
- encrypted CPIM messages bound to their Message-ID, signed IMDNs (`rcs_signature`), Commit bundles for the Conversation Focus, Commits applied once accepted, moving to unencrypted (`end_mls` with its reason), self-healing through External Commits
- leaving with `self_remove` Proposals (sections 6.2.3, 7.11.8, 9.4), which other members commit and External Commits cover when pending; the ProposalList for the leaving BYE (section 7.9.4), and withdrawing the Proposal again when the Conversation Focus refuses the leave, as OpenMLS makes no Commit while its own `self_remove` is pending; `leaving_members()` tells whose `self_remove` is pending, for the committer to remove the other Clients of their Participants in the same Commit
- `server_remove` Proposals (sections 7.11.9, 9.6, 10.1.1): removing the Clients of a Participant the Messaging Server removed, and self-healing with an External Commit that takes out several old Clients, e.g. those of a former Participant Key
- enhanced self-healing (sections 6.3.2, 7.10, 10.1.2): the MLS-Enhanced-Group-Info-Pull request, applying the control messages of the response page by page, and telling when to fall back to an External Commit. Commits and Proposals handled before, through it or otherwise, come out as `Duplicate` when delivered again.
- when a key update is due (section 9.5.2): `key_update_due()` applies the intervals of Table 7, the initial ones after joining with a last resort KeyPackage, counting the messages this client encrypted since its leaf was last updated, by creating or joining the group, a Commit of its own with an UpdatePath, or an External Commit. The client tells the time by the system clock, or by one given with `MlsClient::set_clock()`.
- certificate updates (section 9.5.3): `MlsClient::renew()` takes on a renewed certificate and its signature key. Each group goes on signing with the key of the client's leaf in it until `update_keys()` brings the new ones into the group, signing that Commit with the former key; `key_update_due()` asks for that key update at once.
- KeyPackage updates of other members (section 9.5.4): `stale_members()` lists the Clients whose certificate expired or no longer passes the validator otherwise, and those whose leaf keys this client first saw over 30 days ago; `replace_members()` removes their leaves and adds the KeyPackages the Home KDS returned for their Participants, leaving out those of Clients that stay and of this client, with a Welcome for the Clients added. A Client replaced joins again with that Welcome through `join_conversation()`, which takes the place of its group.
- new Eras (section 8.3): `EraBase` is what the next Era is made from, the GroupInfo of the Conversation Focus or the group of this client, and `continuity_holds()` tells whether the continuity token carries over (section 8.3.1.2), comparing Participants and members by MSISDN. `MlsClient::create_next_era()` makes the next Era in place of the group of the Era before, with the GroupContext extensions of the base. `join_conversation()` takes the place of a group still active for a Welcome of a later Era. Asking the members for a continuity token this client does not have (section 8.3.1.3) is not done.
- file, thumbnail, icon and subject encryption (Annex C.2, C.3)
- Client Certificate validation (Annex A.4.1): `RcsCredentialValidator` checks X.509 credentials against the agreed roots, the certificate profiles, the ParticipantInformation signature and key rolls, and the Vendor ID, and applies the rules for KDS query results, additions and certificate updates. Revocation of intermediate CAs is checked through a callback, fetching CRLs is left to the caller.
- the Participant Key (sections 3.1, 4.1, Annex A.3.8.9): `ParticipantKey` gives the `participant_public_key` of the configuration request, and signs the ParticipantInformation of the Client Certificate the Home KDS is to issue, for the Client ID, Vendor ID, MLS signature key and tel URIs the certificate will carry, valid from an hour before for 76 days
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
- the identity verification code (Annex C.5): `HASH_TO_DIGITS` is not defined
- the interface to the KDS, which RCC.16 leaves vendor specific

### FAQ

Q: Why are you re-writing so many basic things like HTTP, why not use genuine, proven Libraries like reqwest?

A: Well, the GBA algorithm dictates that we know the cipher-suite used in the underlying ssl connection before calculating the credentials for the Authorization header, this function I could not find in any of the popular HTTP libraries at the time of writing.

Q: Why use Rust? Isn't Java a more suitable choice if your code is going to run mostly on mobile devices?

A: First of all, I had already written an Android RCS library for my company but that is proprietary. Secondly, Rust is fun. And it forces you to be clear on what you are writing, which is perfect for protocols and stuff.

### Note

Part of the code were written when I was fairly new with the Rust programming language. I expect those would need serious overhaul to look decent.
