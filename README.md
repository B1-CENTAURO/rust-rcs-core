# rust-rcs-core
Core libraries that provide basic RCS capabilities.

This library itself should prove a suitable base for building a SIP/RCS client. It is used by rust-rcs-client to create a functional RCS client under areas that had neccessary network support.

### What's Missing

SIP sessions and MSRP had not gone through any testing and we should re-work FFI functions since they are heavily Android-biased now.

Also, some code are half way through the sync-async conversion and require clean ups.

### End-to-End Encryption (Universal Profile 3.0)

The `e2ee` feature adds the `mls` module, an MLS (RFC 9420) engine built on OpenMLS that covers identities, KeyPackages, group lifecycle, message protection and state persistence. It needs rustc 1.91 or newer.

Groups are set up as GSMA PRD RCC.16 (v3.0) requires: Era extension, Commits and Proposals as PublicMessages, past epochs kept until pruned, PADME padding. `mls::rcs` adds what RCC.16 and RCC.07 (v15.0) define on top:

- content types, CPIM headers, SIP headers, capability feature tags, ACS parameters, extension and proposal code points, unencrypted CPIM header rules, failure reasons
- the TLS structures (SecretPayload, AuthenticatedData, Verifiable* IMDN content, Commit and Proposal lists, commitments) and protobuf messages (FileInfo, `message/mls-rcs-client`, `message/mls-rcs-server`)
- encrypted CPIM messages bound to their Message-ID, signed IMDNs (`rcs_signature`), Commit bundles for the Conversation Focus, moving to unencrypted (`end_mls`), self-healing through External Commits
- file, thumbnail, icon and subject encryption (Annex C.2, C.3)

Not covered yet:

- validating Client Certificates (Annex A.4.1); a `CredentialValidator` has to be supplied
- Re-Sent Messages after a Fail to Decrypt (Annex C.4): the `group_id[32]` fields don't fit group ids of other lengths
- the identity verification code (Annex C.5): `HASH_TO_DIGITS` is not defined
- group icon and subject keys (section 9.7.1): RCC.16 puts them in GroupContext extensions while leaving them out of the GroupInfo, which the GroupInfo signature does not allow
- the `self_remove` and `server_remove` proposals: OpenMLS cannot apply proposal types it doesn't know; leaving uses a Remove proposal, which section 6.2.3 accepts
- the interface to the KDS, which RCC.16 leaves vendor specific

### FAQ

Q: Why are you re-writing so many basic things like HTTP, why not use genuine, proven Libraries like reqwest?

A: Well, the GBA algorithm dictates that we know the cipher-suite used in the underlying ssl connection before calculating the credentials for the Authorization header, this function I could not find in any of the popular HTTP libraries at the time of writing.

Q: Why use Rust? Isn't Java a more suitable choice if your code is going to run mostly on mobile devices?

A: First of all, I had already written an Android RCS library for my company but that is proprietary. Secondly, Rust is fun. And it forces you to be clear on what you are writing, which is perfect for protocols and stuff.

### Note

Part of the code were written when I was fairly new with the Rust programming language. I expect those would need serious overhaul to look decent.
