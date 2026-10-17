# rust-rcs-core
Core libraries that provide basic RCS capabilities.

This library itself should prove a suitable base for building a SIP/RCS client. It is used by rust-rcs-client to create a functional RCS client under areas that had neccessary network support.

### What's Missing

SIP sessions and MSRP had not gone through any testing and we should re-work FFI functions since they are heavily Android-biased now.

Also, some code are half way through the sync-async conversion and require clean ups.

### End-to-End Encryption (Universal Profile 3.0)

The `e2ee` feature adds the `mls` module, an MLS (RFC 9420) engine built on OpenMLS that covers identities, KeyPackages, group lifecycle, message protection and state persistence. It needs rustc 1.91 or newer.

What it does not cover yet is how MLS is applied within RCS, which GSMA PRD RCC.16 defines: Key Distribution Server interaction, how encrypted content is carried in CPIM / MSRP / File Transfer, message state signing and the certificate model. The `+g.gsma.rcs.mls.mls-version` capability indication is defined in GSMA PRD RCC.07 (v15.0 for UP 3.0).

### FAQ

Q: Why are you re-writing so many basic things like HTTP, why not use genuine, proven Libraries like reqwest?

A: Well, the GBA algorithm dictates that we know the cipher-suite used in the underlying ssl connection before calculating the credentials for the Authorization header, this function I could not find in any of the popular HTTP libraries at the time of writing.

Q: Why use Rust? Isn't Java a more suitable choice if your code is going to run mostly on mobile devices?

A: First of all, I had already written an Android RCS library for my company but that is proprietary. Secondly, Rust is fun. And it forces you to be clear on what you are writing, which is perfect for protocols and stuff.

### Note

Part of the code were written when I was fairly new with the Rust programming language. I expect those would need serious overhaul to look decent.
