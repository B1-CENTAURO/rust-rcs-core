# OpenMLS 0.9.1, patched for RCC.16

This is the `openmls` crate, version 0.9.1, as published on crates.io by the
OpenMLS Authors under the MIT license (see `license` in `Cargo.toml` and
<https://github.com/openmls/openmls>). rust-rcs-core uses it in place of the
published crate through `[patch.crates-io]` in its own `Cargo.toml`.

## Why

GSMA PRD RCC.16 (v4.0, section 7.11.8) has members leave a group with a
`self_remove` proposal of type 0xF003, the only kind of Proposal a Conversation
Focus accepts (section 6.2.3). OpenMLS implements the same proposal, an empty
SelfRemove struct that removes its sender and requires a path, but under the
code of draft-ietf-mls-extensions, 0x000a, and offers no way to choose another.

## Changes

`src/messages/proposals.rs` maps `ProposalType::SelfRemove` to and from 0xF003
instead of 0x000a, which turns 0x000a into a Custom proposal type. Nothing else
in `src` differs from the published crate.

Left out of the published package: `examples/`, `tests/` and `benches/`, and
their targets and the dev-dependencies in `Cargo.toml`. The test modules
inside `src` are kept, but only build under `cfg(test)` or the `test-utils`
feature.

## Updating

Copy `src`, `Cargo.toml` and `README.md` of the new version from crates.io,
remove the `[[example]]`, `[[test]]`, `[[bench]]` and dev-dependency sections
of `Cargo.toml`, and apply the change above again. `diff -r` against the
published `src` should show only that change.
