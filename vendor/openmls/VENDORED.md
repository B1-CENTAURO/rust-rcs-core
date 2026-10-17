# OpenMLS 0.9.1, patched for RCC.16

This is the `openmls` crate, version 0.9.1, as published on crates.io by the
OpenMLS Authors under the MIT license (see `license` in `Cargo.toml` and
<https://github.com/openmls/openmls>). rust-rcs-core uses it in place of the
published crate through `[patch.crates-io]` in its own `Cargo.toml`.

## Why

GSMA PRD RCC.16 (v4.0) defines two proposals OpenMLS cannot express as is:

- `self_remove` (0xF003, section 7.11.8), with which members leave a group and
  the only kind of Proposal a Conversation Focus accepts (section 6.2.3).
  OpenMLS implements the same proposal, an empty SelfRemove struct that
  removes its sender and requires a path, but under the code of
  draft-ietf-mls-extensions, 0x000a, and offers no way to choose another.
- `server_remove` (0xF004, section 7.11.9), a Remove by another name: members
  commit it to remove the Clients of a Participant the Messaging Server
  removed (section 9.6), and External Commits carry it next to their single
  Remove to take out further old Clients (section 10.1.1). OpenMLS cannot
  apply proposal types it does not know.

## Changes

All marked with `rust-rcs-core` comments:

- `src/messages/proposals.rs`: `ProposalType::SelfRemove` maps to and from
  0xF003 instead of 0x000a, which turns 0x000a into a Custom proposal type.
  `ProposalType::ServerRemove` (0xF004) and `Proposal::ServerRemove`, laid out
  as a `RemoveProposal`, with `Proposal::server_remove()` to build one; path
  required; same priority as Remove when proposals for one leaf compete, and
  a SelfRemove keeps its priority over a later Remove.
- `src/messages/proposals_in.rs`, `src/messages/codec.rs`: the incoming
  variant and its encoding.
- `src/group/mls_group/proposal_store.rs`: ServerRemoves count as Removes in
  `remove_proposals()` (and so in `StagedCommit::remove_proposals()` and in the
  validation of Removes), in the check that a Commit does not remove its
  committer, and when filtering proposals for one leaf.
- `src/group/public_group/diff/apply_proposals.rs`: ServerRemoves blank their
  leaf, as Removes do.
- `src/group/public_group/validation.rs`: External Commits may carry inline
  ServerRemoves; the limit of one Remove stays.
- `src/group/public_group/mod.rs`, `src/messages/mod.rs`: a leaf freed by a
  ServerRemove counts when placing the joiner of an External Commit, on both
  the sending and the receiving side.
- `src/group/mls_group/commit_builder/external_commits.rs`:
  `ExternalCommitBuilder::with_removed_credentials()` removes the members
  holding the given credentials, the first with the Remove unless a member
  with the joiner's signature key takes it, the others with ServerRemoves.

Left out of the published package: `examples/`, `tests/` and `benches/`, and
their targets and the dev-dependencies in `Cargo.toml`. The test modules
inside `src` are kept, but only build under `cfg(test)` or the `test-utils`
feature.

## Updating

Copy `src`, `Cargo.toml` and `README.md` of the new version from crates.io,
remove the `[[example]]`, `[[test]]`, `[[bench]]` and dev-dependency sections
of `Cargo.toml`, and apply the changes above again. `diff -r` against the
published `src` should show only those changes.
