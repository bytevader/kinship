# Stage 1 implementation notes

Stage 1 adds identity primitives and an explicitly selected version 2 codec.
The runtime continues to advertise and emit version 1. Identity enforcement,
negotiation, runtime replay policy, bindings and operator tools remain planned
for an opt-in release after 1.0. KI-01 remains Accepted.

Implementation sequence: pin the canonical grammar and replay bindings; add
identity tests and primitives; add version 2 message and packet tests and codecs;
extend compatibility and fuzz coverage; run the proto, core and simulator suites,
formatting, clippy, dependency policy and available MSRV/fuzz checks.

The implementation uses ed25519-dalek **3.0.0**, pinned exactly, with its default
`fast` and `zeroize` features. No RNG, batch verification, hazmat or legacy
compatibility feature is enabled. The selected curve25519-dalek 5.0.0, sha2
0.11.0, digest 0.11.3, ed25519 3.0.0 and signature 3.0.0 all declare Rust 1.85.
Cargo's resolver selected sha2 0.11.0 because 0.11.1 requires Rust 1.88. The lock
file retains that compatible selection. The dependency audit uses the same
`cargo deny check advisories bans sources` command as CI; licenses are
BSD-3-Clause for the dalek crates and MIT/Apache-2.0 for the other additions.

## Canonical grammar and replay bindings

This supplements the accepted design; it does not enable identities. Integers
are big endian and lengths/counts use the existing minimal u32 varint. Names
retain NodeId's exact UTF-8 bytes. No Unicode normalization is performed.

- A signing key is a 32-byte RFC 8032 seed. Public keys must decompress, use a
  canonical field encoding, and not have small order. Verification always uses
  `verify_strict`; batch and legacy compatibility features are not enabled.
- The signature preimage is the eleven ASCII bytes `kinship v2 `, one binary message
  type byte, the eight-byte cluster-label hash, then the canonical body preceding
  the signature. Message count, type/length framing and packet version are not
  signed. This permits unchanged proofs in both upgrade envelopes. Certificate
  bodies include their own version byte (1). Revocations have no version byte,
  matching the proposed 88-byte format; their cluster is in the signature domain.
- Certificates use `[not_before, not_after)` in Unix seconds, with caller-supplied
  skew and saturating arithmetic. Empty/reversed intervals are invalid. An issuer
  id is a routing hint: all matching anchors are tried, never just the first one.
  Certificate ids hash the complete canonical body including the signature.
  Revocations must match the certificate's issuer, id and exact not_after, and
  verify under the same CA and cluster. The codec does not maintain revocation or
  certificate caches. Equal not_before renewals require an operator to issue a
  strictly later certificate; runtime renewal selection remains Stage 4.
- Epochs and accusation `at` are u64 milliseconds. Certificates use seconds.
  Epoch fields are always present in v2, including zero (unknown); refusing an
  identity without an epoch belongs to runtime configuration, not the codec.
  An accusation's `at` is checked against the receiver's existing replay floor in
  Stage 3; the codec neither reads time nor changes that floor. A Left is ordered
  by epoch/incarnation rather than expired as a third-party accusation.
- Ping appends source_epoch, a 16-byte probe challenge, a boolean requester-present byte, and, if present,
  requester name, epoch and original probe sequence. PingReq appends requester
  name, epoch and the same 16-byte challenge. Ack appends target_epoch, requester
  name and epoch, target name, challenge, certificate id and signature. Its leading
  seq is the original requester's sequence, including through relays. Nack appends
  relay name and epoch, requester name and epoch, target name, challenge,
  certificate id and signature. These explicit names remove ambiguity when two
  requesters use the same sequence or a relay uses its own local sequence. A
  relay forwards the Ack unchanged and correlates by the complete probe binding.
  The challenge always belongs to the original requester's round; the relay
  passes it unchanged even when it uses a local sequence for its Ping. This
  expands the sketch's probe size estimates; Stage 2 must remeasure them.
- Every member-signed statement includes its certificate id immediately before
  its signature. Alive already does so; Suspect/Dead append at, certificate id
  and signature; user messages and broadcasts append certificate id and signature.
  Ack/Nack also carry this id. This resolves the sketch's omitted fields in favor
  of its explicit certificate-specific authorization rule: a same-key renewal
  must not make a statement under the previous certificate current again.
  Direct-message
  preimages additionally append the packet's exact 24-byte nonce after the body;
  callers must supply it. Select the nonce before signing and use the same nonce
  when sealing. Other statements reject a supplied nonce to avoid accidental
  domain mismatches. Nonce generation is independent of the payload today.
  Stage 2 must suppress repeated identical direct-message proofs within one
  packet: a key holder can reseal an unseen nonce with duplicate copies, and the
  packet replay set alone cannot suppress those. This needs no runtime change
  in Stage 1 and does not change the accepted nonce binding.
- A push-pull record starts with state and the *original*, unmodified Alive body,
  certificate id and Alive signature. Suspect/Dead append the claimed incarnation.
  Left appends left incarnation, at, Left certificate id and Left signature.
  Keeping a separate left
  incarnation permits forwarding a Left newer than the last signed Alive without
  forging an Alive. Its proof reconstructs Dead with node == from. The extra Left
  fields total 84 bytes rather than the sketch's 72. State and suspected
  incarnation are the peer's unsigned claims, never independent signed reporters.
- PushPull appends a count and certificate ids known by the requester. Certificate
  and Revocation messages travel alongside PushPull in the same TCP payload;
  they need no second nested encoding. Their ordering is preserved, not sorted.
- Known v2 bodies and records reject trailing bytes and truncated signatures.
  Encoding rejects any body or aggregate payload larger than a u32 length before
  allocating output, with checked sizing on 32-bit hosts as well.
  Unknown message types remain skippable. Future signed-field extensions need a
  new grammar so different implementations cannot sign different interpretations.
  IPv6 scope/flow information has no wire representation and is refused on v2
  encoding instead of silently disappearing.

## API isolation

`kinship_proto::WIRE_VERSION` is the highest codec version (2).
`DEFAULT_WIRE_VERSION` stays 1. The core re-exports the default as WIRE_VERSION,
so Rust facade/Python reporting and Alive version ranges stay unchanged.
Existing `Codec::seal`, `seal_stream_frame`, `seal_raw`, `open` and header checks
remain version 1. Separate v2 message/payload types and explicit v2 entry points
avoid dropping a proof through a legacy Message. The v2 sealer requires a chosen
envelope version (1 for upgrade compatibility or 2); the v2 opener validates the
strict v2 grammar in either envelope. A separate versioned opener distinguishes
ordinary v1 from v2 by the envelope version: a version 1 envelope is decoded as
legacy v1 and skips appended proofs. Use `open_v2` when expecting v2 bodies in a
version 1 upgrade envelope. Neither opener verifies statement signatures automatically.

The released 0.4.0 proto is a dev-dependency from a different source with the same
package name/version. Use `cargo test --manifest-path crates/kinship-proto/Cargo.toml`
to select this crate unambiguously. Workspace-wide commands are unchanged.

## Probe freshness decision

The original Ack binding lacked an unpredictable round challenge. With unsigned
Pings and predictable sequences, a key holder can ask a live target for signed
Acks to future rounds and replay them after it crashes. The operator decision
was accepted by Nikola on 2026-10-16: add a fresh 128-bit challenge to every probe
path and cover it in signed replies. The codec carries this field; Stage 2 must
draw it from a cryptographically secure per-node source, independently for each
round, use it across direct/indirect/TCP paths, and require an exact match before
accepting an Ack or Nack. The ordinary protocol-choice RNG and predictable
sequence numbers are unsuitable. The regression uses a harvested Ack with the
same requester, epochs, target and future sequence but a different challenge;
the signature cannot answer the fresh round. No core probe behavior changes in
Stage 1 and no v2 traffic is enabled by this implementation.

## Partition-heal review

At origin/main edd204a the fix/partition-heal-flap branch is unmerged, with no
committed core change. Its current reproduction and tools are read-only inputs
to this work. V1 accusation semantics remain unchanged. V2 carries a signed at
and preserves original Alive proofs independently of a peer's Suspect/Dead
claim, supporting the accepted Stage 3 confirmation rule and KP-05. Stage 3 must
rerun the final partition-heal regression in require mode once that fix exists.

## Validation (2026-10-17)

- `cargo test --manifest-path crates/kinship-proto/Cargo.toml --locked`: 108 tests
  passed, including RFC 8032 vectors, invalid certificates, canonicalization,
  challenge replay binding, oversized-body rejection and released-0.4 compatibility.
- `cargo test --workspace --exclude kinship-py --locked`: passed, including core,
  simulator and the pinned version 1 SWIM trace. Deliberately ignored tests,
  including the KI-01 reproduction and long simulator sweeps, remain ignored.
- `cargo fmt --all --check` and the fuzz manifest's formatting check passed.
  `cargo clippy --workspace --all-targets --locked -- -D warnings` passed.
- `cargo +1.85 check --workspace --locked` passed with the selected dependency
  graph and features, including the bindings crate.
- `cargo deny check advisories bans sources` passed. The duplicate-syn warning
  (2.0.119 and 3.0.6) is already present in origin/main's dependency graph.
- All four proto targets passed nightly libFuzzer smoke runs under WSL Ubuntu:
  `decode_payload` (762,310 executions), `decode_datagram` (70,823),
  `decode_stream_frame` (198,361) and `decode_certificate` (145,400). Each used
  `-max_total_time=60 -max_len=8192`, with mutable corpora and artifacts isolated
  under the ignored target directory. The fuzz crate does not build on Windows.
- Independent final source/security review completed with no outstanding findings.

Git stores LF text blobs; working copies use CRLF with core.autocrlf=true.
The four binary corpus seeds retain their exact bytes in the index.
