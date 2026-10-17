# kinship-proto

Wire types, binary codec and AEAD framing for [kinship](https://crates.io/crates/kinship), SWIM membership and failure detection with Lifeguard.

This crate is the only place kinship turns bytes into protocol messages and back. It is sans-IO: no sockets, no clock and no randomness (callers supply nonces). The decoder works on borrowed slices, checks every length against the bytes that remain and never panics, whatever it is fed. Packets are sealed with XChaCha20-Poly1305 and bound to the cluster label.

Most users want the [`kinship`](https://crates.io/crates/kinship) crate instead. The format is specified in [docs/design.md](https://github.com/bytevader/kinship/blob/main/docs/design.md#wire-format).

Licensed under Apache-2.0 or MIT, at your option.

Experimental Stage 1 identity support lives in `identity` and `v2`. It provides
Ed25519 keys, certificates, revocations and a canonical v2 grammar; it does not
enable runtime identities or verify statements when opening packets. Existing
`Codec::seal`, `open`, stream framing and header checks keep version 1 behavior.
Use `seal_v2` with an explicit `WireVersion`, `open_v2` for strict v2 bodies in
either upgrade envelope. `open_versioned` selects its grammar by envelope version;
its v1 decoder skips appended proofs, so use `open_v2` for v2-in-v1 upgrades.
`WIRE_VERSION` is the highest codec version (2); `DEFAULT_WIRE_VERSION` is 1.
The runtime's exported wire version remains 1. The full opt-in feature is planned
after 1.0 and KI-01 remains Accepted. Exact fields and remaining work are in
[the Stage 1 notes](https://github.com/bytevader/kinship/blob/main/docs/ki01-stage1.md).
