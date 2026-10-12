# kinship-proto

Wire types, binary codec and AEAD framing for [kinship](https://crates.io/crates/kinship), SWIM membership and failure detection with Lifeguard.

This crate is the only place kinship turns bytes into protocol messages and back. It is sans-IO: no sockets, no clock and no randomness (callers supply nonces). The decoder works on borrowed slices, checks every length against the bytes that remain and never panics, whatever it is fed. Packets are sealed with XChaCha20-Poly1305 and bound to the cluster label.

Most users want the [`kinship`](https://crates.io/crates/kinship) crate instead. The format is specified in [docs/design.md](https://github.com/bytevader/kinship/blob/main/docs/design.md#wire-format).

Licensed under Apache-2.0 or MIT, at your option.
