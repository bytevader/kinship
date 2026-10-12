# kinship-core

The sans-IO SWIM and Lifeguard protocol state machine behind [kinship](https://crates.io/crates/kinship).

`Node` is the whole protocol with no sockets, clock, threads or randomness of its own. A driver feeds it datagrams, stream events, timer expiries and commands, each with the current instant, and then drains what it should send, what the application should hear and when to wake it next. The same seed, nonce key and inputs always give the same outputs, byte for byte, which is what lets kinship's simulator replay any run from its seed.

Use this crate to drive the protocol from your own runtime or event loop. For a tokio cluster handle, use [`kinship`](https://crates.io/crates/kinship). The design is described in [docs/design.md](https://github.com/bytevader/kinship/blob/main/docs/design.md).

Licensed under Apache-2.0 or MIT, at your option.
