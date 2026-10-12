# kinship-net

The tokio UDP and TCP driver for [kinship-core](https://crates.io/crates/kinship-core), the sans-IO SWIM and Lifeguard state machine.

One actor task owns the protocol node and feeds it every datagram, stream frame, timer expiry and command. Handles talk to it over a channel, read membership from a snapshot it publishes after every change, and receive events through bounded per-subscription queues that never make it wait.

Most users want the [`kinship`](https://crates.io/crates/kinship) crate, which wraps this driver as `Cluster` with a builder for the configuration.

Licensed under Apache-2.0 or MIT, at your option.
