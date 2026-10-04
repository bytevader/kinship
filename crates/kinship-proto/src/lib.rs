//! Wire types, binary codec and AEAD framing for kinship.
//!
//! This crate is the only place bytes are turned into protocol messages and back. It is sans-IO:
//! no sockets, no clock, no randomness (callers supply nonces), and no allocation while decoding.
//! The decoder works on borrowed slices, checks every length against the bytes that remain and
//! never panics, whatever it is fed.
//!
//! * [`Codec`] seals messages into packets and opens packets into a [`Payload`].
//! * [`FrameReader`] splits a TCP byte stream into packets.
//! * [`tags`] defines the metadata tag encoding carried in [`Alive::meta`].
//!
//! The format is specified in `docs/design.md`, section "Wire format".

mod error;
mod limits;
mod message;
mod packet;
mod stream;
pub mod tags;
mod wire;

pub use error::{ConfigError, DecodeError, EncodeError};
pub use limits::Limits;
pub use message::{
    Alive, Dead, Message, Messages, NodeId, Payload, Ping, PingReq, PushPull, Record, RecordIter,
    Records, State, Suspect, kind,
};
pub use packet::{
    Codec, ENCRYPTED_HEADER_LEN, ENCRYPTED_OVERHEAD, Key, MAGIC, MAX_LABEL_LEN, NONCE_LEN,
    PLAINTEXT_HEADER_LEN, PacketKind, TAG_LEN, WIRE_VERSION,
};
pub use stream::FrameReader;
