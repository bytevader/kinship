//! Commands the application gives the core, and events the core reports back.

use core::fmt;
use core::net::SocketAddr;

/// Names one [`Command`], so its [`Event::CommandDone`] can be matched to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(transparent))]
pub struct CommandId(u64);

impl CommandId {
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn to_raw(self) -> u64 {
        self.0
    }
}

/// A request from the application.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Command {
    /// Exchange state with these seeds until one answers.
    Join { seeds: Vec<SocketAddr> },
    /// Announce departure and stop probing.
    Leave,
    /// Replace this node's metadata, at most `max_meta_bytes`.
    SetMeta(Vec<u8>),
}

/// Why a [`Command`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub enum CommandError {
    /// The command is not implemented by this version of the core.
    Unsupported,
    /// Metadata is larger than `max_meta_bytes`.
    MetaTooLarge,
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => f.write_str("command not supported yet"),
            Self::MetaTooLarge => f.write_str("metadata larger than max_meta_bytes"),
        }
    }
}

impl std::error::Error for CommandError {}

/// Something the application should hear about.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub enum Event {
    /// A [`Command`] finished.
    CommandDone {
        id: CommandId,
        result: Result<(), CommandError>,
    },
}
