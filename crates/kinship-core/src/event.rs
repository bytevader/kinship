//! Commands the application gives the core, and events the core reports back.

use core::fmt;
use core::net::SocketAddr;

use kinship_proto::Key;

use crate::member::Member;

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
    /// Push-pull with every seed, retrying failed ones with backoff until one answers. This
    /// node's own address is skipped, so a node may list itself among its seeds.
    Join { seeds: Vec<SocketAddr> },
    /// Gossip that this node left, and stop probing. Done once the news has been sent as often
    /// as any rumour is, or at once if no other member is alive.
    Leave,
    /// Replace this node's metadata, at most `max_meta_bytes`.
    SetMeta(Vec<u8>),
    /// Let this node decrypt with `key`, as well as the keys it has. Does nothing if it is
    /// already installed. Acts on this node only.
    InstallKey(Key),
    /// Encrypt with the installed `key` from now on; every installed key still decrypts.
    UseKey(Key),
    /// Forget `key`. Refused for the key in use and for the last key; does nothing if it is not
    /// installed.
    RemoveKey(Key),
}

/// What a [`Command`] that succeeded produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub enum CommandOutput {
    /// The command took effect.
    Done,
    /// A join finished, and this many seeds answered (zero if every seed was this node).
    Joined { seeds: usize },
}

/// Why a [`Command`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub enum CommandError {
    /// Metadata is larger than `max_meta_bytes`.
    MetaTooLarge,
    /// No seed answered after `join_retries` attempts each.
    JoinFailed,
    /// This node has left the cluster.
    Left,
    /// A key command on a node that runs without encryption.
    NotEncrypted,
    /// [`Command::UseKey`] for a key that is not installed.
    KeyNotInstalled,
    /// [`Command::RemoveKey`] for the key this node encrypts with.
    KeyInUse,
    /// [`Command::RemoveKey`] for the only installed key.
    LastKey,
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MetaTooLarge => f.write_str("metadata larger than max_meta_bytes"),
            Self::JoinFailed => f.write_str("no seed answered"),
            Self::Left => f.write_str("this node has left the cluster"),
            Self::NotEncrypted => f.write_str("this node runs without encryption and has no keys"),
            Self::KeyNotInstalled => f.write_str("key is not installed"),
            Self::KeyInUse => f.write_str("key is the one in use"),
            Self::LastKey => f.write_str("key is the last one installed"),
        }
    }
}

impl std::error::Error for CommandError {}

/// Something the application should hear about. Member events never describe the local node;
/// [`NameConflict`](Self::NameConflict) may.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub enum Event {
    /// A [`Command`] finished.
    CommandDone {
        id: CommandId,
        result: Result<CommandOutput, CommandError>,
    },
    /// A node is alive that was unknown, dead or left.
    MemberJoined(Member),
    /// A node missed its probes and is suspected.
    MemberSuspect(Member),
    /// A suspect node refuted the suspicion and is alive again.
    MemberRecovered(Member),
    /// A suspicion expired without a refutation.
    MemberDead(Member),
    /// A node left on purpose.
    MemberLeft(Member),
    /// A node changed its metadata.
    MemberUpdated {
        member: Member,
        previous_meta: Vec<u8>,
    },
    /// A node at `other_addr` claims the name of `member`, which keeps it.
    NameConflict {
        member: Member,
        other_addr: SocketAddr,
    },
}
