"""kinship: SWIM membership and failure detection with Lifeguard.

Every node knows which peers are alive, suspect, dead or gone, with no coordinator. The protocol
runs in Rust on its own thread, so a blocked event loop or a long GIL hold never makes a healthy
node look dead. See ``kinship.Cluster`` to start, and ``kinship.blocking`` for sync code.
"""

from kinship import blocking, rendezvous
from kinship._cluster import Cluster, EventStream, Keyring
from kinship._errors import (
    ConfigError,
    JoinError,
    KeyringError,
    KinshipClosed,
    KinshipError,
    MessageTooLarge,
    MetaTooLarge,
    NotAMember,
)
from kinship._kinship import Config, __version__, wire_version
from kinship._logging import log_to_python
from kinship._types import (
    Event,
    EventsLost,
    Member,
    MemberDead,
    MemberJoined,
    MemberLeft,
    MemberRecovered,
    MemberSuspect,
    MemberUpdated,
    NameConflict,
    State,
    Stats,
    UserMessage,
)

__all__ = [
    "Cluster",
    "Config",
    "ConfigError",
    "Event",
    "EventStream",
    "EventsLost",
    "JoinError",
    "Keyring",
    "KeyringError",
    "KinshipClosed",
    "KinshipError",
    "Member",
    "MemberDead",
    "MemberJoined",
    "MemberLeft",
    "MemberRecovered",
    "MemberSuspect",
    "MemberUpdated",
    "MessageTooLarge",
    "MetaTooLarge",
    "NameConflict",
    "NotAMember",
    "State",
    "Stats",
    "UserMessage",
    "__version__",
    "blocking",
    "log_to_python",
    "rendezvous",
    "wire_version",
]
