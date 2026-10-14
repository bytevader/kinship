"""Exceptions raised by kinship. The Rust extension raises these classes by name."""

from __future__ import annotations


class KinshipError(Exception):
    """Base class of every kinship exception."""


class ConfigError(KinshipError, ValueError):
    """A config field holds an unusable value. ``field`` names it."""

    def __init__(self, message: str, field: str | None = None) -> None:
        super().__init__(message)
        self.field = field


class MetaTooLarge(KinshipError, ValueError):
    """Encoded metadata is larger than ``max_meta_bytes`` (512 by default)."""


class MessageTooLarge(KinshipError, ValueError):
    """A message is larger than ``max_user_message`` (64 KiB by default), or a broadcast than
    ``max_user_broadcast`` (256 bytes)."""


class NotAMember(KinshipError, LookupError):
    """``send()`` to a name this node does not hold as a live member at that epoch: one it does
    not know, one that died or left, a run that has since restarted, or this node itself."""


class JoinError(KinshipError):
    """``join()`` reached no seed."""


class KinshipClosed(KinshipError):
    """The cluster is closed, stopped on an internal error, or was created in another process."""


class KeyringError(KinshipError):
    """A keyring change was refused: the key is not installed, is in use, is the last one, or
    the node runs without encryption."""
