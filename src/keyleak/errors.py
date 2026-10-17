"""User-facing errors.

Anything that inherits from KeyleakError is printed as a short message by the CLI and
turned into a non-zero exit code. No stack trace is shown unless --debug is set.
"""

from __future__ import annotations


class KeyleakError(Exception):
    """Base class for errors that should be shown to the user as a plain message."""

    exit_code = 2


class InvalidKeyId(KeyleakError):
    """The thing passed as an access key ID does not look like one."""


class PermissionDenied(KeyleakError):
    """The caller's own credentials lack a permission keyleak needs."""


class CredentialsProblem(KeyleakError):
    """No usable credentials, or they are expired or invalid."""


class ConfirmationRequired(KeyleakError):
    """A command that changes the account was run without --confirm."""


class RefusedLeakedKey(KeyleakError):
    """The caller tried to run keyleak WITH the leaked key as its own credentials."""


class NothingToReport(KeyleakError):
    """report was asked to run before investigate or sweep saved anything."""
