"""Shared guards.

Every piece of DocVault that touches the filesystem, builds a query or opens an
outbound connection goes through one of the helpers below. They are deliberately
boring and deliberately central: if you are writing a new endpoint and you find
yourself joining paths with ``/`` or formatting a value into SQL, you are meant
to reach for something here instead.

- filesystem  -> :func:`ensure_within`, :func:`sanitize_filename`
- SQL         -> :func:`validate_sort_column`, :func:`validate_identifier`
                 (and ``db.query`` / ``db.execute``, which only take bound params)
- outbound    -> :func:`validate_outbound_url`
"""
from __future__ import annotations

import ipaddress
import re
import socket
import unicodedata
from pathlib import Path
from urllib.parse import urlsplit

from .config import OUTBOUND_HOST_ALLOWLIST

#: Characters we are willing to keep in a name that becomes a filename.
_FILENAME_OK = re.compile(r"[^A-Za-z0-9._-]+")
_IDENTIFIER_OK = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

ALLOWED_SCHEMES = ("http", "https")


class SecurityError(Exception):
    """A request asked for something outside a boundary. Callers map this to 400."""


def ensure_within(root: Path, *parts: str) -> Path:
    """Join ``parts`` onto ``root`` and return the result only if it stays inside.

    This is the one supported way to turn request-supplied text into a path.
    ``resolve()`` is applied to both sides so that ``..`` segments, absolute
    components and symlinks that point out of the tree are all caught by the
    same containment check.

    Raises:
        SecurityError: if the resulting path escapes ``root``.
    """
    root = Path(root).resolve()
    candidate = Path(root).joinpath(*parts)
    resolved = candidate.resolve()
    if not resolved.is_relative_to(root):
        raise SecurityError(f"path escapes storage root: {candidate!s}")
    return resolved


def sanitize_filename(name: str, fallback: str = "document") -> str:
    """Reduce arbitrary text to a single safe path component.

    Used for names that end up in ``Content-Disposition`` or as the leaf of a
    generated export. It never returns something containing a separator, so the
    result is safe to hand to :func:`ensure_within` as a single part.
    """
    name = unicodedata.normalize("NFKD", name or "").encode("ascii", "ignore").decode()
    name = _FILENAME_OK.sub("_", name).strip("._")
    name = name[:120]
    return name or fallback


def validate_tool_argument(value: str) -> str:
    """Return ``value`` if it is safe to place in a subprocess argument list.

    An argv list stops the shell from seeing the value, but it does not stop the
    *tool* from seeing it: ``convert`` and ``soffice`` both read an argument
    beginning with ``-`` as an option, so a stored name of ``-write`` would
    become a flag. Empty strings are refused for the same reason.
    """
    if not isinstance(value, str) or not value:
        raise SecurityError("empty subprocess argument")
    if value.startswith("-"):
        raise SecurityError(f"subprocess argument would be read as an option: {value!r}")
    return value


def validate_identifier(name: str) -> str:
    """Return ``name`` if it is a bare SQL identifier, else raise.

    Only for places where a column or table name genuinely has to be inlined.
    Values never go through here -- values are bound parameters.
    """
    if not _IDENTIFIER_OK.match(name or ""):
        raise SecurityError(f"not an identifier: {name!r}")
    return name


def validate_sort_column(column: str, allowed: tuple[str, ...]) -> str:
    """Return a column name chosen from a fixed allowlist.

    ``ORDER BY`` cannot be a bound parameter, so sort columns are matched
    against the caller's own allowlist rather than escaped.
    """
    if column not in allowed:
        raise SecurityError(f"unsupported sort column: {column!r}")
    return validate_identifier(column)


def validate_sort_direction(direction: str) -> str:
    d = (direction or "asc").lower()
    if d not in ("asc", "desc"):
        raise SecurityError(f"unsupported sort direction: {direction!r}")
    return d.upper()


def _is_internal_address(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return True
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            return True
    return False


def validate_outbound_url(url: str, *, resolve_dns: bool = True) -> str:
    """Return ``url`` if the service is allowed to open a connection to it.

    Three checks, in order: the scheme must be http(s), the host must be on
    :data:`config.OUTBOUND_HOST_ALLOWLIST`, and (unless disabled for tests) the
    host must not resolve to a private, loopback or link-local address. The
    allowlist is the load-bearing one; the DNS check is defence in depth for an
    allowlisted name that has been repointed inwards.

    Raises:
        SecurityError: if any check fails.
    """
    parts = urlsplit(url or "")
    if parts.scheme not in ALLOWED_SCHEMES:
        raise SecurityError(f"unsupported scheme: {parts.scheme!r}")
    host = (parts.hostname or "").lower()
    if host not in OUTBOUND_HOST_ALLOWLIST:
        raise SecurityError(f"host not on outbound allowlist: {host!r}")
    if resolve_dns and _is_internal_address(host):
        raise SecurityError(f"host resolves to an internal address: {host!r}")
    return url
