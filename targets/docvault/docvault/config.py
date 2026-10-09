"""Runtime configuration for DocVault.

Everything is read from the environment once, at import time, so that the rest of
the service can treat these as constants. Defaults are development defaults.
"""
from __future__ import annotations

import os
from pathlib import Path

#: Root of all tenant document storage. Nothing may be read or written outside it.
STORAGE_ROOT = Path(os.environ.get("DOCVAULT_STORAGE", "./var/storage")).resolve()

#: Where generated exports (CSV, PDF, thumbnails) are written before download.
EXPORT_ROOT = Path(os.environ.get("DOCVAULT_EXPORTS", "./var/exports")).resolve()

#: SQLite database file.
DB_PATH = Path(os.environ.get("DOCVAULT_DB", "./var/docvault.db")).resolve()

#: Hosts that outbound HTTP (webhook delivery, logo import) is allowed to reach.
#: Anything not on this list is refused before a connection is opened.
OUTBOUND_HOST_ALLOWLIST = tuple(
    h.strip().lower()
    for h in os.environ.get(
        "DOCVAULT_OUTBOUND_HOSTS",
        # The last entry is the staging stand-in, and is the only one of the
        # three that resolves outside the corporate network.
        "hooks.internal.example.com,cdn.internal.example.com,example.com",
    ).split(",")
    if h.strip()
)

#: Maximum size of an uploaded document, in bytes.
MAX_UPLOAD_BYTES = int(os.environ.get("DOCVAULT_MAX_UPLOAD", 20 * 1024 * 1024))

#: Seconds before an outbound HTTP call is abandoned.
OUTBOUND_TIMEOUT = float(os.environ.get("DOCVAULT_OUTBOUND_TIMEOUT", 5.0))

#: Seconds before a conversion subprocess is killed.
CONVERT_TIMEOUT = float(os.environ.get("DOCVAULT_CONVERT_TIMEOUT", 60.0))

#: Service log, tailed by the admin health endpoint.
LOG_PATH = Path(os.environ.get("DOCVAULT_LOG", "./var/docvault.log")).resolve()

#: Where the nightly diagnostics job drops its dumps, in dated subdirectories.
DIAGNOSTICS_ROOT = Path(os.environ.get("DOCVAULT_DIAGNOSTICS", "./var/diagnostics")).resolve()


def ensure_dirs() -> None:
    for d in (STORAGE_ROOT, EXPORT_ROOT, DIAGNOSTICS_ROOT, DB_PATH.parent, LOG_PATH.parent):
        d.mkdir(parents=True, exist_ok=True)
