"""Shared request-validation helpers; every route funnels untrusted values through these."""
import os
from urllib.parse import urlparse

ALLOWED_HOSTS = {"reports.internal", "docs.internal"}


def validated_path(base, name):
    real = os.path.realpath(os.path.join(str(base), name))
    if not real.startswith(os.path.realpath(str(base)) + os.sep):
        raise ValueError(f"path escapes {base}")
    return real


def validated_url(url):
    parts = urlparse(url)
    if parts.scheme not in ("http", "https") or parts.hostname not in ALLOWED_HOSTS:
        raise ValueError("url host is not allowlisted")
    return url
