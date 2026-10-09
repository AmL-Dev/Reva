from __future__ import annotations

import pytest


def test_ensure_within_accepts_contained_path(env):
    from docvault.security import ensure_within

    p = ensure_within(env.STORAGE_ROOT, "1", "report.pdf")
    assert p.is_relative_to(env.STORAGE_ROOT)


@pytest.mark.parametrize("part", ["../escape", "../../etc/passwd", "/etc/passwd", "a/../../b"])
def test_ensure_within_rejects_escapes(env, part):
    from docvault.security import SecurityError, ensure_within

    with pytest.raises(SecurityError):
        ensure_within(env.STORAGE_ROOT, part)


def test_ensure_within_rejects_symlink_escape(env, tmp_path):
    from docvault.security import SecurityError, ensure_within

    outside = tmp_path / "outside"
    outside.mkdir()
    link = env.STORAGE_ROOT / "link"
    link.symlink_to(outside)
    with pytest.raises(SecurityError):
        ensure_within(env.STORAGE_ROOT, "link", "secret.txt")


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("../../etc/passwd", "etc_passwd"),
        ("Q3 report.pdf", "Q3_report.pdf"),
        ("", "document"),
        ("....", "document"),
        ("a/b/c", "a_b_c"),
    ],
)
def test_sanitize_filename(env, raw, expected):
    from docvault.security import sanitize_filename

    assert sanitize_filename(raw) == expected


def test_validate_sort_column(env):
    from docvault.security import SecurityError, validate_sort_column

    assert validate_sort_column("title", ("id", "title")) == "title"
    with pytest.raises(SecurityError):
        validate_sort_column("title; DROP TABLE reports", ("id", "title"))


def test_validate_outbound_url_allows_allowlisted_host(env):
    from docvault.security import validate_outbound_url

    url = "https://hooks.internal.example.com/x"
    assert validate_outbound_url(url, resolve_dns=False) == url


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "https://evil.example.net/webhook",
        "file:///etc/passwd",
        "gopher://hooks.internal.example.com/",
        "http://localhost:8080/",
    ],
)
def test_validate_outbound_url_rejects(env, url):
    from docvault.security import SecurityError, validate_outbound_url

    with pytest.raises(SecurityError):
        validate_outbound_url(url, resolve_dns=False)
