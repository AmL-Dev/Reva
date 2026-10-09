from __future__ import annotations

import httpx
import pytest


def auth(key: str) -> dict:
    return {"X-API-Key": key}


@pytest.fixture()
def no_dns(monkeypatch):
    """The allowlisted example hosts do not resolve, so skip the DNS layer."""
    import docvault.security as security

    monkeypatch.setattr(security, "_is_internal_address", lambda host: False)
    return security


def test_read_webhook_shows_allowlist(client, member_key):
    r = client.get("/teams/me/webhook", headers=auth(member_key))
    assert r.status_code == 200
    assert "hooks.internal.example.com" in r.json()["allowed_hosts"]


def test_set_webhook_accepts_allowlisted_host(client, member_key, no_dns):
    r = client.put(
        "/teams/me/webhook",
        json={"url": "https://hooks.internal.example.com/team"},
        headers=auth(member_key),
    )
    assert r.status_code == 200


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:8080/admin",
        "https://attacker.example.net/collect",
        "file:///etc/passwd",
    ],
)
def test_set_webhook_rejects_everything_else(client, member_key, no_dns, url):
    r = client.put("/teams/me/webhook", json={"url": url}, headers=auth(member_key))
    assert r.status_code == 400


def test_delivery_is_checked_again_at_send_time(client, member_key, monkeypatch, no_dns):
    """A URL stored while allowlisted must still be refused once it is not."""
    import docvault.config as config
    import docvault.security as security
    from docvault.routers import webhooks

    client.put(
        "/teams/me/webhook",
        json={"url": "https://hooks.internal.example.com/team"},
        headers=auth(member_key),
    )
    monkeypatch.setattr(config, "OUTBOUND_HOST_ALLOWLIST", ("other.internal.example.com",))
    monkeypatch.setattr(security, "OUTBOUND_HOST_ALLOWLIST", ("other.internal.example.com",))

    called = []
    monkeypatch.setattr(webhooks.httpx, "post", lambda *a, **k: called.append(a) or None)
    r = client.post("/teams/me/webhook/test", json={"event": "ping"}, headers=auth(member_key))
    assert r.status_code == 502
    assert called == []

    deliveries = client.get("/teams/me/webhook/deliveries", headers=auth(member_key)).json()
    assert deliveries and "allowlist" in deliveries[0]["error"]


def test_delivery_does_not_follow_redirects(client, member_key, monkeypatch, no_dns):
    from docvault.routers import webhooks

    seen = {}

    def fake_post(url, **kwargs):
        seen.update(kwargs)
        seen["url"] = url
        return httpx.Response(200, request=httpx.Request("POST", url))

    client.put(
        "/teams/me/webhook",
        json={"url": "https://hooks.internal.example.com/team"},
        headers=auth(member_key),
    )
    monkeypatch.setattr(webhooks.httpx, "post", fake_post)
    r = client.post("/teams/me/webhook/test", json={"event": "report.published"}, headers=auth(member_key))
    assert r.status_code == 200
    assert seen["follow_redirects"] is False
    assert seen["url"] == "https://hooks.internal.example.com/team"


def test_logo_import_requires_admin(client, member_key, no_dns):
    r = client.post(
        "/teams/me/logo",
        json={"url": "https://cdn.internal.example.com/logo.png"},
        headers=auth(member_key),
    )
    assert r.status_code == 403


def test_logo_import_rejects_non_allowlisted_host(client, admin_key, no_dns):
    r = client.post(
        "/teams/me/logo",
        json={"url": "http://169.254.169.254/latest/meta-data/"},
        headers=auth(admin_key),
    )
    assert r.status_code == 400


def test_logo_is_stored_inside_storage_root(client, env, admin_key):
    from docvault.routers.integrations import store_logo

    key = store_logo(1, "image/png", b"\x89PNG")
    assert key == "1/branding/logo.png"
    assert (env.STORAGE_ROOT / key).is_file()
