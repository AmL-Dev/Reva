from __future__ import annotations


def auth(key: str) -> dict:
    return {"X-API-Key": key}


def test_healthz_is_public(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_list_requires_api_key(client):
    assert client.get("/reports").status_code == 401
    assert client.get("/reports", headers=auth("nope")).status_code == 401


def test_list_is_scoped_to_team(client, member_key, other_team_key):
    mine = client.get("/reports", headers=auth(member_key)).json()
    theirs = client.get("/reports", headers=auth(other_team_key)).json()
    assert {r["team_id"] for r in mine} == {1}
    assert {r["team_id"] for r in theirs} == {2}


def test_filters_are_bound_parameters(client, member_key):
    r = client.get("/reports", params={"status": "draft"}, headers=auth(member_key))
    assert r.status_code == 200
    assert all(x["status"] == "draft" for x in r.json())

    injected = client.get("/reports", params={"status": "draft' OR '1'='1"}, headers=auth(member_key))
    assert injected.status_code == 200
    assert injected.json() == []


def test_sort_allowlist(client, member_key):
    ok = client.get("/reports", params={"sort": "title", "direction": "asc"}, headers=auth(member_key))
    assert ok.status_code == 200
    titles = [r["title"] for r in ok.json()]
    assert titles == sorted(titles)

    bad = client.get("/reports", params={"sort": "title); DROP TABLE reports --"}, headers=auth(member_key))
    assert bad.status_code == 400

    # The table survived the attempt.
    assert client.get("/reports", headers=auth(member_key)).status_code == 200


def test_published_feed_is_public(client):
    r = client.get("/reports/published")
    assert r.status_code == 200
    assert all(x["status"] == "published" for x in r.json())
    assert len(r.json()) == 2

    scoped = client.get("/reports/published", params={"team": "finance"})
    assert [x["team_id"] for x in scoped.json()] == [2]


def test_crud_roundtrip(client, member_key):
    created = client.post("/reports", json={"title": "New review", "summary": "s"}, headers=auth(member_key))
    assert created.status_code == 201
    rid = created.json()["id"]

    patched = client.patch(f"/reports/{rid}", json={"status": "review"}, headers=auth(member_key))
    assert patched.status_code == 200
    assert patched.json()["status"] == "review"

    assert client.delete(f"/reports/{rid}", headers=auth(member_key)).status_code == 204
    assert client.get(f"/reports/{rid}", headers=auth(member_key)).status_code == 404


def test_cannot_read_another_teams_report(client, member_key):
    assert client.get("/reports/4", headers=auth(member_key)).status_code == 404


def test_admin_only_endpoints(client, member_key, admin_key):
    assert client.get("/admin/audit", headers=auth(member_key)).status_code == 403
    assert client.get("/admin/audit", headers=auth(admin_key)).status_code == 200


def test_admin_endpoints(client, admin_key):
    assert client.get("/admin/storage", headers=auth(admin_key)).status_code == 200
    assert client.get("/admin/log", headers=auth(admin_key)).status_code == 200

    index = client.get("/admin/diagnostics/index", headers=auth(admin_key))
    assert index.status_code == 200
    assert "2026-10-08/queues.json" in index.json()

    dump = client.get("/admin/diagnostics", params={"name": "2026-10-08/queues.json"}, headers=auth(admin_key))
    assert dump.status_code == 200
    assert "convert" in dump.json()["content"]

    assert client.get("/admin/diagnostics", params={"name": "nope$"}, headers=auth(admin_key)).status_code == 400


def test_templates_roundtrip(client, admin_key):
    body = {"name": "Postmortem", "sections": ["Impact", "Timeline"], "default_status": "draft"}
    saved = client.put("/admin/templates/postmortem", json=body, headers=auth(admin_key))
    assert saved.status_code == 201
    got = client.get("/admin/templates/postmortem", headers=auth(admin_key))
    assert got.status_code == 200
    assert got.json()["sections"] == ["Impact", "Timeline"]
