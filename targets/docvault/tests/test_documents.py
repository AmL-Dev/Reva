from __future__ import annotations


def auth(key: str) -> dict:
    return {"X-API-Key": key}


def upload(client, key, filename, data=b"hello", content_type="text/plain", report_id=2):
    return client.post(
        f"/reports/{report_id}/documents",
        files={"file": (filename, data, content_type)},
        headers=auth(key),
    )


def test_upload_and_download(client, member_key):
    r = upload(client, member_key, "notes.txt")
    assert r.status_code == 201, r.text
    doc = r.json()
    assert doc["filename"] == "notes.txt"

    got = client.get(f"/documents/{doc['id']}/download", headers=auth(member_key))
    assert got.status_code == 200
    assert got.content == b"hello"


def test_traversal_filename_does_not_escape_storage(client, env, member_key):
    r = upload(client, member_key, "../../../../tmp/pwned.txt")
    assert r.status_code == 201

    stored = [p for p in env.STORAGE_ROOT.rglob("*") if p.is_file()]
    assert stored, "nothing was written"
    for p in stored:
        assert p.resolve().is_relative_to(env.STORAGE_ROOT)
    assert not (env.STORAGE_ROOT.parent / "tmp" / "pwned.txt").exists()
    # The display name is preserved verbatim in the database.
    assert r.json()["filename"] == "../../../../tmp/pwned.txt"


def test_stored_name_is_server_generated(client, env, member_key):
    upload(client, member_key, "report.pdf")
    names = [p.name for p in env.STORAGE_ROOT.rglob("*") if p.is_file()]
    assert len(names) == 1
    assert names[0].endswith(".pdf")
    assert names[0] != "report.pdf"
    assert len(names[0]) > 32


def test_document_access_is_team_scoped(client, member_key, other_team_key):
    doc_id = upload(client, member_key, "notes.txt").json()["id"]
    assert client.get(f"/documents/{doc_id}/download", headers=auth(other_team_key)).status_code == 404


def test_delete_document(client, env, member_key):
    doc_id = upload(client, member_key, "notes.txt").json()["id"]
    assert client.delete(f"/documents/{doc_id}", headers=auth(member_key)).status_code == 204
    assert not [p for p in env.STORAGE_ROOT.rglob("*") if p.is_file()]


def test_manifest_csv(client, member_key):
    upload(client, member_key, "a.txt")
    upload(client, member_key, "b.txt")
    r = client.get("/reports/2/manifest.csv", headers=auth(member_key))
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    body = r.text.splitlines()
    assert body[0] == "filename,content_type,size_bytes,uploaded_at"
    assert len(body) == 3


def test_write_export_contains_name(client, env, member_key):
    from docvault.routers.documents import write_export

    p = write_export(1, "../../escape.csv", b"x")
    assert p.resolve().is_relative_to(env.EXPORT_ROOT)
    assert p.name == "escape.csv"


def test_bundle_zip_members_are_flat(client, admin_key):
    import io
    import zipfile

    upload(client, admin_key, "../../etc/passwd", data=b"nope", report_id=1)
    r = client.get("/admin/reports/1/bundle", headers=auth(admin_key))
    assert r.status_code == 200
    with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
        for name in zf.namelist():
            assert "/" not in name and ".." not in name


def test_thumbnail_without_tool_is_503_or_image(client, member_key):
    doc_id = upload(client, member_key, "a.png", data=b"notreallyapng", content_type="image/png").json()["id"]
    r = client.get(f"/documents/{doc_id}/thumbnail", headers=auth(member_key))
    assert r.status_code in (200, 502, 503)
