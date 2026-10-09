-- DocVault schema. Applied idempotently on startup by db.init_schema().

CREATE TABLE IF NOT EXISTS teams (
    id          INTEGER PRIMARY KEY,
    slug        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    webhook_url TEXT,
    logo_path   TEXT
);

CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY,
    email    TEXT NOT NULL UNIQUE,
    name     TEXT NOT NULL,
    api_key  TEXT NOT NULL UNIQUE,
    role     TEXT NOT NULL DEFAULT 'member',  -- 'member' | 'admin'
    team_id  INTEGER NOT NULL REFERENCES teams(id)
);

CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER PRIMARY KEY,
    title       TEXT NOT NULL,
    summary     TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'draft',  -- 'draft' | 'review' | 'published'
    owner_id    INTEGER NOT NULL REFERENCES users(id),
    team_id     INTEGER NOT NULL REFERENCES teams(id),
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS reports_team_idx ON reports(team_id, status);

CREATE TABLE IF NOT EXISTS documents (
    id            INTEGER PRIMARY KEY,
    report_id     INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    filename      TEXT NOT NULL,          -- display name, as uploaded
    stored_name   TEXT NOT NULL,          -- single safe component under STORAGE_ROOT/<team>/
    content_type  TEXT NOT NULL DEFAULT 'application/octet-stream',
    size_bytes    INTEGER NOT NULL DEFAULT 0,
    uploaded_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS documents_report_idx ON documents(report_id);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id          INTEGER PRIMARY KEY,
    team_id     INTEGER NOT NULL REFERENCES teams(id),
    event       TEXT NOT NULL,
    target_url  TEXT NOT NULL,
    status_code INTEGER,
    error       TEXT,
    sent_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
    id       INTEGER PRIMARY KEY,
    actor    TEXT NOT NULL,
    action   TEXT NOT NULL,
    detail   TEXT NOT NULL DEFAULT '',
    at       TEXT NOT NULL DEFAULT (datetime('now'))
);
