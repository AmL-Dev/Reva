# DocVault

Internal document and report service. Teams write reports, attach documents to
them, publish a subset externally, and get events pushed to their own webhook.
It backs the Reports tab in the staff portal and the `dv` CLI.

Small by design: one FastAPI app, one SQLite file, one storage directory. It is
not a multi-tenant product — tenancy is a `team_id` column and every query is
scoped by it.

## Running it

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt

export DOCVAULT_DB=./var/docvault.db
export DOCVAULT_STORAGE=./var/storage
export DOCVAULT_EXPORTS=./var/exports

python -m docvault.seed --reset          # schema + a little sample data
uvicorn docvault.app:app --port 9231
```

Then `http://127.0.0.1:9231/docs` for the OpenAPI UI.

Tests: `pytest`.

## Authentication

An `X-API-Key` header, looked up in the `users` table. Two roles, `member` and
`admin`. The seeded keys are development keys and are printed in
`docvault/seed.py`.

Three endpoints are deliberately unauthenticated: `GET /healthz`,
`GET /reports/published` and the OpenAPI docs. Everything else needs a key, and
everything under `/admin` needs `role = 'admin'`.

## Endpoints

| Method | Path | Auth | Notes |
| --- | --- | --- | --- |
| GET | `/healthz` | – | liveness |
| GET | `/reports` | member | filter by `status`/`owner`, sort by an allowlisted column |
| GET | `/reports/published` | – | public feed, optionally filtered by team slug |
| POST | `/reports` | member | |
| GET&nbsp;/&nbsp;PATCH&nbsp;/&nbsp;DELETE | `/reports/{id}` | member | team-scoped |
| GET | `/reports/{id}/documents` | member | |
| POST | `/reports/{id}/documents` | member | multipart upload |
| GET | `/reports/{id}/manifest.csv` | member | CSV listing of attachments |
| GET | `/documents/{id}/download` | member | |
| DELETE | `/documents/{id}` | member | |
| GET | `/documents/{id}/thumbnail` | member | ImageMagick, 503 if absent |
| POST | `/documents/{id}/pdf` | member | LibreOffice headless, 503 if absent |
| GET&nbsp;/&nbsp;PUT | `/teams/me/webhook` | member | outbound target, allowlisted |
| POST | `/teams/me/webhook/test` | member | sends a ping |
| GET | `/teams/me/webhook/deliveries` | member | delivery log |
| GET&nbsp;/&nbsp;POST | `/teams/me/logo` | admin | import branding from the asset CDN |
| GET | `/admin/audit` | admin | |
| GET | `/admin/log` | admin | tails the service log |
| GET | `/admin/diagnostics` | admin | one nightly dump |
| GET | `/admin/diagnostics/index` | admin | available dumps |
| GET | `/admin/storage` | admin | bytes per team |
| GET | `/admin/reports/{id}/bundle` | admin | zip of a report's attachments |
| PUT&nbsp;/&nbsp;GET | `/admin/templates/{name}` | admin | report templates, stored as JSON |

## Layout

```
docvault/
  app.py            application factory, router wiring, /healthz
  config.py         environment -> module constants
  security.py       the shared guards (read this before adding an endpoint)
  db.py             sqlite connection, schema application, query helpers
  schema.sql        tables
  auth.py           X-API-Key -> User, admin dependency
  models.py         pydantic request/response bodies
  seed.py           schema + sample data
  routers/
    reports.py      report CRUD, list/filter/sort, public feed
    documents.py    upload, download, delete, CSV manifest, export writer
    conversion.py   thumbnails and PDF rendering (external binaries)
    webhooks.py     outbound delivery and its log
    integrations.py logo import from the asset CDN
    admin.py        audit, log tail, diagnostics, storage, bundles, templates
tests/              pytest, no network
```

## House rules

These exist because every one of them has been got wrong here at least once.

**Paths.** Never build a path by concatenation. `security.ensure_within(root,
*parts)` is the only supported way to turn request data into a path; it resolves
both sides and refuses anything that leaves `root`, including through a symlink.
`security.sanitize_filename` reduces arbitrary text to one safe component — use
it for anything that becomes a filename or a `Content-Disposition` value.
Storage layout is `STORAGE_ROOT/<team-id>/<stored_name>` where `stored_name` is
a server-generated UUID; the name the user uploaded is a display string in the
database and never a path.

**SQL.** Values are bound parameters, always. Build the statement from literals
and pass values in the tuple — `db.query` / `db.execute` take `(sql, params)`
and nothing else. Identifiers cannot be bound, so an `ORDER BY` column comes
from `security.validate_sort_column(column, ALLOWLIST)` with the allowlist
declared next to the endpoint (`reports.SORTABLE`). `db.placeholders(values)`
builds `?, ?, ?` from the *length* of a list for `IN (...)`.

**Outbound HTTP.** Nothing opens a connection to a user-supplied URL without
`security.validate_outbound_url` first: scheme must be http(s), host must be on
`config.OUTBOUND_HOST_ALLOWLIST`, and the host must not resolve to a private,
loopback or link-local address. A URL is re-checked at send time, not just when
it is stored, because the allowlist can change in between. Redirects are not
followed — an allowlisted host must not be able to bounce us somewhere else.

**Subprocesses.** Argument lists only. `shell=True` is not used anywhere in this
repository and should not start being used. Paths handed to a tool are resolved
with `ensure_within` in the same function that starts the process, and values
derived from stored data go through `security.validate_tool_argument`, because
`convert` and `soffice` read a leading `-` as an option even inside an argv list.

**Deserialisation.** JSON, parsed with `json.loads` and validated into a
pydantic model. No `pickle`, no `yaml.load`, nothing that can construct objects.

## Operational notes

- The conversion binaries (`convert`, `soffice`) are optional. The endpoints
  answer `503` when they are missing, which is the normal state in CI.
- `OUTBOUND_HOST_ALLOWLIST` defaults to three `*.example.com` hosts that do not
  resolve. Set `DOCVAULT_OUTBOUND_HOSTS` for a real environment.
- Uploads are capped at `DOCVAULT_MAX_UPLOAD` (20 MB) and read in one shot.
- There are no migrations. `schema.sql` is `CREATE TABLE IF NOT EXISTS` and is
  applied on every start.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `DOCVAULT_DB` | `./var/docvault.db` | SQLite file |
| `DOCVAULT_STORAGE` | `./var/storage` | document storage root |
| `DOCVAULT_EXPORTS` | `./var/exports` | generated exports, thumbs, bundles |
| `DOCVAULT_DIAGNOSTICS` | `./var/diagnostics` | nightly diagnostics dumps |
| `DOCVAULT_LOG` | `./var/docvault.log` | service log |
| `DOCVAULT_OUTBOUND_HOSTS` | three `*.example.com` hosts | outbound allowlist |
| `DOCVAULT_MAX_UPLOAD` | `20971520` | max upload bytes |
| `DOCVAULT_OUTBOUND_TIMEOUT` | `5.0` | seconds |
| `DOCVAULT_CONVERT_TIMEOUT` | `60.0` | seconds |

See `BACKLOG.md` for what is being asked for next.
