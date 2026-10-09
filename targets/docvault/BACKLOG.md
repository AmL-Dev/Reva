# DocVault backlog

Ordered roughly by how often someone asks for it. Each item is a request from a
team, written down as it came in. Estimates are not in here on purpose.

---

### 1. Sortable report columns

> The reports table in the portal has clickable column headers but they don't do
> anything yet. People want to click a header and sort by it — any column we
> show, ascending or descending, and it should stick when they page through.
> Right now it's always "last updated, newest first" and the finance team in
> particular keeps asking to sort by owner.

*Requested by: Portal frontend · Size: S*

---

### 2. Full-text search over reports

> There's no way to find an old report unless you know roughly when it was
> written. We'd like a search box over the title and summary — partial words
> should match, and it should be one query param so the frontend can just append
> it to the existing list call.

*Requested by: Support · Size: S*

---

### 3. Export a report as CSV

> Finance want to pull a report out as a CSV they can open in Excel, rather than
> reading it in the portal. One endpoint, returns the report plus its attachment
> list as CSV. Please name the file after the report title — they download
> dozens at a time and `export.csv (3)` is useless to them.

*Requested by: Finance Operations · Size: S*

---

### 4. Import a team logo or avatar from a URL

> Design keeps brand assets on the asset CDN and they'd rather paste a link than
> download and re-upload a PNG. Let an admin give us a URL and we fetch it. They
> also mentioned some of their assets are behind a short link that redirects, so
> that should work too.

*Requested by: Design · Size: S*

---

### 5. Nightly digest to each team's own webhook

> Teams want a daily summary of their reports pushed into their own tooling.
> Each team should be able to set the destination themselves in team settings —
> several of them run their own internal bots and the URLs aren't going to be
> the same shape as the ones we post to today.

*Requested by: Platform Engineering · Size: M*

---

### 6. Convert Office attachments to PDF on upload

> About a third of attachments are .docx or .xlsx and the preview pane can't
> show them, so people download them to look at them. Convert them to PDF when
> they're uploaded and show the PDF in the preview. We already shell out to
> LibreOffice for the manual endpoint, so this should mostly be wiring.

*Requested by: Portal frontend · Size: M*

---

### 7. Restore a report bundle from an archive

> We can download a report bundle as a zip but there's no way back in. Support
> want to take a bundle a customer sends them — zip or tar.gz, they get both —
> and load it into a report so they can look at the attachments in the portal.
> Admin-only is fine.

*Requested by: Support · Size: M*

---

### 8. Upload report templates as files

> Editing templates through the API one JSON body at a time doesn't work for the
> people who actually write them. They keep them in a repo as files and want to
> upload them directly — they write them in YAML because that's what the rest of
> their tooling uses, so we should accept that as well as JSON.

*Requested by: Technical Writing · Size: S*
