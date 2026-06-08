# 2ms-web — Low False-Positive Secret Scanner

A web-based secret scanner built on top of the [2ms](../README.md) engine. It adds
a precision pipeline that dramatically cuts false positives, and ships as a
**single self-contained binary** with the UI embedded — no Node build, no
database, no external services.

---

## Quick start (anyone, any machine)

You need **[Go](https://go.dev/dl/) 1.26 or newer** installed. Check with `go version`.

```bash
# 1. get the code, then go into the webtool folder
cd 2ms-master/webtool

# 2. build and run (this also opens the dashboard in your browser)
make run
```

That's it. You'll see:

```
  2ms-web · low false-positive secret scanner
  ------------------------------------------------
  Dashboard : http://127.0.0.1:8080
  Data dir  : /Users/you/.2ms-web
  Stop      : press Ctrl+C
```

If port 8080 is busy it automatically picks the next free port — just use the URL printed in the banner.

### No `make`? Use Go directly

```bash
cd 2ms-master/webtool
go run .
```

### Install it once, run from anywhere

```bash
cd 2ms-master/webtool
make install          # or: go install .
2ms-web               # now available on your PATH
```

> Ensure `$(go env GOPATH)/bin` is on your `PATH`.

---

## How to use it

Open the dashboard and pick one of three inputs:

- **Local path** — a folder on this machine.
- **Git URL** — e.g. `https://github.com/org/repo.git` (shallow-cloned, needs `git`).
- **Upload zip** — drag & drop a `.zip` of your code.

Then click **Scan**. Results are grouped by confidence (High / Medium). Use
**Reveal values** to see the actual secret, **Mark FP** to teach the tool to
ignore a false positive forever, and **Export JSON/CSV** to save the report.

---

## Sharing prebuilt binaries with your team

If teammates don't have Go, build binaries for every OS once and hand them out:

```bash
cd 2ms-master/webtool
make release          # or: ./build.sh
ls bin/
# 2ms-web-darwin-arm64  2ms-web-linux-amd64  2ms-web-windows-amd64.exe  ...
```

Each file is fully self-contained (UI included). A teammate just runs the file
for their OS — no Go, no setup.

---

## Command-line flags

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `8080` | Preferred port; auto-falls back if busy |
| `--host` | `127.0.0.1` | Interface to bind. Use `0.0.0.0` to expose on your LAN |
| `--open` | `true` | Open the dashboard in your browser on startup |
| `--data-dir` | `~/.2ms-web` | Where the learned false-positive list is stored |
| `--log-level` | `warn` | `trace`/`debug`/`info`/`warn`/`error` |

> Security note: the tool has **no login**, and the "Local path" input scans
> folders on the machine running the server. Keep the default `127.0.0.1`
> (your machine only). Don't bind it to `0.0.0.0` on an untrusted network.

---

## How it reduces false positives

```
Web UI ─> Layer 1 (skip build/dep/cache files)
            └─> 2ms engine (full rule set + custom recall rules)
                 └─> Layer 2 (confidence scoring + noise gates)
                      └─> Layer 3 (your learned false positives)
                           └─> results (High / Medium)
```

- **Layer 1 (`excludes.go`)** skips `node_modules`, `.git`, `dist`, `build`,
  `target`, minified/generated assets, lockfiles and binaries.
- **Layer 2 (`confidence.go`)** trusts structured provider tokens (AWS, GitHub,
  Stripe, Slack…) as High, and forces broad keyword matches through gates:
  template/variable references (`${{password}}`, `{password}`), placeholders,
  version tags, code identifiers, comments, low entropy, and word-only values.
- **Layer 3 (`feedback.go`)** remembers anything you "Mark as false positive"
  (stored as a one-way hash — secret values are never written to disk).

Custom recall rules (`customrules.go`) additionally catch keyword-assigned
passwords (e.g. `pg_pass = "..."`) and standalone AWS secret keys — but only
when a real value is present, never on the variable name alone.

---

## API (for automation)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/scan` | Start a scan (multipart zip, or JSON `{path}`/`{gitUrl}`). Returns `{id}`. |
| `GET` | `/api/scan/{id}` | Job status, progress, and scored results. |
| `POST` | `/api/feedback` | `{jobId, findingId, undo}` — mark/unmark a finding as FP. |
| `GET` | `/api/export/{id}?format=json\|csv` | Download the report. |

---

## Troubleshooting

- **"command not found: go"** → install Go from <https://go.dev/dl/>.
- **Git URL scan fails** → make sure `git` is installed and the repo is public.
- **Browser didn't open** → just open the URL printed in the banner manually.
- **Want raw engine output** → turn off "Confidence filtering" in the UI.
