## oobcli — Interactsh + Webhook.site helper

Minimal, single-binary CLI to spin up out-of-band endpoints fast for bug bounty work. Wraps the official `interactsh-client` and supports Webhook.site without tokens. Sessions and events are stored locally under `~/.local/share/oobcli`.

### Quick Start (Go 1.21+)

```
# optional: install interactsh-client (from ProjectDiscovery) and put it on PATH
# build
go build -o oobcli ./cmd/oobcli

# one-shot setup (interactsh): creates session, starts watcher, prints endpoints, self-tests
./oobcli up

# webhook.site without extra setup: auto-creates an inbox for you
./oobcli up --provider webhook

# generate copy-paste payloads for the session
./oobcli payloads --session <id>

# view endpoints again
./oobcli endpoints --session <id>

# stop background watcher
./oobcli stop --session <id>
```

### Install

```
# installs to /usr/local/bin by default
make install
# or set a custom prefix
PREFIX=$HOME/.local make install
```

### Environment Variables

- `INTERACTSH_URL`: When using `interactsh`, sets the HTTP base used by `send-test` if it’s not yet captured from the client output.
- `WEBHOOK_SITE_API_BASE`: Override the Webhook.site API base (default `https://webhook.site`) for restricted or proxied environments.
- `WEBHOOK_SITE_API_KEY`: Optional key for Webhook.site API polling (used automatically if present).

### Interactsh Setup

Install the official `interactsh-client` and ensure it’s on your `PATH`:

```
# Option A: Go (installs to $GOPATH/bin or $GOBIN)
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Option B: macOS (Homebrew)
brew install projectdiscovery/tap/interactsh

# Verify
interactsh-client -version

# Run oobcli with interactsh
oobcli up --provider interactsh --wait 10s
```

This will:
- create a session under `~/.local/share/oobcli/sessions/<id>`
- start a background watcher
- print assigned endpoints (HTTP/DNS/SMTP)
- send a self-test and confirm receipt

### Webhook.site Mode (no tokens)

```
# Auto-provisions an inbox by default
./oobcli up --provider webhook

# Or reuse an existing inbox URL from https://webhook.site/<uuid>
./oobcli up --provider webhook --webhook-url https://webhook.site/<uuid>
```

### Notes
- Requires `interactsh-client` on PATH for Interactsh features (URL auto-capture, streaming events).
- Sessions and events are stored under `~/.local/share/oobcli/sessions/<id>/`.
- `watch --bg` runs the stream in background (log at `watch.log`, PID in `watch.pid`).
- `stop --session <id>` is safe: it validates the PID stored in `watch.pid` and refuses to act on invalid values.
- Webhook.site API polling is best-effort and auto-disables when an API key is required; you can still send tests and review in the UI.
- Webhook.site sessions auto-create an inbox if one is not stored in the session; pass `--webhook-url` only when you need to reuse an existing inbox.
- This repo uses a local Go build cache (`.gocache/`) so `make run/test/lint` work in restricted environments. The cache and built binaries are ignored by git.

### Release Builds

To build cross-platform binaries into `dist/` with checksums:

```
make release
# or set a specific version exported to the script
VERSION=v1.0.0 make release
```

### Development

```
make run     # prints CLI help
make lint    # gofmt + govet (and common JS/Python if present)
make test    # go test ./...
```

### Testing
- Basic unit tests cover URL/domain parsing, CSV filtering, data dir resolution, and tailing events files for self‑test confirmation.
- Run `make test` or `go test ./...` to execute.
