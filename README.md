## oobcli — Interactsh + Webhook.site helper

Minimal, single-binary CLI to spin up out-of-band endpoints fast for bug bounty work. Wraps the official `interactsh-client` and supports Webhook.site without tokens.

### Quick Start (Go 1.21+)

```
# optional: install interactsh-client (from ProjectDiscovery) and put it on PATH
# build
go build -o oobcli ./cmd/oobcli

# one-shot setup (interactsh): creates session, starts watcher, prints endpoints, self-tests
./oobcli up --client-args '-http'

# generate copy-paste payloads for the session
./oobcli payloads --session <id>

# view endpoints again
./oobcli endpoints --session <id>

# stop background watcher
./oobcli stop --session <id>
```

### Webhook.site Mode (no tokens)

```
# use your inbox URL from https://webhook.site/<uuid>
./oobcli up --provider webhook --webhook-url https://webhook.site/<uuid>
```

### Notes
- Requires `interactsh-client` on PATH for Interactsh features (URL auto-capture, streaming events).
- Sessions and events are stored under `~/.local/share/oobcli/sessions/<id>/`.
- `watch --bg` runs the stream in background (log at `watch.log`, PID in `watch.pid`).
- Webhook.site API polling is best-effort and auto-disables when an API key is required; you can still send tests and review in the UI.
