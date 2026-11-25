# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An outbound-only SMTP relay with DKIM signing: one static Go binary (`CGO_ENABLED=0`) that is both the
daemon (`serve`) and the admin CLI, with all state in one SQLite file. It never receives mail for local
delivery. The repository is public: use only `example.com` / `example.org` and the documentation IP
ranges (`192.0.2.0/24`, `2001:db8::/32`) in code, tests, docs and commits.

## Commands

```sh
go build ./cmd/outbound-smtp
go test -race ./...                                        # unit + integration, no network needed
go test -race -run TestNeverAnOpenRelay ./internal/smtpd   # single test
go test -race ./internal/integration                       # end-to-end only
gofmt -l . && go vet ./... && golangci-lint run ./...      # must all be clean (CI enforces)
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
docker build -t outbound-smtp .
```

Commits use Conventional Commits; release-please derives versions and `CHANGELOG.md` from them
(`feat` = minor, `fix` = patch). Do not edit `CHANGELOG.md` or `.release-please-manifest.json` by hand.

## Architecture

Message flow: `smtpd` (accept, authorise, fix headers) -> `dkim` (sign) -> `store.Enqueue` (commit, then
250) -> `queue` (schedule) -> `delivery` (MX or smarthost) -> done, deferred, or `delivery.BuildDSN` bounce
re-queued through the same path.

- `cmd/outbound-smtp`: subcommand dispatch with stdlib `flag` (`parse` allows flags after positionals).
  `serve.go` wires everything; the integration test wires the same components by hand, so keep the two
  in step.
- `internal/store`: the only package that touches SQLite. The schema is owned by embedded SQL migrations
  (`migrations/NNNN_*.sql`, applied via `PRAGMA user_version`); GORM is used for queries only, never
  AutoMigrate. Add a new numbered migration for schema changes and keep GORM structs in sync by hand.
  Timestamps are unix seconds. The CLI and the daemon share the file (WAL), and the daemon re-reads
  domains, users and networks per session, so CLI changes need no restart or IPC.
- `internal/smtpd`: go-smtp server. `session.go` holds the relay rules: a session has no `principal`
  until it authenticates or its IP matches a trusted network, and nothing is accepted without one.
  Envelope sender and `From` header are both checked by `checkSender`. go-smtp creates a new session on
  every EHLO (also after STARTTLS); per-connection state lives in `limitListener`/`trackedConn`.
- `internal/delivery`: uses stdlib `net/smtp` (not go-smtp) because it needs our HELO name before
  STARTTLS; `DATA` is done over `textproto` to capture the remote's final reply. Only a 5xx reply from
  the remote is permanent; everything else defers.
- `internal/queue`: groups due recipients by (message, destination domain). Finished recipients are
  deleted (history is in the logs); in-flight state is memory-only, so a crash just leaves rows due.
- `internal/acmecert`: optional Let's Encrypt via lego (HTTP-01, or DNS-01 with Cloudflare, Hetzner,
  cPanel). It only writes `DATA_DIR/acme/{fullchain,privkey}.pem`; `serve` then points
  `TLS_CERT_FILE`/`TLS_KEY_FILE` at them, so smtpd loads and hot-reloads them like an operator's own
  pair. Verified manually against Pebble (not part of `go test`).
- `internal/metrics`, `internal/tracing`: Prometheus on its own registry; OpenTelemetry via the global
  tracer (no-op unless `OTEL_EXPORTER_OTLP_ENDPOINT` is set). The trace context is stored in
  `messages.traceparent` so delivery spans join the submission trace.
- `internal/testutil`: self-signed cert helper and `Sink`, a fake remote MX (`bounce@` -> 550,
  `defer@` -> 451).

## Invariants

- Never an open relay. Any change to who may send needs a case in `TestNeverAnOpenRelay`.
- A fresh database has no domains, users or networks and relays nothing.
- A client gets 250 only after the queue transaction commits; a DKIM failure is a 4xx and queues nothing.
- Domain matching is exact (no implicit subdomains). `network_domains.domain_id` deliberately does not
  cascade, so deleting a domain cannot turn a restricted network into an unrestricted one.
- Metric labels and trace attributes never contain recipient addresses (metrics: not even recipient
  domains). Logs carry the recipient domain only. Passwords and bodies are never logged.
- Bounces use a null envelope sender and are never bounced again; unsignable bounces are dropped.
- Logging is an injected `*zap.Logger`; no global logger.
