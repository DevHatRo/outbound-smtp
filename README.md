# outbound-smtp

[![CI](https://github.com/DevHatRo/outbound-smtp/actions/workflows/ci.yml/badge.svg)](https://github.com/DevHatRo/outbound-smtp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/DevHatRo/outbound-smtp?sort=semver)](https://github.com/DevHatRo/outbound-smtp/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A small outbound-only SMTP relay with DKIM signing. Applications and servers
hand it mail over SMTP; it signs each message, queues it durably and delivers
it to the recipients' mail servers. It is one static Go binary (daemon and
admin CLI in one) that runs in Docker and keeps all its state in a single
SQLite file.

It is meant as a replacement for an outbound-only Postfix.

## What it is not

- **No inbound mail.** It never accepts mail for local delivery.
- **No mailboxes**, no IMAP, no POP3, no aliases or forwarding.
- **No spam or virus filtering.** It sends what authorised clients give it.
- **Not an open relay.** A fresh install has no domains, users or trusted
  networks and relays nothing until you configure it.

## How it works

1. A client connects on port 465 (implicit TLS) or 587 (STARTTLS required)
   and authenticates, or connects from a trusted network.
2. The envelope sender and the `From` header must both be in a domain you
   configured, and the client must be allowed to use them.
3. The message is DKIM-signed with the key of the `From` domain and committed
   to the SQLite queue. Only then does the client get `250`.
4. The relay looks up the recipient's MX, delivers with opportunistic
   STARTTLS, retries temporary failures with exponential backoff, and sends a
   bounce to the envelope sender on permanent failure or expiry.

## Quick start

You need a server whose IP has a PTR record pointing to the relay's hostname,
and a TLS certificate for that hostname: your own, or one the relay obtains
from Let's Encrypt (see [TLS certificates](#tls-certificates)).

```yaml
# docker-compose.yml
services:
  outbound-smtp:
    image: ghcr.io/devhatro/outbound-smtp:latest
    restart: unless-stopped
    environment:
      SMTP_HOSTNAME: relay.example.com
      TLS_CERT_FILE: /certs/fullchain.pem
      TLS_KEY_FILE: /certs/privkey.pem
    ports:
      - "465:465"
      - "587:587"
      - "127.0.0.1:9090:9090" # metrics: never publish this publicly
    volumes:
      - outbound-smtp-data:/data
      - ./certs:/certs:ro # readable by uid 10001
    stop_grace_period: 40s
volumes:
  outbound-smtp-data:
```

```sh
docker compose up -d
alias relay='docker compose exec outbound-smtp outbound-smtp'

relay domain add example.com
relay dkim generate example.com      # prints the DNS TXT record to publish
relay dkim verify example.com        # after publishing it
relay user add myapp --generate      # prints the password once
relay send-test --from myapp@example.com --to you@example.org
relay queue list
```

Point your application at `relay.example.com:465` (TLS) or `:587` (STARTTLS)
with the username and password. Then work through the
[DNS checklist](#dns-checklist).

The container runs as uid 10001. Docker lets unprivileged containers bind
ports 465 and 587; on runtimes that do not, either set
`net.ipv4.ip_unprivileged_port_start=0` for the container or listen on high
ports with `SMTP_LISTEN_465` / `SMTP_LISTEN_587` and map them.

## Who may send

| Client | Ports | Requirement |
| --- | --- | --- |
| Authenticated user | 465, 587 | AUTH PLAIN or LOGIN, only over TLS |
| Trusted network | 465, 587, 25 | Client IP inside a configured CIDR; no AUTH needed. Port 587 still requires STARTTLS. |
| Anyone else | - | Rejected |

- The envelope sender and the `From` header address must each be in a
  configured domain. Matching is exact: `example.com` does not cover
  `mail.example.com`; add subdomains separately.
- A user can be limited to domains or single addresses
  (`user add --allow example.com --allow billing@example.org`); a network can
  be limited to domains (`network add 192.0.2.0/24 --domain example.com`).
  The limit applies to both the envelope sender and the `From` header.
- Messages with no `From`, several `From` fields or several `From` addresses
  are rejected, as is the null envelope sender (`MAIL FROM:<>`).
- Port 25 is off unless `SMTP_ENABLE_PORT25=true`. It never offers AUTH and
  serves trusted networks only.

### Trusted networks and Docker

A trusted network relays **without authentication**, so the relay must see
the real client address. With Docker Desktop, rootless Docker or the userland
proxy, every external client can appear to come from the bridge gateway
(for example `172.17.0.1`). If you trust a range that contains that gateway,
you have built an open relay. Check the `client_ip` field in the logs before
adding a network, prefer host networking or authenticated users when in
doubt, and never trust `172.16.0.0/12` or `192.168.0.0/16` wholesale.
`network add` warns about these ranges and refuses anything broader than /8
for IPv4 or /32 for IPv6.

## Configuration

All settings are environment variables read once at start. Domains, DKIM
keys, users and trusted networks are managed with the CLI and stored in
SQLite; CLI changes take effect without a restart.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SMTP_HOSTNAME` | *(required)* | Name used in EHLO, `Received` and `Message-ID`. Every message carries a `Received: by <hostname> (DevHatRO SMTP) ...` field identifying the relay. Must match the PTR record of the sending IP. |
| `TLS_CERT_FILE` | *(unset)* | PEM certificate chain you provide. Required unless `ACME_ENABLED=true`. The daemon does not start without a valid, unexpired certificate. |
| `TLS_KEY_FILE` | *(unset)* | PEM private key for `TLS_CERT_FILE`. |
| `ACME_ENABLED` | `false` | Obtain and renew the certificate from Let's Encrypt instead. See [TLS certificates](#tls-certificates). |
| `ACME_AGREE_TOS` | `false` | Must be `true` with ACME: you accept the certificate authority's terms of service. |
| `ACME_EMAIL` | *(unset)* | Optional contact address for the ACME account. |
| `ACME_DOMAINS` | `SMTP_HOSTNAME` | Comma-separated host names for the certificate. No wildcards. |
| `ACME_CHALLENGE` | `http` | `http` (HTTP-01) or `dns` (DNS-01). |
| `ACME_HTTP_LISTEN` | `:80` | Where the HTTP-01 challenge is answered. Open only while a certificate is being issued. |
| `ACME_DNS_PROVIDER` | *(unset)* | For DNS-01: `cloudflare`, `hetzner` or `cpanel`. |
| `ACME_DNS_PROPAGATION_WAIT` | *(unset)* | For DNS-01: wait this long (for example `90s`) instead of checking propagation. Needed where outbound DNS is only allowed through the local resolver. |
| `ACME_DIRECTORY_URL` | Let's Encrypt production | ACME directory. Use `https://acme-staging-v02.api.letsencrypt.org/directory` while testing. |
| `DATA_DIR` | `/data` | Directory of the SQLite database (`relay.db`). |
| `SMTP_ENABLE_PORT25` | `false` | Enable the plain SMTP listener for trusted networks. |
| `SMTP_PORT25_STARTTLS` | `true` | Offer STARTTLS on port 25. Set `false` for a plaintext-only port 25; see [Migrating from Postfix](#migrating-from-postfix). |
| `SMTP_LISTEN_465` | `:465` | Listen address, implicit TLS. |
| `SMTP_LISTEN_587` | `:587` | Listen address, STARTTLS required. |
| `SMTP_LISTEN_25` | `:25` | Listen address when port 25 is enabled. |
| `MAX_MESSAGE_SIZE` | `25MB` | Largest accepted message (bytes, or with `KB`/`MB`/`GB`). |
| `MAX_RECIPIENTS` | `100` | Recipients per message. |
| `QUEUE_MAX_AGE` | `72h` | Queue lifetime before a message bounces (Go duration). |
| `DELIVERY_CONCURRENCY` | `20` | Simultaneous deliveries overall. |
| `DELIVERY_CONCURRENCY_PER_DOMAIN` | `2` | Simultaneous deliveries per destination domain. |
| `DELIVERY_IPV6` | `false` | Also deliver over IPv6. Enable only if the IPv6 address has PTR and SPF. |
| `SMARTHOST_HOST` | *(unset)* | Send everything through this host instead of MX lookup. |
| `SMARTHOST_PORT` | `587` | Smarthost port. 465 uses implicit TLS, others STARTTLS. |
| `SMARTHOST_USERNAME` | *(unset)* | Smarthost AUTH username. |
| `SMARTHOST_PASSWORD` | *(unset)* | Smarthost AUTH password. |
| `MAX_CONNECTIONS_PER_IP` | `10` | Simultaneous connections per client IP. |
| `RATE_LIMIT_USER_PER_HOUR` | `1000` | Messages per hour per user, unless `user add --rate` overrides it. |
| `RATE_LIMIT_NETWORK_PER_HOUR` | `1000` | Messages per hour per trusted network, unless `network add --rate` overrides it. |
| `AUTH_FAILURE_LIMIT` | `5` | Failed logins per client IP per 10 minutes before AUTH is refused. |
| `METRICS_LISTEN` | `:9090` | HTTP listener for `/metrics` and `/healthz`. |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | *(unset)* | Enables tracing; see [OpenTelemetry](#opentelemetry-traces). |

Notes:

- The certificate is reloaded on `SIGHUP` and within 30 seconds of the files
  changing. If the new files are invalid, the previous certificate stays.
- The DNS-01 providers read further optional variables (TTL, propagation
  timeout); see the [lego DNS provider documentation](https://go-acme.github.io/lego/dns/).
- Rate limits are token buckets: a client may send its hourly amount in a
  burst and then refills evenly. Counters are in memory and reset on restart.
- With smarthost credentials set, TLS with a verified certificate is
  mandatory and the relay never falls back to plaintext.
- On `SIGTERM` the daemon stops accepting, gives open sessions and running
  deliveries 30 seconds, and exits. Queued mail survives restarts.

## TLS certificates

Ports 465 and 587 never run without a certificate. There are three ways to
provide one. In every case the certificate must be for the name clients
connect to.

### 1. Bring your own certificate

Set `TLS_CERT_FILE` and `TLS_KEY_FILE`. The files are reloaded on `SIGHUP`
and within 30 seconds of changing, so any tool that renews them in place
works without a restart.

### 2. Built-in Let's Encrypt

Set `ACME_ENABLED=true` and `ACME_AGREE_TOS=true` and leave the two file
variables unset. At start the relay registers an account, proves control of
each name in `ACME_DOMAINS` and stores the account key, certificate and key
under `/data/acme` (mode `0600`). It checks twice a day and renews in the
last third of the certificate's lifetime (30 days before expiry for a 90-day
certificate). If a renewal fails it keeps serving the current certificate
and tries again; if no valid certificate exists at start, it refuses to
start. Use the staging `ACME_DIRECTORY_URL` while experimenting: production
Let's Encrypt has strict rate limits.

Control is proven with one of two challenges. Ports 465 and 587 cannot be
used for this.

**HTTP-01** (`ACME_CHALLENGE=http`, the default): Let's Encrypt fetches a
token from `http://<name>/.well-known/acme-challenge/...`, so port 80 of each
name must reach the relay from the internet. Publish it (`- "80:80"`) or
forward it. The relay only listens on it during issuance.

**DNS-01** (`ACME_CHALLENGE=dns`): the relay creates a temporary
`_acme-challenge` TXT record through your DNS provider's API. No inbound port
is needed, which suits hosts behind NAT. Set `ACME_DNS_PROVIDER` and the
provider's credentials:

| `ACME_DNS_PROVIDER` | Credentials |
| --- | --- |
| `cloudflare` | `CLOUDFLARE_DNS_API_TOKEN`: an API token with *Zone / DNS / Edit* on the zone (and *Zone / Zone / Read*). |
| `hetzner` | `HETZNER_API_TOKEN`: a Hetzner Cloud API token (read and write) of the project that holds the DNS zone. |
| `cpanel` | `CPANEL_USERNAME`, `CPANEL_TOKEN`, `CPANEL_BASE_URL` (for example `https://cpanel.example.com:2083`); `CPANEL_MODE=whm` for WHM. |

Before asking for validation the relay checks that the record is visible on
the zone's authoritative name servers. Networks that block outbound DNS
except through their own resolver make that check time out; set
`ACME_DNS_PROPAGATION_WAIT=90s` there to wait a fixed time instead.

These tokens can change DNS for the zone. Scope them to the one zone, and
prefer HTTP-01 when port 80 is available.

```yaml
    environment:
      SMTP_HOSTNAME: relay.example.com
      ACME_ENABLED: "true"
      ACME_AGREE_TOS: "true"
      ACME_CHALLENGE: dns
      ACME_DNS_PROVIDER: cloudflare
      CLOUDFLARE_DNS_API_TOKEN: ${CLOUDFLARE_DNS_API_TOKEN}
```

### 3. An external ACME client

For any other DNS provider or an existing setup, run certbot, acme.sh, lego,
Caddy or Traefik yourself and point `TLS_CERT_FILE` / `TLS_KEY_FILE` at the
files they maintain (readable by uid 10001). The relay picks up each renewal
through the file reload described above.

## CLI reference

The same binary is the admin tool. Commands work on the SQLite file directly,
so they can run through `docker exec` while the daemon is up. Flags may come
before or after arguments.

| Command | Purpose |
| --- | --- |
| `serve` | Run the daemon. |
| `version` | Print version, commit and Go version. |
| `healthcheck` | Exit 0 if the running daemon answers `/healthz` (used by the image). |
| `domain add\|remove <domain>`, `domain list` | Manage sending domains. Removing a domain removes its DKIM keys. |
| `dkim generate <domain> [--selector s] [--algorithm rsa\|ed25519]` | Create a key and print its DNS record. The first key of a domain is active at once. |
| `dkim show <domain>` | Print the DNS records of all selectors. |
| `dkim verify <domain> [--selector s]` | Check by DNS lookup that the published record matches the key. |
| `dkim rotate <domain> [--selector s] [--algorithm a] [--force]` | Rotate keys; see below. |
| `user add <name> [--allow domain-or-address]... [--rate N]` | Create a user. The password is prompted for, read with `--password-stdin`, or created with `--generate`. Minimum 12 characters. |
| `user passwd <name>` | Change a password (same password options). |
| `user list`, `user remove <name>` | List or delete users. |
| `network add <cidr> [--domain d]... [--rate N]` | Trust a network. |
| `network list`, `network remove <cidr>` | List or delete trusted networks. |
| `queue list` | Show queued recipients with state and last error. |
| `queue show <id> [--raw]` | Show a message, or dump it with `--raw`. |
| `queue retry <id>`, `queue retry --all` | Make deliveries due now. |
| `queue delete <id>` | Drop a message without a bounce. |
| `send-test --from a@example.com --to b@example.org` | Queue a signed test message. |

Passwords are never accepted as command-line arguments and are stored as
argon2id hashes. DKIM private keys are stored unencrypted in the database,
which is created with mode `0600`; protect the data volume and its backups.

### DKIM key rotation

Rotation takes two steps so that mail is never signed with a selector that is
not in DNS yet:

```sh
relay dkim rotate example.com   # 1: creates a new inactive key, prints its record
# publish the record, wait for DNS
relay dkim rotate example.com   # 2: verifies DNS, then switches signing to it
```

Keep the old selector's record published for about a week; mail signed with
it may still be in transit. RSA-2048 is the default. Ed25519 keys are smaller
but are not verified by every receiver yet.

## DNS checklist

For each sending domain (`example.com`) and the relay host
(`relay.example.com`, sending IP `192.0.2.10`):

- [ ] **PTR**: `192.0.2.10` resolves to `relay.example.com`, and
      `relay.example.com` resolves back to `192.0.2.10`. Set `SMTP_HOSTNAME`
      to the same name. Ask your hosting provider to set the PTR.
- [ ] **SPF**: a TXT record on `example.com` that authorises the sending IP,
      for example `v=spf1 ip4:192.0.2.10 -all` (merge with an existing SPF
      record; a domain must have only one).
- [ ] **DKIM**: the TXT record printed by `dkim generate`, at
      `<selector>._domainkey.example.com`. Confirm with `dkim verify`.
- [ ] **DMARC**: a TXT record at `_dmarc.example.com`, starting with
      `v=DMARC1; p=none; rua=mailto:dmarc@example.com` and tightened to
      `quarantine` or `reject` once reports look clean.
- [ ] The domain can **receive bounces**: bounces go to the envelope sender
      through that domain's normal MX. This relay does not receive them.
- [ ] The provider allows **outbound port 25** (many clouds block it by
      default), or you use smarthost mode.
- [ ] If you enable `DELIVERY_IPV6`: an IPv6 PTR and `ip6:` in SPF.

## Logs

Structured JSON on stdout, one line per accepted message, per rejection and
per delivery attempt:

```json
{"level":"info","time":"...","msg":"message accepted","queue_id":"ILF4UHF7JRE6FWZ5","sender":"app@example.com","from_domain":"example.com","source":"auth","client":"myapp","listener":"465","client_ip":"192.0.2.44","tls":true,"recipients":1,"recipient_domains":["example.org"],"size":960,"trace_id":""}
{"level":"info","time":"...","msg":"delivery attempt","queue_id":"ILF4UHF7JRE6FWZ5","sender":"app@example.com","recipient_domain":"example.org","result":"delivered","response":"250 2.0.0 Ok: queued","remote_host":"mx.example.org","tls":true,"attempt":1,"trace_id":""}
```

Passwords and message bodies are never logged. Recipients appear by domain
only; use `queue list` for full addresses of mail still in the queue.

## Prometheus metrics

`METRICS_LISTEN` serves `/metrics` and `/healthz`. The listener is
**unauthenticated: do not publish it to the internet.** Bind it to loopback
or a private network.

| Metric | Labels |
| --- | --- |
| `smtprelay_connections_total` | `listener`, `tls` |
| `smtprelay_connections_active` | `listener` |
| `smtprelay_auth_attempts_total` | `result` (`success`, `failure`, `blocked`) |
| `smtprelay_messages_accepted_total` | `source` (`auth`, `network`), `domain` |
| `smtprelay_messages_rejected_total` | `reason` (`relay_denied`, `sender_not_allowed`, `size`, `rate_limit`, `invalid_message`) |
| `smtprelay_deliveries_total` | `result` (`delivered`, `deferred`, `bounced`), `tls` |
| `smtprelay_delivery_duration_seconds` | histogram |
| `smtprelay_queue_depth` | `state` (`pending`, `deferred`) |
| `smtprelay_queue_oldest_message_age_seconds` | |
| `smtprelay_dkim_sign_total` | `domain`, `result` |
| `smtprelay_tls_cert_expiry_timestamp_seconds` | |
| `smtprelay_build_info` | `version`, `go_version` |

Labels only ever contain your own sending domains, never recipient addresses
or recipient domains.

```yaml
# prometheus.yml
scrape_configs:
  - job_name: outbound-smtp
    static_configs:
      - targets: ["relay.internal.example.com:9090"]
```

```yaml
# Suggested alert rules
groups:
  - name: outbound-smtp
    rules:
      - alert: SmtpRelayQueueOld
        expr: smtprelay_queue_oldest_message_age_seconds > 3600
        for: 15m
        annotations:
          summary: Mail has been stuck in the queue for over an hour
      - alert: SmtpRelayBounceRateHigh
        expr: |
          sum(rate(smtprelay_deliveries_total{result="bounced"}[30m]))
            / sum(rate(smtprelay_deliveries_total{result=~"delivered|bounced"}[30m])) > 0.05
        for: 30m
        annotations:
          summary: More than 5% of final deliveries are bouncing
      - alert: SmtpRelayCertExpiresSoon
        expr: smtprelay_tls_cert_expiry_timestamp_seconds - time() < 14 * 86400
        annotations:
          summary: The relay TLS certificate expires in under 14 days
      - alert: SmtpRelayDkimFailing
        expr: increase(smtprelay_dkim_sign_total{result="error"}[15m]) > 0
        annotations:
          summary: Messages are being refused because DKIM signing fails
```

## OpenTelemetry traces

Tracing is off by default. Set the standard variables to export traces over
OTLP/HTTP (protobuf):

```sh
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector.internal.example.com:4318
OTEL_SERVICE_NAME=outbound-smtp            # optional
OTEL_EXPORTER_OTLP_HEADERS=key=value       # optional
```

Each message produces one trace that follows it from submission to its final
state, also across restarts (the trace context is stored with the queued
message):

| Span | When |
| --- | --- |
| `smtp.receive` | A message is submitted; child `dkim.sign` |
| `smtp.deliver` | Each delivery attempt per destination domain, with one event per recipient result |
| `dsn.generate` | A bounce is created; the bounce's own delivery continues the trace |
| `smtp.reject` | A transaction is refused (separate short trace) |

Spans carry the queue ID, envelope sender, sending domain, recipient
*domain*, result and remote response. Full recipient addresses are not
exported. Log lines include `trace_id` for correlation. Only OTLP/HTTP is
supported; point it at a collector if your backend needs gRPC.

## Migrating from Postfix

| Postfix | outbound-smtp |
| --- | --- |
| `myhostname` | `SMTP_HOSTNAME` |
| `mynetworks` | `network add <cidr>` (none by default; `127.0.0.0/8` is **not** trusted implicitly) |
| `smtpd_sasl_auth_enable` + a SASL backend | `user add` |
| `smtpd_sender_login_maps` | `user add --allow ...` |
| `smtpd_tls_cert_file` / `smtpd_tls_key_file` | `TLS_CERT_FILE` / `TLS_KEY_FILE` |
| `relayhost` + `smtp_sasl_password_maps` | `SMARTHOST_*` |
| `message_size_limit` | `MAX_MESSAGE_SIZE` |
| `maximal_queue_lifetime` | `QUEUE_MAX_AGE` |
| `smtp_destination_concurrency_limit` | `DELIVERY_CONCURRENCY_PER_DOMAIN` |
| OpenDKIM / `milter` | built in: `dkim generate` |
| `mailq`, `postqueue -f`, `postsuper -d` | `queue list`, `queue retry --all`, `queue delete` |

Steps:

1. Add your domains and generate new DKIM keys under a **new selector**,
   publishing them next to the old ones. Existing OpenDKIM keys cannot be
   imported; the old selector keeps verifying mail Postfix already sent.
2. Recreate SASL users with `user add` and trusted networks with
   `network add`. Applications on the same host need a user or an explicit
   network entry.
3. Send a `send-test` to a mailbox you control and check for `dkim=pass`,
   `spf=pass` and `dmarc=pass` in the received headers.
4. Let the Postfix queue drain (`mailq`), then switch clients over and stop
   Postfix.

Applications that send to port 25 without TLS keep working unchanged: enable
port 25 and add their addresses with `network add`. One catch: many clients
(Nodemailer, Grafana and others) upgrade to STARTTLS whenever a server offers
it and then verify the certificate, which fails if they connect by IP or by a
name that is not on the certificate. If your Postfix did not offer STARTTLS,
set `SMTP_PORT25_STARTTLS=false` so port 25 behaves the same; ports 465 and
587 are not affected.

Differences to be aware of: no `sendmail` binary or pickup directory (use
SMTP), no header or address rewriting, no content filters or milters, no
MTA-STS or DANE for outbound TLS, no SMTPUTF8, and one instance per database
(no clustering).

## Building from source

Requires Go 1.27 or newer.

```sh
CGO_ENABLED=0 go build -o outbound-smtp ./cmd/outbound-smtp
go test -race ./...
docker build -t outbound-smtp .
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

## How releases work

Commits follow [Conventional Commits](https://www.conventionalcommits.org/).
On every push to `main`, [release-please](https://github.com/googleapis/release-please)
maintains a release pull request with the next version and `CHANGELOG.md`.
Merging that pull request creates the tag and GitHub release, and the same
workflow then:

- builds the image for `linux/amd64` and `linux/arm64` and pushes it to
  `ghcr.io/devhatro/outbound-smtp` tagged with the full version,
  `major.minor`, `major` and `latest`, with a build provenance attestation;
- attaches static Linux binaries (amd64, arm64) and `checksums.txt` to the
  release.

Verify an image's provenance with:

```sh
gh attestation verify oci://ghcr.io/devhatro/outbound-smtp:latest --repo DevHatRo/outbound-smtp
```

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
