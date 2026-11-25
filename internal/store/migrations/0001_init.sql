-- Timestamps are unix seconds. Domain names are lowercase ASCII (punycode).

CREATE TABLE domains (
  id         INTEGER PRIMARY KEY,
  name       TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL
);

CREATE TABLE dkim_keys (
  id          INTEGER PRIMARY KEY,
  domain_id   INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  selector    TEXT NOT NULL,
  algorithm   TEXT NOT NULL CHECK (algorithm IN ('rsa','ed25519')),
  private_key BLOB NOT NULL, -- PKCS#8 DER
  active      INTEGER NOT NULL DEFAULT 0,
  created_at  INTEGER NOT NULL,
  UNIQUE (domain_id, selector)
);
CREATE UNIQUE INDEX dkim_one_active ON dkim_keys(domain_id) WHERE active = 1;

CREATE TABLE users (
  id            INTEGER PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL, -- argon2id PHC string
  rate_per_hour INTEGER,       -- NULL = global default
  created_at    INTEGER NOT NULL
);

-- No rows for a user means any configured domain.
CREATE TABLE user_senders (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  pattern TEXT NOT NULL, -- 'example.com' or 'app@example.com'
  PRIMARY KEY (user_id, pattern)
);

CREATE TABLE networks (
  id            INTEGER PRIMARY KEY,
  cidr          TEXT NOT NULL UNIQUE, -- canonical form
  rate_per_hour INTEGER,              -- NULL = global default
  created_at    INTEGER NOT NULL
);

-- No rows for a network means any configured domain. That is why domain_id
-- does not cascade: deleting a domain must never silently turn a restricted
-- network into an unrestricted one.
CREATE TABLE network_domains (
  network_id INTEGER NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
  domain_id  INTEGER NOT NULL REFERENCES domains(id),
  PRIMARY KEY (network_id, domain_id)
);

CREATE TABLE messages (
  id            TEXT PRIMARY KEY, -- queue ID
  envelope_from TEXT NOT NULL,    -- '' for DSNs
  from_domain   TEXT NOT NULL,    -- signing domain
  source        TEXT NOT NULL CHECK (source IN ('auth','network','internal')),
  source_ident  TEXT NOT NULL,    -- username, CIDR, or 'dsn'/'send-test'
  size          INTEGER NOT NULL,
  body          BLOB NOT NULL,    -- full message, already DKIM-signed
  traceparent   TEXT NOT NULL DEFAULT '', -- W3C trace context of the accepting span
  created_at    INTEGER NOT NULL
);

CREATE TABLE recipients (
  id              INTEGER PRIMARY KEY,
  message_id      TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  address         TEXT NOT NULL,
  domain          TEXT NOT NULL,
  state           TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','deferred')),
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL,
  last_attempt_at INTEGER NOT NULL DEFAULT 0, -- 0 = never tried
  last_error      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX recipients_due ON recipients(next_attempt_at);
CREATE INDEX recipients_msg ON recipients(message_id);
