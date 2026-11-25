# Contributing

Thanks for helping. Bug reports, fixes and focused features are welcome.
For anything large, open an issue first so we can agree on the approach.

Security problems must not go into public issues: see [SECURITY.md](SECURITY.md).

## Build and test

Requires Go 1.27 or newer. Docker is only needed for the image build.

```sh
go build ./cmd/outbound-smtp
go test -race ./...                       # unit and integration tests
go test -race -run TestNeverAnOpenRelay ./internal/smtpd   # a single test
gofmt -l . && go vet ./...
golangci-lint run ./...                   # config in .golangci.yml
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
docker build -t outbound-smtp .
```

CI runs exactly these on every pull request. Tests start real SMTP listeners
on loopback and use fakes for DNS and the remote mail server; they need no
network access and must stay that way.

## Ground rules

- **Never weaken relay control.** Any change to who may send
  (`internal/smtpd`) needs a test in `TestNeverAnOpenRelay` or next to it.
- **No private data** in code, tests, docs or commit messages: use
  `example.com`, `example.org`, `192.0.2.0/24` and `2001:db8::/32`.
- **No CGO.** The binary must build with `CGO_ENABLED=0`.
- **Schema changes** go into a new numbered file in
  `internal/store/migrations/`; never edit a released migration.
- **Dependencies** must be license-compatible with Apache-2.0 and worth their
  weight; prefer the standard library.
- Keep metric label cardinality bounded: never label by recipient.
- New behaviour comes with a test.

## Commits and pull requests

Commits follow [Conventional Commits](https://www.conventionalcommits.org/);
release-please derives the version and changelog from them.

```
feat: add per-domain delivery rate limit
fix(queue): cap retry time at message expiry
docs: explain smarthost TLS requirements
feat!: drop support for ...        # breaking change
```

`feat` bumps the minor version, `fix` the patch version, and `!` or a
`BREAKING CHANGE:` footer the major version (minor while below 1.0). Use
`docs`, `test`, `ci`, `build`, `refactor` and `chore` for changes that should
not trigger a release.

Pull requests are squash-merged, so the pull request title must be a valid
Conventional Commit message.

By contributing you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE).

## Repository setup (maintainers, once)

These settings live in GitHub, not in the repository:

- **Branch protection for `main`**: require a pull request, require the
  status check **`ci`** (the aggregate job of the CI workflow), and require
  branches to be up to date.
- **Actions permissions**: under *Settings > Actions > General*, allow
  GitHub Actions to create pull requests (release-please needs it).
- **Private vulnerability reporting**: enable it under *Settings > Security*,
  because SECURITY.md and the Code of Conduct point to it.
- **Package visibility**: after the first release, set the
  `outbound-smtp` container package to public under the organisation's
  *Packages* settings; new GHCR packages start private.
- **Release pull request checks**: pull requests opened with the built-in
  `GITHUB_TOKEN` do not trigger workflows, so CI does not start on the
  release-please pull request by itself. Close and reopen it to run the
  required check before merging.
