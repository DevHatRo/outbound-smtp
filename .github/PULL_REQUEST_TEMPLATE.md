<!-- The title must be a Conventional Commit message, e.g. "fix(queue): cap retry time at expiry". -->

## What and why

<!-- What does this change, and what problem does it solve? Link the issue if there is one. -->

## Checklist

- [ ] `go test -race ./...` passes
- [ ] `gofmt`, `go vet` and `golangci-lint run ./...` are clean
- [ ] New behaviour has a test
- [ ] Changes to relay or sender rules are covered by an open-relay test
- [ ] README updated (environment variables, CLI, metrics) if behaviour changed
- [ ] No real domains, addresses, IPs, keys or credentials anywhere in the change
