# Security policy

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub security
advisories:

1. Open the [Security tab](https://github.com/DevHatRO/outbound-smtp/security) of this repository.
2. Choose **Report a vulnerability**.
3. Describe the issue, the affected version and how to reproduce it.

Do not open a public issue, pull request or discussion for a suspected
vulnerability, and do not include real credentials, keys or third-party mail
in a report.

You can expect an acknowledgement within a few days. We will keep you
informed while we work on a fix, credit you in the advisory unless you prefer
otherwise, and publish the advisory together with the fixed release.

## What counts

Especially interesting:

- any way to relay mail without being an authenticated user or in a trusted
  network (open relay), or to send as a domain or address a client is not
  allowed to use;
- authentication bypass, credential or DKIM private key disclosure;
- ways to make the relay sign or send content the client did not submit;
- denial of service that a single unauthenticated client can cause.

## Supported versions

Security fixes are released for the latest version only. Please upgrade to
the newest release before reporting.

## Deployment notes

The `/metrics` listener is unauthenticated by design and must not be exposed
publicly. The data volume contains DKIM private keys and password hashes;
restrict access to it and to its backups.
