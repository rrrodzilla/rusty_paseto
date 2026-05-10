# Security Policy

## Audit status

This crate has not been independently audited by a third-party firm. As with
any open-source cryptographic code that has not undergone formal audit, use is
at your own risk. The maintainer welcomes audit reports and will incorporate
findings.

## Supported versions

Security fixes are issued against the latest minor version on the `main`
branch. Older minor versions are not patched.

| Version          | Security fixes |
| ---------------- | -------------- |
| 0.10.x (current) | ✅              |
| < 0.10           | ❌              |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.** GitHub
issues are public, and a disclosure there exposes downstream users (atuin,
federal deployments such as acton-service and meridian, and other consumers)
before a fix can ship.

Use one of these private channels:

1. **GitHub Security Advisory (preferred):** open a private vulnerability
   report at
   <https://github.com/rrrodzilla/rusty_paseto/security/advisories/new>.
   This creates a confidential discussion between you and the maintainer.
2. **Email:** `rrrodzilla@proton.me` with subject prefix
   `[rusty_paseto security]`. Encrypting via PGP is welcome but not required —
   if you need a key, request one via the same address before sending
   sensitive content.

### What to include

- A description of the vulnerability and the threat model it breaks.
- A proof-of-concept or minimal reproducer, if you have one.
- The affected versions you have tested.
- Whether you have already coordinated disclosure with downstream
  consumers — and if not, please give the maintainer at least 90 days
  to coordinate before public disclosure.

### What to expect

- Acknowledgement within 7 days.
- Triage and impact assessment within 30 days.
- A coordinated fix and release for confirmed vulnerabilities, with a
  RustSec advisory if appropriate.
- Public credit for the reporter in the release notes (unless you ask
  to remain anonymous).

## Hardening notes for users

- Choose PASETO v4 (`v4_local`, `v4_public`) for new deployments — v1/v2/v3
  are supported only for compatibility with existing tokens.
- Avoid the `v1_public_insecure` feature unless interoperating with an
  existing v1 deployment.
- Set explicit expirations on issued tokens (`ExpirationClaim`). The
  builders enforce a default expiration but you should pick a duration
  appropriate to your threat model.
- Rotate symmetric and asymmetric keys on a schedule. The `paserk`
  feature offers wrapping/sealing primitives for key management.
- Run `cargo audit` regularly against your `Cargo.lock`. This crate
  pins direct dependencies known free of advisories at release; any
  newly disclosed advisory should still be reviewed by your team.
