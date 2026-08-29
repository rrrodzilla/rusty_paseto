# Changelog

All notable changes to this project will be documented in this file.

## [0.10.1] - 2026-08-29

### Security

- Reject present `nbf` claims that are null, non-string, empty, or malformed
  instead of treating them as if the optional claim were absent.
- When non-expiring tokens are explicitly enabled, accept only an absent `exp`
  claim; reject present null, non-string, empty, malformed, or expired values.

### Fixed

- Correct claim-mismatch errors so they report the verifier's configured value
  as expected and the token's claim value as received
  ([#92](https://github.com/rrrodzilla/rusty_paseto/issues/92)).
- Restore core-only feature builds by compiling the JSON error variant only
  when the `generic` feature enables `serde_json`.

## [0.10.0] - 2026-05-10

This release is a focused security pass driven by a full internal audit of the
crate against the PASETO specification and current advisory database.

### Security

- **Ed25519 verification is now strict (RFC 8032).** `Paseto::<V2, Public>` and
  `Paseto::<V4, Public>` now call `ed25519_dalek::VerifyingKey::verify_strict`
  instead of the lenient `verify`. The strict path rejects signatures with
  torsion components and non-canonical R encodings, eliminating ed25519
  signature malleability. All 56 default tests and the official PASETO v2/v4
  public test vectors continue to pass.
- **Default parser now rejects tokens missing the `exp` claim.** A second-look
  audit highlighted an asymmetry: the builder required an explicit
  `set_no_expiration_danger_acknowledged()` to mint non-expiring tokens, but
  the parser silently accepted them. The parser is now symmetric — an absent,
  null, or non-string `exp` returns `PasetoClaimError::Missing("exp")`. Use
  the new `PasetoParser::set_no_expiration_danger_acknowledged()` to opt in
  when you genuinely want to accept non-expiring tokens.
- **Token and footer size limits.** New constants `Paseto::MAX_TOKEN_SIZE`
  (64 KiB) and `Paseto::MAX_FOOTER_SIZE` (1024 bytes, per PASETO spec
  recommendation) are enforced in both `parse_raw_token` and
  `UntrustedToken::try_parse` before any base64 decoding or PAE construction.
  Bounds the work an attacker can force on inputs that would have failed MAC
  verification. New error variants `Error::TokenTooLarge` and
  `Error::FooterTooLarge`.
- **Derived encryption and authentication keys now zeroize on drop.**
  `EncryptionKey`, `AuthenticationKey`, and `HkdfKey` derive
  `Zeroize` + `ZeroizeOnDrop`. The root `PasetoSymmetricKey` (`Key<N>`) was
  already zeroized; this closes the gap for per-message Ek/Ak material derived
  via HKDF (v1/v3) and BLAKE2b (v4).
- **Eliminated two public-API panic-on-bad-input paths.**
  `Key::<N>::from(&[u8])` and `PasetoAsymmetricPrivateKey::<V2|V4, Public>::from(&[u8])`
  previously called `copy_from_slice` into fixed-size buffers, panicking the
  thread on size mismatch. Both now use `TryFrom<&[u8]>` returning
  `PasetoError::InvalidKey`. The infallible array-typed `From` impls remain
  for callers that already have a correctly-sized array.

### Dependencies

- **`time` 0.3 → 0.3.47** to resolve RUSTSEC-2026-0009 (DoS via stack
  exhaustion in claim parsing).
- **`zeroize` 1.4 → 1.8** for current derive macros and bug fixes.

### Fixed

- **`nbf` claim boundary.** A token with `nbf == now` is now accepted, per
  RFC 7519 §4.1.5. Previously the strict `<=` check rejected tokens for one
  instant at the boundary.

### Breaking changes

- `PasetoParser::default()` now rejects tokens missing `exp` by default;
  callers that want non-expiring tokens must add
  `.set_no_expiration_danger_acknowledged()` on the parser (mirroring the
  existing builder method).
- `Key::<N>::from(&[u8])` removed. Callers using `Key::<N>::from(slice)`
  with a slice (rather than an array) must switch to
  `Key::<N>::try_from(slice)?`. The array-typed `From<[u8; N]>` and
  `From<&[u8; N]>` impls are unchanged.
- `PasetoAsymmetricPrivateKey::<V2|V4, Public>::from(&[u8])` is now
  `TryFrom<&[u8]>`. Callers using `from(slice)` must switch to
  `try_from(slice)?`. V1 (RSA, arbitrary-length) and V3 (Key<48>-typed)
  are unaffected.

### Spec compliance

- **PAE `le64`** now masks the high bit (`n &= 0x7FFF_FFFF_FFFF_FFFF`) for
  byte-exact compatibility with the reference implementation. In Rust this is
  structurally redundant — slice/Vec lengths are bounded by `isize::MAX` — but
  the masking matches the spec pseudocode.

### Documentation

- **Corrected `v1_public_insecure` rationale.** Previous docs cited
  RUSTSEC-2023-0071 (Marvin Attack), which targets the `rsa` crate. This crate
  uses `ring`'s RSA-PSS, which is constant-time blinded and not affected by
  that advisory. The `_insecure` suffix and `#[deprecated]` attributes remain
  — V1 is the legacy PASETO version (2048-bit RSA-PSS-SHA384) and the spec
  recommends V4 — but the justification now reflects reality.
- **`SECURITY.md`** rewritten with private disclosure channels (GitHub
  Security Advisory plus `rrrodzilla@proton.me`), supported-versions table,
  SLA expectations, and hardening guidance for users.
- **`actix_identity` example hardened.** Replaced hardcoded keys with env
  vars (`PASETO_KEY`, `COOKIE_KEY` as 32-byte hex; random fallback per
  process start), removed `.expect()`/`.unwrap()` from request handlers,
  and added a leading module doc explaining what to fix before adapting it
  to production.

### Meta

- **MSRV declared as 1.85**, the minimum supported by the dependency tree
  (transitive `time-core 0.1.8` requires `edition2024`).

### Notes

- `cargo audit` against the library's runtime dependency tree is clean.
  Two `rand` warnings (`RUSTSEC-2026-0097`, "unsound with a custom logger")
  remain in the dev-dependency tree, reachable only through `proptest`
  and the actix-web-based `actix_identity` example. They do not affect
  consumers of `rusty_paseto` itself.

## [0.8.0] - 2025-10-05

### Added
- Automated release creation on version tags (#72)
- Untrusted footer parsing for key rotation (#67)
- Compile-time checks for incompatible feature combinations (#56)

### Changed
- Update dependencies to latest versions (#57)
  - Update primes dev dependency to 0.4
  - Update thiserror to 2.0
  - Update rand_core from 0.6 to 0.9
  - Update aes dependency from 0.7 to 0.8 (#55)

### Fixed
- Remove unnecessary ed25519-dalek dependency in v1_public (#71)
- Relax lifetime bound in PasetoParser::check_claim (#68)
- Resolve clippy lints and update dependencies (#65)

### Refactored
- Simplify wrap_value by removing redundant empty map check (#66)

### Documentation
- Clarify expiration validation behavior in PasetoParser (#69)

### CI/CD
- Improve test execution and lint coverage (#64)

## [0.7.2] - 2024-12-09

### Changed
- Patch bumps for dependencies
- Add flake for environment
- Ignore env files
- Disable clippy temporarily

### Added
- Create funding.yml

## [0.7.1] - 2024-05-31

### Fixed
- Return error if key size mismatch in TryFrom (#50)

### Changed
- Refactor test and clippy workflows for feature matrix
- Refactor error handling in v4 test vectors
- Update dependencies in v4_public.rs
- Update test configurations and enhance cryptographic features
- Update blake2 dependency and refactor usage
- Update chacha20poly1305 version
- Update erased-serde dependency version
- Update iso8601 and uuid dependencies
- Update dependencies and refactor base64 encoding

### Documentation
- Clarify secure flag usage in actix example (#51)

### Repository
- Enforce EOL via .gitattributes (#42)
- Unify line ending to unix-style (#41)
- Update .gitignore file

### Reverted
- Revert "chore: update aes to 0.8 (#44)" (#45)
- Revert "Update dependencies and refactor cryptographic functions"

## [0.7.0] - 2024-01-19

### Changed
- Bump ring for RISC-V support (#33)

### Fixed
- Remove stray eprintln! (#35)

## [0.6.0] - 2023-11-05

### Security
- Bump ed25519-dalek to v2.0 for RUSTSEC-2022-0093

### Repository
- Add .idea folder to .gitignore

## [0.5.0] - 2022-12-30

### Added
- V3 public key support
- Paseto layer for v3_public
- V3_public generic builder and parser
- V3_public core implementation

### Documentation
- Update roadmap with v3_public progress
- Add documentation for prelude module & unit tests
- Add documentation for generic module

### Fixed
- V3 local tokens were not having Implicit Assertions set

### CI/CD
- Minor changes to remove clippy warnings
- Update GitHub Actions workflows

## [0.4.0] - 2022-03-06

### Changed
- Update hmac and yanked sha2 versions
- Remove requirement on 'static for claim values

### Added
- Add actix_identity example with readme

## [0.3.0] - 2022-01-12

### Documentation
- Document core module
- Update readme
- Add logo file to new assets directory

## [0.2.0] - 2022-01-02

### Added
- Feature gates for versions, purposes, layers
- Custom Debug implementation for Symmetric Keys
- Custom crates readme

### Changed
- Make serde optional and include with generic layer
- Update documentation to describe feature gates

## [0.1.0] - 2021-12-10

### Added
- Initial public release
- V1 test vectors
- V3 local test vectors
- Feature gates for different PASETO versions
- Support for V1, V2, V3, and V4 PASETO tokens
- Both local (symmetric) and public (asymmetric) support

### Changed
- Swap chronos for time crate
- Refactor keys to align with PASETO spec
- Update keywords and documentation

## [0.1.13] - 2021-10-22

### Added
- Add chrono to Cargo and add paseto_builder (#10)
- extend_claims method to GenericTokenBuilder

## [0.1.10..v0.1.13] - 2021-10-22

### Added
- Add optional closure for custom validation
- Added an optional closure argument to the validate_claim method for custom validation logic
- Added logic in the parse method to run custom validation closures
- PasetoTokenParseError::InvalidClaimValueType(String) for claim values we try to convert to an invalid type
- PasetoTokenParseError::CustomClaimValidation for claims which fail in user provided custom validation closures
- Implement Default trait on all reserved claims
- Implement From(&str) for CustomClaim
- Move chrono from dev dependencies to dependencies
- Added PasetoTokenBuilder in preparation for adding PASETO validation logic

### Fixed
- Repair the readme file from a poor merge

## [0.1.11] - 2021-10-21

### Added
- Create initial commit
- Add strongly typed claims
- Add all 9 shared key test vector cases

### Changed
- Rename structs, move mods, refactor traits
- Generalize dependencies with trait bounds
- Rename unit test mods, add v2localheader struct
- Refactor entire project
- Rename some structs and complete minor edits
- Refactor arbitrary claim to use try_from trait
- Tighten up arbitrary claim api
- Rename claim structs and fix lifetime issues
- Refactor most structs to generics
- Update readme
- Update minor version in Cargo.toml

### Features
- Basic encryption and decryption
- Generic token building and parsing
- Flexible claim validation sans custom validation functions
- All v2.local [PASETO](https://github.com/paseto-standard/test-vectors/blob/master/v2.json) test vectors implemented and successfully passing

### Notes
- Message struct renamed to Payload, moved around mods and refactored conversion traits
- Generalizing some dependencies by using trait bounds in several methods and trait implementations
- Unit test mods were renamed for consistency
- Major refactor to change most structs to generics using version and purpose as arguments
