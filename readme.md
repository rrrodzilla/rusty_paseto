# rusty_paseto

A type-driven, ergonomic implementation of the [PASETO](https://github.com/paseto-standard/paseto-spec) protocol for secure stateless tokens.

### PASETO: Platform-Agnostic Security Tokens

Paseto is everything you love about JOSE (JWT, JWE, JWS) without any of the
[many design deficits that plague the JOSE standards](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid).

![unit tests](https://github.com/rrrodzilla/rusty_paseto/actions/workflows/rust.yml/badge.svg)
![GitHub](https://img.shields.io/github/license/rrrodzilla/rusty_paseto?label=License)

## Roadmap and Current Feature Status

| APIs, Tests & Documentation | v1.<br />local| v1.<br />public | v2.<br />local | v2.<br />public |v3.<br />local | v3.<br />public | v4.<br />local | v4.<br />public |
| ------------: | :-----------: | :----------:    |:-----------:   |:-----------:    |:-----------:  |:-----------:    |:-----------:   |:-----------:    |
| PASETO Token Builder		| :green_circle: | :green_circle: | :green_circle: | :green_circle: | :green_circle: | :black_circle: | :green_circle: | :green_circle: |
| PASETO Token Parser		| :green_circle: | :green_circle: | :green_circle: | :green_circle: | :green_circle: | :black_circle: | :green_circle: | :green_circle: |
| Flexible Claim Validation	| :green_circle: | :green_circle: | :green_circle: | :green_circle: | :green_circle: | :black_circle: | :green_circle: | :green_circle: |
| Generic Token Builder		| :green_circle: | :green_circle: | :green_circle: | :green_circle: | :green_circle: | :black_circle: | :green_circle: | :green_circle: |
| Generic Token Parser		| :green_circle: | :green_circle: | :green_circle: | :green_circle: | :green_circle: | :black_circle: | :green_circle: | :green_circle: |
| Encryption/Signing		| :green_circle: |  :green_circle: | :green_circle: | :green_circle: | :green_circle: | :black_circle: | :green_circle: | :green_circle: |
| Decryption/Verification	| :green_circle: |  :green_circle: | :green_circle: | :green_circle: | :green_circle: | :black_circle: | :green_circle: | :green_circle: |
| [PASETO Test vectors](https://github.com/paseto-standard/test-vectors)  | :black_circle: | :black_circle: | :green_circle: | :green_circle: | :black_circle: | :black_circle: | :green_circle: | :green_circle: |
| Documentation			| :black_circle: | :black_circle: | :orange_circle: | :black_circle: | :black_circle: | :black_circle: | :black_circle: | :black_circle: |

