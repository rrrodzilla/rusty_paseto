# Contributing

When contributing to this repository, please first discuss the change you wish to make via issue,
email, or any other method with the owners of this repository before making a change.

Please note we have a code of conduct, please follow it in all your interactions with the project.

## Architecture Overview

### Feature-Gated Design

This crate uses **mutually exclusive features by design**. The PASETO specification recommends choosing a single version per application. This architectural choice:

- Minimizes binary size by only compiling required cryptographic dependencies
- Enforces compile-time safety through intentionally conflicting trait implementations
- Prevents version mixing that could introduce security vulnerabilities

**Important:** `cargo build --all-features` **will fail**. This is intentional, not a bug.

### Feature Combinations

**Valid combinations:**
```bash
# Single version + purpose
--features v4_local
--features v4_public
--features v1_local

# Same version, both purposes
--features "v4_local,v4_public"

# Default (recommended)
# Enables: batteries_included + v4_local + v4_public
```

**Invalid combinations (will fail at compile time):**
```bash
# Multiple public features
--features "v1_public,v2_public"  # ❌ Trait conflict
--features "v3_public,v4_public"  # ❌ Trait conflict

# All features
--all-features                    # ❌ Enables conflicting features
```

See [Issue #48](https://github.com/rrrodzilla/rusty_paseto/issues/48) for details.

## Development Setup

### Required Tools

```bash
# Install cargo-nextest (used by CI and local development)
cargo install cargo-nextest
```

### Testing

**Match CI behavior** by testing each feature combination individually:

```bash
# Test individual features (matches CI matrix)
cargo nextest run --no-default-features --features v1_local
cargo nextest run --no-default-features --features v2_local
cargo nextest run --no-default-features --features v3_local
cargo nextest run --no-default-features --features v4_local
cargo nextest run --no-default-features --features v1_public
cargo nextest run --no-default-features --features v2_public
cargo nextest run --no-default-features --features v3_public
cargo nextest run --no-default-features --features v4_public

# Test default features
cargo nextest run
```

**Do NOT use:**
```bash
cargo test --all-features  # ❌ Will fail
cargo nextest run --all-features  # ❌ Will fail
```

### Building

```bash
# Build with specific features
cargo build --no-default-features --features v4_local

# Build with default features
cargo build
```

### Linting

```bash
# Run clippy (zero tolerance for warnings)
cargo clippy --all-targets --features v4_local -- -D warnings
cargo clippy --all-targets --features v4_public -- -D warnings

# Format code
cargo fmt
```

## Feature Architecture Layers

The crate has three architectural layers:

1. **`core`** - Bare PASETO cryptographic primitives (no serde, minimal deps)
2. **`generic`** - Customizable builder/parser foundation (adds serde, claims)
3. **`batteries_included`** - Ready-to-use builders with sensible defaults

Version/purpose combinations:
- `v1_local`, `v2_local`, `v3_local`, `v4_local` - Symmetric encryption
- `v1_public`, `v2_public`, `v3_public`, `v4_public` - Asymmetric signing

## Contribution Guidelines

### Before Submitting

1. **Discuss first** - Open an issue before starting work
2. **Test all affected features** - Run the feature-specific tests shown above
3. **Check clippy** - Zero warnings policy
4. **Format code** - Run `cargo fmt`
5. **Update docs** - If adding features or changing public APIs

### Pull Request Process

1. Ensure tests pass for all affected feature combinations
2. Update CHANGELOG.md if applicable
3. Follow conventional commit format: `type(scope): description`
4. Reference related issues with `Closes #123` or `Addresses #123`

### Understanding Test Failures

If your PR fails CI with trait conflicts:
- Check if you're enabling multiple public features
- Verify your changes don't break feature isolation
- Test locally with the exact feature combination that failed

### Common Mistakes

❌ **Don't:** Try to make `--all-features` work
✅ **Do:** Understand this is intentional architectural design

❌ **Don't:** Test only with default features
✅ **Do:** Test all affected feature combinations individually

❌ **Don't:** Add dependencies without feature gates
✅ **Do:** Make new dependencies optional and feature-gated

❌ **Don't:** Implement traits that conflict across versions
✅ **Do:** Keep version-specific code isolated

## Questions?

Open an issue or reach out to the maintainers before starting work.
