# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Added [Takumi Guard](https://github.com/flatt-security/setup-takumi-guard-rubygems) to CI
  (blocking-only mode, no account required) so `bundle install` routes through a proxy that
  blocks known-malicious gems before they reach the build.
- Added `bundler-audit` to CI to continuously check dependencies against the Ruby Advisory
  Database, and patched the vulnerabilities it immediately found: `sqlite3` (Use-After-Free,
  GHSA-mwm8-39rw-8826), `json` (crash on truncated input, CVE-2026-71847), and
  `loofah`/`rails-html-sanitizer` (SVG local-reference bypass / XSS).
- CI now installs gems with `BUNDLE_FROZEN=true` instead of relying on `bundler-cache: true`,
  so a `Gemfile.lock` that drifts from `Gemfile` fails the build instead of silently updating.
- Enabled Dependabot security alerts on the GitHub repository (detection/notification only; no
  automatic PRs).

### Changed

- Clarified in README that the crypto-agility claim applies at the KEM/SIG algorithm-name level
  only; the classical curve (X25519), HKDF hash (SHA-256), and symmetric cipher (AES-256-GCM) used
  by `HybridKem` are hardcoded and not currently swappable.
- Documented in `docs/THREAT_MODEL.md` that IETF's TLS working group voted to keep hybrid key
  exchange mandatory (rejecting a standalone ML-KEM draft), reinforcing `HybridKem`'s design
  choice, and added a note tracking NIST's additional signature Round 3 candidates (including the
  2026-07-28 AI-discovered structural weakness in HAWK).
- Clarified in README and `docs/THREAT_MODEL.md` that TLS-layer PQC adoption by CDNs/edge
  providers (e.g. Cloudflare's origin-connection auto-enable) does not cover the application-layer
  data protection `pqc_rails` provides.

## [0.1.0] - 2026-07-22

### Added

- FFI bindings to [liboqs](https://github.com/open-quantum-safe/liboqs) for NIST-standardized
  post-quantum algorithms: ML-KEM (FIPS 203, levels 512/768/1024) and ML-DSA (FIPS 204, levels
  44/65/87), exposed as `PqcRails::Kem` and `PqcRails::Sig`.
- `PqcRails::Algorithms` registry resolving symbols (e.g. `:ml_kem_768`) to liboqs algorithm
  names, while still allowing raw liboqs strings for algorithms outside the registry (e.g.
  Classic McEliece, HQC).
- `PqcRails::HybridKem`: a KEM-DEM hybrid public-key encryption scheme combining X25519 (classical
  ECDH) with a post-quantum KEM via HKDF-SHA256, backed by `PqcRails::EnvelopeCipher`
  (AES-256-GCM).
- `PqcRails::Session::PqcCookieStore`: a drop-in replacement for Rails' `cookie_store` that
  encrypts session data with `HybridKem` instead of the standard AES-256-GCM signed/encrypted
  cookie jar.
- `PqcRails::ActiveRecord::Context` and `PqcRails::Cipher` / `PqcRails::ActiveRecord::KeyProvider`:
  a full `ActiveRecord::Encryption` integration, replacing Rails' default cipher and key provider
  with the `HybridKem`-based implementation.
- Multi-generation key rotation for both the session store and `ActiveRecord::Encryption`:
  `previous_keypairs` support lets old keys keep decrypting existing data/sessions while new
  writes use the current key.
- `pqc_rails:install` generator, scaffolding the initializer and writing session/record keys to
  Rails credentials.
- `docs/MIGRATION.md`: dual-stack migration guide (adopting `pqc_rails` alongside existing
  encrypted data), key rotation procedure, key-loss recovery guidance, and rollback steps.
- `docs/THREAT_MODEL.md` and `docs/CRYPTO_INVENTORY.md`: threat model and crypto-inventory
  documentation for decision-makers and developers.
- CI workflow building liboqs from source and running the test suite on push/PR.

[Unreleased]: https://github.com/mabutast/pqc_rails/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mabutast/pqc_rails/releases/tag/v0.1.0
