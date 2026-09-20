# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `bundle install` now builds liboqs automatically from source vendored in the gem (via
  `ext/pqc_rails/extconf.rb`, populated by the new `rake vendor:liboqs` release task), so a fresh
  install needs no pre-existing liboqs setup. Verified on macOS (arm64) and Linux (arm64, via
  Docker); Windows and x86_64 remain unverified. Users who already have liboqs installed, or who
  lack a C build toolchain, can skip the build with `bundle config set build.pqc_rails
  --skip-liboqs` (or `PQC_RAILS_SKIP_LIBOQS_BUILD=1`) and point `config.liboqs_path` at their own
  copy. Added `NOTICE.md` documenting liboqs's MIT license and the permissive third-party
  algorithm-implementation licenses it bundles.

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
- Added a [Trusted Publishing](https://guides.rubygems.org/trusted-publishing/) release workflow
  (`.github/workflows/release.yml`) so publishing to RubyGems.org no longer requires a long-lived
  API key: GitHub Actions authenticates via OIDC to a RubyGems.org Trusted Publisher scoped to
  this repository, workflow, and the `release` environment.
- Added GitHub CodeQL static analysis for Ruby (`.github/workflows/codeql.yml`), running on push,
  pull request, and a weekly schedule.

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
- Documented HAWK's formal withdrawal from NIST's additional-signature Round 3 process (now 8
  candidates) in `docs/THREAT_MODEL.md`.
- Added IonQ's fully-compiled resource estimate for breaking ECDLP-256 (secp256k1), and a note
  tracking a new theoretical quantum algorithm for the dihedral coset problem relevant to the
  lattice assumptions ML-KEM/ML-DSA rely on, to `docs/THREAT_MODEL.md`.
- Documented in README why `pqc_rails` binds to liboqs via FFI rather than bundling algorithm
  reference implementations directly, in response to a newly-appeared competing gem
  (`pq_crypto`) taking the latter approach.
- Updated `docs/THREAT_MODEL.md`'s regulatory-timeline and enterprise-market sections with recent
  developments (EO 14412 deadlines, FIPS 140-3 certified HSM offerings), and added a recommended
  architecture note for combining `pqc_rails` with a FIPS 140-3 certified HSM/KMS via a custom
  `KeySource`.
- Added a crypto-wallet/key-management backend example to README's use-case list.
- Added a README troubleshooting section covering the most common first-install failures
  (liboqs `LoadError`, unknown algorithm, session invalidation on switch, existing-data
  decryption failure).

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
