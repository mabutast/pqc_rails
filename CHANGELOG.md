# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
