# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- `PqcRails::Error` raised by the session encryption no longer keeps the original exception as its `cause` when
  that exception's message can hold session data or connection details. When a session is written, a session
  value that cannot be converted to UTF-8 (with `session_serializer = :json`) and a failure to compare the session
  key with per-attribute key providers no longer pass part of the session value or connection details to error
  pages and error reporting services that show the `cause`. When `PqcRails::Session::Encryptor#decrypt` is
  called directly, invalid JSON in a session cookie no longer keeps part of the decrypted cookie in the `cause`.
- With `session_serializer = :json`, a session string that is labeled UTF-8 but holds invalid bytes, a
  symbol that cannot be converted to UTF-8, and a session key (at the top level or in a nested hash) that is not valid UTF-8, now raise
  `PqcRails::Error` without the value, the key or a `cause`. Before, they raised `JSON::GeneratorError`, whose
  `invalid_object` held the unencrypted value or key. Keys that can be converted to UTF-8 are stored as UTF-8;
  two keys that become the same key in UTF-8 raise `PqcRails::Error` instead of losing one of the values. While writing
  with `:marshal`, `session_not_json_safe.pqc_rails` also reports these values, and reports a key that is not
  valid UTF-8 under a fixed name instead of the key itself.
- A legacy (v0) session cookie is now rejected on the authentication key and `accept_legacy_cookies_until`
  checks before the session key is compared with record keys. Before, every such cookie ran that comparison,
  which reads the encrypted attributes of every model, so any request carrying such a cookie could trigger it.

### Fixed

- `pqc_rails:status` now compares the previous session keys with the record keys when the current session
  key is not set. Before, it reported that legacy cookies are read without comparing them.
- The `TypeError` raised when a key pair, a KEM result or a `PqcRails::EnvelopeCipher` is passed to
  `Marshal.dump` no longer suggests `PqcRails::KeySource.encode`. That method returns a string that contains
  the secret key, so storing its result in a cache, a job argument or a file stores the key there. The message
  now says not to store these objects in caches, job arguments or files, and to keep keys in Rails credentials
  or environment variables and load them when needed. Use `PqcRails::KeySource.encode` only to create the
  value for credentials or an environment variable.

## [0.7.1] - 2026-11-25

### Security

- While legacy session cookies are read (before `accept_legacy_cookies_until` or with `ciphertext_format = :v0`),
  a legacy cookie is now refused when the session key is also the key of a per-attribute
  `PqcRails::ActiveRecord::KeyProvider` (`encrypts ..., key_provider:`, including `previous:`), not only the
  database key of the context. Only models that are loaded at that time are compared, so with lazy loading
  (`config.eager_load = false`) a model that has not been loaded yet is not compared. Rails' own key providers
  are not compared when all their keys are AES keys; a Rails key provider that holds a pqc_rails key pair
  cannot be compared, so legacy cookies are refused. If an attribute uses a custom key provider that does not return public keys
  (`#public_keys`), the keys cannot be compared and legacy cookies are refused. `rails pqc_rails:status` reports
  the same-key condition, and reports that legacy cookies are not read when the per-attribute keys cannot be
  checked or the models fail to load, instead of stopping.
- `PqcRails::HybridKem` now overwrites with zeros the X25519 and ML-KEM secret keys made during key
  generation, the X25519 and ML-KEM shared secrets before they are combined, and their concatenation
  passed to HKDF, as soon as they are no longer needed, including when an error is raised. The combined
  shared secret and the AES key derived from it are not overwritten.

## [0.7.0] - 2026-11-25

### Security

- With Rails' 6.1 marshalling format (`config.load_defaults` below 7.1), `Marshal.dump` of a record
  wrote the current and previous database secret keys and authentication keys into the dump when the encrypted attribute
  was given `key_provider: PqcRails::ActiveRecord::KeyProvider.new`, directly or in a `previous:`
  scheme, after that key provider had read its keys. Caching such a record (`Rails.cache`) stored the
  keys in the cache. `PqcRails::ActiveRecord::KeyProvider` and the default key source now write only
  where the keys come from, and read the keys again after loading. If your application cached such
  records, update all servers, clear the cache, and rotate the database key. Servers on 0.6.0 or
  earlier cannot read key providers cached by 0.7.0, so clear the cache again if you roll back. A
  custom key source passed to a per-attribute `KeyProvider` is written as is, so it must not keep keys
  in a form that `Marshal` writes.

### Changed

- **Breaking:** `Marshal.dump` of a key pair, a KEM result (`Encapsulation`) or
  `PqcRails::EnvelopeCipher` now raises `TypeError`, and so does `Marshal.dump` of an object that
  holds one (such as `PqcRails::Session::Encryptor`). Previously the dump contained the secret values
  as is, so a key object stored in `Rails.cache` or a file was readable there. The error message does
  not contain secret values. Store keys with `PqcRails::KeySource.encode`. Records with encrypted
  attributes can still be marshaled with both the 6.1 and 7.1 formats when they use the default key
  source.

## [0.6.0] - 2026-11-24

### Added

- `PqcRails.configuration.session_serializer = :json` writes session cookies in a new format (v2)
  whose content is JSON instead of `Marshal`. Reading a v2 cookie never calls `Marshal.load`.
  The format version is part of the AES key derivation and the associated data, so v1 and v2
  cookies cannot be swapped. Strings, integers, finite floats, `true`, `false`, `nil`, arrays and
  hashes with string keys are accepted; symbol values are stored as strings. Other values (such
  as `Time`, symbol keys, or custom objects) raise `PqcRails::Error` when the session is saved.
  The default stays `:marshal`. All versions from 0.6.0 read both v1 and v2 cookies.
- `accept_marshal_cookies_until`: while `session_serializer` is `:json`, `Marshal` cookies
  (formats v0 and v1) are read only until this time. With the default `nil` they are not read.
- With `:marshal`, a `session_not_json_safe.pqc_rails` event reports the top-level session keys
  whose values would not survive JSON (key names only, no values). See `docs/MIGRATION.md`,
  "セッションの中身を JSON に切り替える".

## [0.5.0] - 2026-11-24

### Added

- `rails pqc_rails:status` reports encrypted columns that are too short for the
  ciphertext and `string` columns that longer values can overflow. `PqcRails::ActiveRecord::ColumnCapacity`
  provides `too_short`, `may_overflow`, and `too_long`. The task now exits with status 1 when a
  column is too short for the ciphertext. The check is skipped when the database is unavailable.

### Fixed

- The README and `docs/MIGRATION.md` now state that encrypted columns need the `text` type.
  A MySQL `string` column (255 characters) cannot hold a ciphertext: the write raises
  `ActiveRecord::ValueTooLong` in strict mode, and with `strict: false` the value is truncated
  and cannot be recovered. Run `rails pqc_rails:status`, and change any reported column to `text`.

## [0.4.1] - 2026-11-24

### Fixed

- `rails generate pqc_rails:install` now also generates the database key (`pqc_record_key`).
  Previously it wrote only the session key, so the first write to an encrypted column raised
  `PqcRails::MissingKeyError` in a new installation.
- `rails generate pqc_rails:install` no longer replaces keys that are already set in Rails
  credentials or in `PQC_SESSION_KEY` / `PQC_RECORD_KEY`, and no longer overwrites an existing
  `config/initializers/pqc_rails.rb`. Previously, running it again replaced `pqc_session_key`,
  which ended existing sessions. If this happened and the earlier key is still available, add it
  to your list of previous session keys (`pqc_session_previous_keys` in credentials, or
  `PQC_SESSION_PREVIOUS_KEYS`, which takes precedence over the credentials list when set).
- `rails generate pqc_rails:install` warns about a configured key that is empty, invalid or
  generated by 0.3.0 or earlier, and keeps it.
- `rails generate pqc_rails:install` appends new keys to Rails credentials instead of rewriting the
  file, so comments are kept and credentials containing dates no longer stop it. With `--pretend`
  and `rails destroy` it no longer writes keys. If keys cannot be appended without changing an
  existing value, it writes nothing and exits with a failure status.

## [0.4.0] - 2026-11-23

### Added

- Platform gems for x86_64-linux-gnu, aarch64-linux-gnu, x86_64-linux-musl, aarch64-linux-musl
  and arm64-darwin bundle a prebuilt liboqs, so `bundle install` no longer needs CMake or a C
  compiler on those platforms. The prebuilt liboqs does not depend on OpenSSL, selects optimized
  code for the CPU at run time, and on Linux runs on glibc 2.28 or later or on musl. Other
  platforms keep installing the source gem, which builds liboqs as before.
- Ciphertexts for ActiveRecord columns and session cookies now record a format version, the
  algorithm that produced them (for example `X25519+ML-KEM-768`) and the id of the key used. These
  values are authenticated as AES-GCM associated data. Decryption uses the recorded algorithm, so
  changing `pq_alg_name` no longer makes existing records and cookies undecryptable, and only keys
  with a matching id are tried. Only registered algorithms and the configured algorithm are
  accepted from a ciphertext. See "暗号文の形式" in the README and the algorithm change procedure
  in docs/MIGRATION.md.
- `PqcRails.configuration.ciphertext_format`: set to `:v0` to keep writing the 0.3.0 format while
  servers are updated one by one, then remove the setting. Defaults to `:v1`.
- `PqcRails::ActiveRecord::Context.install!` accepts `key_provider:`, so a custom key source can be
  passed as described in docs/MIGRATION.md.
- `PqcRails.configuration.accept_legacy_records`: set to `false` to reject ActiveRecord ciphertexts
  in the 0.3.0 format once all records have been re-encrypted. Defaults to `true`.
- `PqcRails.configuration.accept_legacy_cookies_until`: a `Time` until which session cookies in the
  0.3.0 format are read with keys generated by 0.3.0 or earlier. To keep existing sessions when
  upgrading, set it to the time the last server stops writing the 0.3.0 format plus the longest
  session lifetime. Defaults to `nil`: these cookies are rejected, except while `ciphertext_format`
  is `:v0`.
- A `decryption_failed.pqc_rails` ActiveSupport::Notifications event is published when an
  encrypted column or a session cookie cannot be decrypted, with the target (`:record` or
  `:session`) and the exception class. Failures that are part of ActiveRecord trying `previous:`
  schemes in turn are not reported.
- `PqcRails.liboqs_version` returns the version of the loaded liboqs, and `rails pqc_rails:status`
  shows it.
- `rails pqc_rails:status` lists the model attributes encrypted with `encrypts` (eager loading the
  application first) and the algorithm ids that new database and session ciphertexts use.
- `PqcRails::ActiveRecord::CiphertextInfo.parse(record.ciphertext_for(:attr))` reads the format
  version, algorithm id and key id of a stored ciphertext without decrypting it, so records still
  using an old key or the 0.3.0 format can be identified. `PqcRails::Cipher#algorithm_id` returns
  the algorithm id written to new ciphertexts.
- Key pairs generated by `PqcRails::HybridKem#generate_keypair` include a random 32-byte
  authentication key, stored as a third element of the encoded key. `rails pqc_rails:status`
  reports keys without one.

### Changed

- A key value of 32 or 64 bytes whose first byte is not zero, such as most ML-KEM or ML-DSA seeds
  (a pqc_rails key value always starts with a zero byte), now fails with a message saying it looks like a seed-only secret key and pointing to
  `rails generate pqc_rails:install`, instead of saying the key is truncated. `rails pqc_rails:status`
  reports the same. The error is still a `PqcRails::Error`, and which values are accepted is unchanged.
- `PqcRails::Sig#verify` returns `false` when the signature is not a String (for example `nil`
  from a missing request parameter) instead of raising `NoMethodError`. `PqcRails::Sig#sign` and
  `#verify` raise `ArgumentError` instead of `NoMethodError` when the message is not a String, as
  they already do for keys.
- docs/THREAT_MODEL.md states precisely how `PqcRails::Sig#verify` handles input lengths: a signature
  longer than the maximum returns `false` without calling liboqs, a shorter one is checked by liboqs and
  returns `false`, and a public key of the wrong length raises `ArgumentError`.
- docs/THREAT_MODEL.md describes what the in-memory secret key is protected from before what it is
  not: the key never reaches the database, backups or logs, and an attacker who can read the running
  process's memory is treated as holding that process's privileges, as in any software that keeps
  keys in-process. The facts and recommended mitigations are unchanged.
- **Requires Ruby 3.3 or later.** Ruby 3.2 reached its end of life on 2026-04-01 and is no longer
  supported. Ruby 4.0 is now tested in CI alongside 3.3 and 3.4.
- README adds ML-DSA key and signature sizes (and why SLH-DSA is not registered), explains the
  constant-time and standards-based reasons for building on liboqs, and mentions DARPA's Quantum
  Benchmarking Initiative. docs/THREAT_MODEL.md adds the NIST IR 8547 (final version) timeline,
  the EU supervisory authorities' autumn 2026 risk update, DARPA QBI, and states that liboqs is not a
  FIPS 140-3 validated module.
- README notes the German BSI's 2026-10-01 recommendation not to use Classic McEliece in new
  developments, states that ML-KEM and ML-DSA are standardized in FIPS 203 and FIPS 204, and
  lists blockchain and cryptocurrency transaction signatures as out of scope.
- README lists, for each protected value (session cookies, encrypted columns, signatures, TLS),
  the cryptography Rails uses by default and what pqc_rails uses instead.
- README states that the default ML-KEM-768 is the parameter set NIST IR 8547 recommends as the
  default for key establishment. docs/THREAT_MODEL.md notes that NIST IR 8547 typically expects
  hybrid key establishment to be a temporary measure leading to a second transition to PQC-only
  algorithms.
- README's API stability section now lists the key generation and encoding calls used in
  docs/MIGRATION.md (`HybridKem.open` with `#generate_keypair`, `KeySource.encode` / `.decode`),
  `CiphertextInfo`, `Cipher#algorithm_id`, `CiphertextFormat.key_id`, the new configuration
  options and `MissingAuthenticationKeyError` as stable API.
- docs/MIGRATION.md adds a guide for replacing application-level RSA / ECDH data-key wrapping with
  pqc_rails encrypted columns.
- docs/MIGRATION.md re-encrypts with `user.with_lock { user.encrypt }` so updates made while the
  application keeps running are not overwritten, shows how to count records still using an old
  key or the 0.3.0 format with `CiphertextInfo`, and states that public keys need not be
  distributed.
- Keys generated by 0.3.0 and earlier have no authentication key and cannot write the new
  ciphertext format; doing so raises `PqcRails::MissingAuthenticationKeyError`. They can still
  decrypt existing data and write the 0.3.0 format with `ciphertext_format = :v0`. Generate new keys
  and rotate to them when upgrading; see "0.3.0 以前からの更新" in docs/MIGRATION.md. Keys in the new
  encoding can still be read by 0.3.0, which uses only the public and secret key.
- Ciphertexts grow by about 60 bytes per ActiveRecord column and about 30 bytes per session cookie
  with ML-KEM-768. ActiveRecord ciphertexts written in the 0.3.0 format are still decrypted, using
  the configured algorithm. Ciphertexts written in the new format cannot be decrypted by 0.3.0 or
  earlier, so roll back only data written with `ciphertext_format = :v0`.
- `PqcRails::HybridKem` public keys and ciphertexts, the KEM ciphertext of encrypted ActiveRecord
  attributes and session cookies with extra bytes after their last component now raise
  `ArgumentError` (`ActiveRecord::Encryption::Errors::Decryption` for attributes, `PqcRails::Error`
  for cookies). Previously the extra bytes were ignored, so the same plaintext could have more than
  one valid encoding and a value with appended data was accepted silently. Values written by
  pqc_rails never have extra bytes, so existing records, cookies and keys read as before. Hybrid
  secret keys and key values are read as before.

### Security

- When a key value cannot be read, the raised `PqcRails::Error` no longer carries the internal
  unpacking error as its `cause`. That error's message held the first four bytes of the key value,
  so error reports that include the cause could show part of a secret key or seed.
- Key pairs (`PqcRails::Sig::Keypair`, `Kem::Keypair`, `DhKem::Keypair` and
  `HybridKem::Keypair`) no longer show secret key bytes in `inspect`, `to_s`, `pp` (used by IRB
  and the Rails console) or string interpolation. Secret keys and the authentication key appear as
  `[FILTERED]` and public keys as their length in bytes. `keypair.secret_key`, `to_a` and `==` are
  unchanged.
- KEM results (`Kem::Encapsulation`, `DhKem::Encapsulation` and `HybridKem::Encapsulation`) no
  longer show the shared secret in `inspect`, `to_s`, `pp` or string interpolation. The shared
  secret appears as `[FILTERED]` and the ciphertext as its length in bytes.
- Key pairs and KEM results no longer expose secret values through `as_json` and `to_json`, which
  `render json:` and JSON logs use. Public keys and ciphertexts appear as their length in bytes and
  other values as `[FILTERED]`. Values read explicitly (`shared_secret`, `to_h`, `to_a`) and `==`
  are unchanged, so passing those values to a log or to JSON still reveals them.
- `PqcRails::EnvelopeCipher` no longer shows its AES key in `inspect`, `pp`, `as_json` or `to_json`.
- Key pairs, KEM results and `EnvelopeCipher` no longer expose secret values in YAML (`to_yaml` and
  the Rails `debug` view helper). They are written as a plain map with the same content as
  `as_json`, and loading that YAML does not restore a key object. **Key pairs saved with `to_yaml`
  no longer contain their secret key**; store keys with `PqcRails::KeySource.encode`. `Marshal.dump`
  still contains the secret values, so do not store these objects in a cache or a log with it.
- Ciphertexts in the new format authenticate their creator. In 0.3.0 and earlier, the KEM shared
  secret was used directly as the AES-256-GCM key, so anyone who knew the public key could create
  ciphertexts that decrypt successfully: forged session cookies (for example with an arbitrary
  `user_id`), or arbitrary values in encrypted columns for someone able to write to the database.
  The AES key is now derived from both the KEM shared secret and a separate random authentication
  key held with the key pair, so the authentication key is required to create a ciphertext. With
  the default key storage (`PQC_SESSION_KEY` / `PQC_RECORD_KEY` or Rails credentials), the public
  key is stored together with the secret key and is not exposed, so this was not exploitable unless
  the public key was disclosed separately. Ciphertexts in the 0.3.0 format remain forgeable with the public
  key; reject ActiveRecord ciphertexts with `accept_legacy_records` once they are no longer needed.
- Session cookies in the 0.3.0 format are no longer read by default, because their content is
  restored with `Marshal.load` and a cookie forged with the public key could lead to code execution.
  **Existing sessions end when upgrading** unless `accept_legacy_cookies_until` is set. These
  cookies are read only with keys generated by 0.3.0 or earlier, before that deadline or while
  `ciphertext_format` is `:v0`. They are not read when the session key is also configured as a
  current or previous record key, because the 0.3.0 format cannot distinguish the two uses.
- ActiveRecord ciphertexts in the 0.3.0 format are now decrypted only with keys generated by 0.3.0
  or earlier, so a value forged with a newer key's public key is rejected. Keep the original key as
  a previous key until the records are re-encrypted. With a newer key, `ciphertext_format = :v0`
  raises `PqcRails::Error` when writing a column value or a session cookie.
- Ciphertexts in the new format are bound to their use. The AES key derivation and associated data
  distinguish ActiveRecord columns from session cookies, so with the same key configured for both,
  a stored column value cannot be presented as a session cookie.
- An authentication key that is not a 32-byte string is now rejected instead of being used to
  derive the AES key.
- Secret keys and shared secrets passed to and from liboqs are now zeroed in the native buffers
  after each key generation, encapsulation, decapsulation and signature. Previously these buffers
  were freed by the garbage collector without being cleared. Secret keys held as Ruby Strings cannot
  be wiped reliably and stay in memory for the life of the process; see "中間値の破棄" in
  docs/THREAT_MODEL.md.
- Fewer copies of secret keys are left in Ruby memory. Keys are decoded once per key source and
  kept, instead of the previous keys being decoded again on every decryption, and the decoded key
  blob and the X25519 and ML-KEM secret key copies made during decapsulation are zeroed after use.
  Keys are therefore read once per process; restart the application after changing them, as was
  already needed for the current key. docs/THREAT_MODEL.md lists what remains in memory and
  recommends disabling core dumps and unencrypted swap in production.
- The bundled liboqs source is pinned to the upstream commit of its release tag. Gem builds and the
  development fallback that clones liboqs stop if the tag resolves to a different commit, and
  `rake vendor:verify` compares the bundled source file by file with that commit. Pass `DIR=` to
  check the `ext/pqc_rails/vendor/liboqs` directory of a gem unpacked with `gem unpack`.

### Fixed

- `PqcRails::Cipher#decrypt` no longer raises `NoMethodError` when ActiveRecord passes keys that
  are not pqc_rails key pairs. This happens when Rails' standard encryption was configured
  (`primary_key` set) and ActiveRecord adds previous schemes; an unreadable value now raises
  `ActiveRecord::Encryption::Errors::Decryption` as expected.
- `bundle install` now builds liboqs correctly when the gem is installed under a path containing
  spaces. The build scripts run `git` and `cmake` directly with argument lists instead of through
  a shell, so the install path is no longer split or interpreted by the shell.
- `nil` keys and ciphertexts passed to `PqcRails::Kem` and `PqcRails::DhKem` now raise
  `ArgumentError` instead of `NoMethodError`. Truncated or empty keys and ciphertexts passed to
  `PqcRails::HybridKem` raise `ArgumentError` stating that the input is truncated, instead of
  `TypeError` or `NoMethodError`. A `PqcRails::EnvelopeCipher` ciphertext shorter than the IV and
  the 16-byte authentication tag raises `ArgumentError` before decryption, instead of an OpenSSL
  error.
- A truncated session cookie now raises `PqcRails::Error`, for both the current and the 0.3.0
  format. `PqcRails::Session::PqcCookieStore` treats it as an unreadable session as before.
- A key value in `ENV` or Rails credentials that is cut short now raises `PqcRails::Error` when
  the key is loaded, and `rails pqc_rails:status` reports it instead of stopping. This also applies
  to previous keys, so a cut-short previous key stops the application in the same way as a missing
  current key. Previously such a key loaded and failed only when it was used.
- Encrypted ActiveRecord attributes holding non-ASCII text (for example Japanese) are now read back
  as UTF-8 strings. Previously they were returned with the `ASCII-8BIT` (binary) encoding, so they
  did not compare equal to the original string and could raise `Encoding::CompatibilityError` when
  combined with UTF-8 strings in views. Stored ciphertexts are unchanged; existing records read
  correctly after updating. Binary attributes are still returned as binary. Strings in encodings
  other than UTF-8 are not restored to their original encoding.

## [0.3.0] - 2026-09-25

### Changed

- pqc_rails is now licensed under the Apache License 2.0 instead of the Business Source License
  1.1. Commercial and non-commercial use, modification and redistribution are free, with no
  restriction on hosted or embedded offerings. The license includes an explicit patent grant
  (Section 3) and a limitation of liability (Section 8). The gemspec `license` field is now
  `Apache-2.0`. Versions up to and including 0.2.1, previously released under the Business Source
  License 1.1, are also made available under the Apache License 2.0.

## [0.2.1] - 2026-09-22

### Added

- `rails pqc_rails:status` reports whether the session/record keys are configured, whether key
  rotation (previous keys) is in progress, whether `:pqc_cookie_store` is active, and whether
  `PqcRails::ActiveRecord::Context.install!` has been called — so setup mistakes surface before
  they hit production traffic instead of on the first real encrypt/decrypt. Exits non-zero if any
  check fails, for use in CI or deploy hooks. The underlying `PqcRails::StatusCheck.run` is also
  available for programmatic use (e.g. in a custom health-check endpoint).
- README now documents Puma worker/thread guidance: pqc_rails' encrypt/decrypt throughput doesn't
  improve with more threads (CRuby's GVL serializes the FFI calls into liboqs), only with more
  worker processes (Puma cluster mode), and worker counts beyond the container's CPU quota make
  throughput worse, not better.

### Fixed

- On Ruby 3.2, `HybridKem`/`DhKem` raised `NoMethodError` (`undefined method 'raw_public_key'`)
  because Ruby 3.2's bundled `openssl` gem predates the version that added
  `OpenSSL::PKey::PKey#raw_public_key`/`#raw_private_key`. The gemspec now declares
  `openssl >= 3.2` explicitly so `bundle install` always resolves a compatible version.
- [docs/MIGRATION.md](docs/MIGRATION.md)'s bulk re-encryption instructions recommended `save!`,
  which silently does nothing when the decrypted value hasn't changed (ActiveRecord's dirty
  tracking skips the UPDATE). Now recommends `record.encrypt`, which re-encrypts unconditionally.
  The rollback code sample also now notes that `PqcRails::Cipher.new`'s `pq_alg_name:` must match
  whatever was passed to `Context.install!`, or decryption fails silently for non-default
  algorithms such as `:ml_kem_512`.
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)'s FIPS shall-requirements table hadn't been updated
  since an earlier audit and understated pqc_rails' actual compliance: it listed RNG strength as
  unverified, when a later source audit of liboqs had already confirmed it meets every parameter
  set's required strength. It also listed intermediate-value zeroization as asymmetric between
  ML-KEM (satisfied) and ML-DSA (not satisfied) at the liboqs vendor-library level; bumping the
  default bundled liboqs to 0.16.0 (see Changed) closes that gap too, since its ML-DSA
  implementation (`mldsa-native`) now zeroizes intermediate values just like ML-KEM's does.
  Updated the table to match.
- README's HQC example (`PqcRails::Kem.open("HQC-1")`) didn't work against the liboqs `bundle
  install` actually builds by default: HQC is disabled by default in liboqs 0.15.0
  (`OQS_ENABLE_KEM_HQC` defaults to off) and only defaults to enabled starting in 0.16.0, so the
  example failed with `PqcRails::Error` out of the box. Fixed by bumping the default bundled
  liboqs to 0.16.0 (see Changed), where the example now works unmodified.

### Changed

- The liboqs version `bundle install` builds by default is now 0.16.0 (was 0.15.0). Verified
  against liboqs's own release notes and source: the `OQS_KEM`/`OQS_SIG` struct layouts and the
  `OQS_KEM_*`/`OQS_SIG_*` functions pqc_rails calls via FFI are unchanged between the two
  versions, and the full test suite passes unmodified against a 0.16.0 build. `--skip-liboqs`
  with a manually supplied liboqs 0.15.0 remains supported and is checked in CI as a backward-
  compatibility case.
- CI now runs the test suite across the full supported matrix (Ruby 3.2/3.3/3.4 × Rails 7.1/8.1,
  plus liboqs 0.15.0 on the newest Ruby/Rails combination as a backward-compatibility check) on
  every push and pull request, instead of a single combination with the rest verified manually.
- Added an "API の安定性" section to the README, declaring which classes/methods are the stable
  public API (intended to be covered by SemVer once 1.0 ships) versus internal implementation
  detail that may change without notice.

### Removed

- Removed `PqcRails::Session::KeyManager.encode`/`.decode`, which only ever delegated to
  `PqcRails::KeySource.encode`/`.decode`. Use `PqcRails::KeySource.encode`/`.decode` directly.

## [0.2.0] - 2026-09-20

### Added

- `bundle install` now builds liboqs automatically from source vendored in the gem (via
  `ext/pqc_rails/extconf.rb`, populated by the new `rake vendor:liboqs` release task), so a fresh
  install needs no pre-existing liboqs setup. Verified on macOS (arm64) and Linux (arm64, via
  Docker); Windows and x86_64 remain unverified. Users who already have liboqs installed, or who
  lack a C build toolchain, can skip the build with `bundle config set build.pqc_rails
  --skip-liboqs` (or `PQC_RAILS_SKIP_LIBOQS_BUILD=1`) and point `config.liboqs_path` at their own
  copy. Added `NOTICE.md` documenting liboqs's MIT license and the permissive third-party
  algorithm-implementation licenses it bundles.

  **Note for existing installs**: if you were relying on a manually-installed system liboqs
  without setting `LIBOQS_PATH` or `config.liboqs_path` explicitly, a fresh `bundle install`
  after upgrading will now prefer the bundled build over your system copy. This should be
  behaviorally identical for the default build, but if you built your system liboqs with custom
  options, set `config.liboqs_path` explicitly (or `--skip-liboqs`) to keep using it.

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
  reference implementations directly.
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

[Unreleased]: https://github.com/mabutast/pqc_rails/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/mabutast/pqc_rails/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/mabutast/pqc_rails/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/mabutast/pqc_rails/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/mabutast/pqc_rails/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/mabutast/pqc_rails/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/mabutast/pqc_rails/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/mabutast/pqc_rails/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mabutast/pqc_rails/releases/tag/v0.1.0
