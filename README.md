# PqcRails

[![Gem Version](https://badge.fury.io/rb/pqc_rails.svg)](https://badge.fury.io/rb/pqc_rails)

**pqc_rails** は、既存の Ruby on Rails アプリケーションに耐量子暗号（PQC: Post-Quantum Cryptography）を組み込むための gem です。[liboqs](https://github.com/open-quantum-safe/liboqs) への FFI バインディングを通じて、NIST 標準化アルゴリズムを Ruby ネイティブに呼び出します。

ジェネレータを実行した後、2 行の設定を追加するだけで Rails アプリのセッションと DB を PQC 化できます。

```bash
rails generate pqc_rails:install
```

```ruby
# config/application.rb
config.session_store :pqc_cookie_store

# config/initializers/pqc_rails.rb
PqcRails::ActiveRecord::Context.install!
```

## 現在の対応状況

| 機能                          | 状態                                             |
| ----------------------------- | ------------------------------------------------ |
| KEM（鍵カプセル化機構）       | ✅ 対応済み（ML-KEM-512/768/1024 で動作確認）     |
| DSA（署名アルゴリズム）       | ✅ 対応済み（ML-DSA-44/65/87 で動作確認）         |
| セッション暗号化              | ✅ 対応済み（`PqcCookieStore`）                   |
| ActiveRecord::Encryption 連携 | ✅ 対応済み（`PqcRails::Cipher` + `KeyProvider`） |

KEM と DSA に加え、セッション Cookie と ActiveRecord::Encryption の両方を ML-KEM ベースのハイブリッド暗号（KEM-DEM 構成）で保護します。liboqs がサポートする他のアルゴリズムも、アルゴリズム名を文字列で指定するだけで利用できます（liboqs 側のビルド設定に依存します）。

## 必要要件

- Ruby >= 3.2.0
- Rails >= 7.1
- [liboqs](https://github.com/open-quantum-safe/liboqs)（C ライブラリ）がビルド・インストール済みであること
  - 本 gem は liboqs を同梱しません。事前に共有ライブラリ（`liboqs.dylib` / `liboqs.so`）をビルドし、システムに配置してください。

## ⚠️ liboqs の成熟度について

本 gem は [liboqs](https://github.com/open-quantum-safe/liboqs) を基盤としています。liboqs は [Open Quantum Safe (OQS)](https://openquantumsafe.org/) プロジェクトによって開発されている、NIST の耐量子暗号標準化プロジェクトに基づくアルゴリズム実装です。

liboqs 自身の公式ドキュメントでは、以下の点が明記されています：

- liboqs は研究・プロトタイピングを目的としており、**本番環境や機密データの保護に依存することは現時点では推奨されていません**
- セキュリティバグを避けるための最善の努力はされていますが、本番投入に必要な水準の監査・分析はまだ実施されていません

`pqc_rails` は liboqs を「正しく安全に呼び出す」ことに責任を持ちますが、liboqs 自体の暗号実装の正しさ・安全性を保証するものではありません。本番環境への導入を検討される際は、上記の liboqs の現状を踏まえ、利用するシステムの重要度に応じたリスク評価を行ってください。

NIST 標準化アルゴリズム自体（ML-KEM, ML-DSA など）は確定した仕様ですが、その「実装」の成熟度は今後も liboqs 側の改善とともに変わっていく可能性があります。

## インストール

Gemfile に以下を追記:

```ruby
gem "pqc_rails"
```

その後:

```bash
bundle install
rails generate pqc_rails:install
```

ジェネレータが `config/initializers/pqc_rails.rb` を生成し、セッション用・DB 用の鍵を Rails credentials に書き込みます。

## 設定

### liboqs ライブラリパス

liboqs の共有ライブラリへのパスを指定します。未設定の場合、環境変数 `LIBOQS_PATH`、それも無ければ OS ごとの一般的な場所（macOS: `/usr/local/lib/liboqs.dylib`、Linux: `/usr/local/lib/liboqs.so`）を仮定します。

```ruby
# config/initializers/pqc_rails.rb
PqcRails.configure do |config|
  config.liboqs_path = "/usr/local/lib/liboqs.dylib"
end
```

### セッション暗号化

```ruby
# config/application.rb
config.session_store :pqc_cookie_store
```

Rails の `cookie_store` を ML-KEM ベースの PQC ストアで完全に置き換えます。既存のセッションは切り替え時に無効化されます（全ユーザーが再ログインになります）。

鍵は Rails credentials の `pqc_session_key` から読み込みます。環境変数 `PQC_SESSION_KEY` で上書き可能です。

### ActiveRecord::Encryption

```ruby
# config/initializers/pqc_rails.rb
PqcRails::ActiveRecord::Context.install!
```

```ruby
# モデル
class User < ApplicationRecord
  encrypts :email, :phone_number
end
```

`ActiveRecord::Encryption` の Cipher と KeyProvider を ML-KEM ベースの実装に置き換えます。新規導入の場合はそのまま利用できます。既存の ActiveRecord::Encryption（Rails デフォルト）で暗号化済みのデータがある場合、切り替え後に復号できなくなるため、事前に再暗号化が必要です。

鍵は Rails credentials の `pqc_record_key` から読み込みます。環境変数 `PQC_RECORD_KEY` で上書き可能です。セッション用の鍵とは別管理です。

## 使い方

### アルゴリズムの指定方法

`PqcRails::Kem` / `PqcRails::Sig` は、liboqs の生のアルゴリズム名文字列（`"ML-KEM-512"` 等）に加えて、シンボル（`:ml_kem_512` 等）でも指定できます。シンボルは `PqcRails::Algorithms` レジストリ経由で liboqs 名に解決されます。

```ruby
PqcRails::Kem.new(:ml_kem_512)   # シンボル指定（推奨）
PqcRails::Kem.new("ML-KEM-512")  # liboqs の生の名前を直接指定
```

現在レジストリに登録済みのアルゴリズム：

| 種別 | シンボル                                       | NIST セキュリティレベル |
| ---- | ---------------------------------------------- | ----------------------- |
| KEM  | `:ml_kem_512` / `:ml_kem_768` / `:ml_kem_1024` | 1 / 3 / 5               |
| SIG  | `:ml_dsa_44` / `:ml_dsa_65` / `:ml_dsa_87`     | 2 / 3 / 5               |

未登録のシンボルを渡すと `PqcRails::Algorithms::UnknownAlgorithmError`（`PqcRails::Error` のサブクラス）が発生します。

### 鍵交換（KEM）の基本フロー

```ruby
PqcRails::Kem.open("ML-KEM-512") do |kem|
  # 受信側: 鍵ペアを生成
  keypair = kem.generate_keypair

  # 送信側: 受信側の公開鍵から共有秘密と ciphertext を生成
  encapsulation = kem.encapsulate(keypair.public_key)

  # 受信側: ciphertext と自分の秘密鍵から共有秘密を復元
  shared_secret = kem.decapsulate(encapsulation.ciphertext, keypair.secret_key)

  shared_secret == encapsulation.shared_secret # => true
end
```

`PqcRails::Kem.open` はブロックを抜けると自動的にネイティブメモリを解放します。手動でリソースを管理したい場合は `new` / `free` を直接使うこともできます。

```ruby
kem = PqcRails::Kem.new("ML-KEM-512")
# ...
kem.free
```

#### 鍵長の参照

```ruby
kem = PqcRails::Kem.new("ML-KEM-512")
kem.length_public_key    # => 800
kem.length_secret_key    # => 1632
kem.length_ciphertext    # => 768
kem.length_shared_secret # => 32
```

### 署名（DSA）の基本フロー

```ruby
PqcRails::Sig.open("ML-DSA-44") do |sig|
  # 署名者: 鍵ペアを生成
  keypair = sig.generate_keypair

  # 署名者: メッセージに署名
  signature = sig.sign("hello world", keypair.secret_key)

  # 検証者: 署名を検証
  sig.verify("hello world", signature, keypair.public_key) # => true
end
```

`verify` は、署名が無効な場合に例外を発生させず `false` を返します（liboqs の `OQS_SIG_verify` の挙動に準拠）。

```ruby
sig.verify("tampered message", signature, keypair.public_key) # => false
```

`PqcRails::Sig` も `PqcRails::Kem` と同様、`open` によるブロック形式と `new` / `free` による手動管理の両方をサポートしています。

#### 鍵長・署名長の参照

```ruby
sig = PqcRails::Sig.new("ML-DSA-44")
sig.length_public_key # => 1312
sig.length_secret_key # => 2560
sig.length_signature  # => 2420（最大長。実際の署名はこれより短いことがあります）
```

## エラーハンドリング

- 未知のアルゴリズム名や、liboqs が有効化していないアルゴリズムを指定すると `PqcRails::Error` が発生します。
- `encapsulate` / `decapsulate` / `sign` に渡すバイト列の長さが不正な場合は `ArgumentError` が発生します。
- `free` 済みのインスタンスに対する操作は `PqcRails::Error` が発生します。
- `PqcRails::Sig#verify` は、署名が無効な場合でも例外を発生させず `false` を返します（KEM とは異なる設計です）。
- `ActiveRecord::Encryption` で復号に失敗した場合は `ActiveRecord::Encryption::Errors::Decryption` が発生します。
- セッション Cookie が不正・改竄されている場合は空のセッションとして扱います（クラッシュしません）。

## 動作確認済み環境

- Ruby 3.2 / 3.3 / 3.4
- Rails 7.1 / 8.1
- liboqs 0.15.0

## 開発

```bash
bin/setup
bundle exec rspec
```

## ライセンス

[Business Source License (BSL)](https://mariadb.com/bsl11/) を採用予定です（詳細未確定、検討中）。

- ソースコードは公開し、開発・検証・非商用利用は無料
- 商用の本番利用には別途ライセンス契約が必要
- リリースから一定期間後、各バージョンは自動的にオープンソースライセンス（Apache 2.0 または MPL 2.0 を想定）に移行

正式なライセンス文面は今後確定し次第、[LICENSE.txt](LICENSE.txt) として公開します。現時点では本リポジトリのコードを商用利用しないでください。

## コントリビューション

Issue・Pull Request は [GitHub](https://github.com/mabutast/pqc_rails) で受け付けています。
