# PqcRails

[![Gem Version](https://badge.fury.io/rb/pqc_rails.svg)](https://badge.fury.io/rb/pqc_rails)
[![Test](https://github.com/mabutast/pqc_rails/actions/workflows/test.yml/badge.svg)](https://github.com/mabutast/pqc_rails/actions/workflows/test.yml)

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

## PQC 対応が必要な理由

PQC 対応の義務化を待つ理由はありません。今この瞬間も、ハーベスト攻撃（Harvest Now, Decrypt Later：暗号化通信を今傍受し、将来の量子コンピュータで解読する攻撃）によってデータは蓄積され続けています。

過去に漏れたデータは取り返せませんが、これから先の通信は今日から守ることができます。`pqc_rails` は、既存の Rails アプリケーションに耐量子暗号を組み込み、この現在進行形のリスクに対処します。

詳しい脅威モデルはこちら → [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)

自組織のクリプト・インベントリに `pqc_rails` の利用箇所を記載する際の記入例はこちら → [docs/CRYPTO_INVENTORY.md](docs/CRYPTO_INVENTORY.md)

## 現在の対応状況

| 機能                          | 状態                                             |
| ----------------------------- | ------------------------------------------------ |
| KEM（鍵カプセル化機構）       | ✅ 対応済み（ML-KEM-512/768/1024 で動作確認）     |
| DSA（署名アルゴリズム）       | ✅ 対応済み（ML-DSA-44/65/87 で動作確認）         |
| セッション暗号化              | ✅ 対応済み（`PqcCookieStore`）                   |
| ActiveRecord::Encryption 連携 | ✅ 対応済み（`PqcRails::Cipher` + `KeyProvider`） |
| 鍵ローテーション              | ✅ 対応済み（セッション・DB 双方で旧鍵世代を併用可能。詳細は [docs/MIGRATION.md](docs/MIGRATION.md#鍵ローテーションpqc_rails鍵世代間)） |

KEM と DSA に加え、セッション Cookie と ActiveRecord::Encryption の両方を ML-KEM ベースのハイブリッド暗号（KEM-DEM 構成）で保護します。liboqs がサポートする他のアルゴリズムも、アルゴリズム名を文字列で指定するだけで利用できます（liboqs 側のビルド設定に依存します）。

## スコープ

- **対象はアプリケーション層の暗号化**（セッション Cookie・DB カラム）です。TLS 通信路そのものの PQC 化（Web サーバ・ロードバランサ側の設定）は対象外です。Ruby / RubyGems エコシステム側でも標準ライブラリ全体を PQC 対応させる議論（[Ruby Feature #22068](https://bugs.ruby-lang.org/issues/22068)）が進んでいますが、これは輸送路の話であり、`pqc_rails` が担うアプリケーションデータの暗号化とはレイヤーが異なります。
- **PKI・証明書管理基盤の代替ではありません**。鍵の発行・ライフサイクル管理・監査ログといった機能は提供しません。`pqc_rails` が担うのは Rails アプリ内のセッション・DB カラムの暗号化のみです。
- **量子コンピュータそのものを使う暗号方式（QKD、量子署名など）は対象外です**。`pqc_rails` が提供するのは、古典コンピュータ上で動作し量子コンピュータに対して耐性を持つ暗号（PQC: Post-Quantum Cryptography）です。
- **JWT/トークン署名は対象外です**。`PqcRails::Sig`（ML-DSA）はスタンドアロンの署名プリミティブとして提供していますが、セッション・DB統合と違いJWT等のトークンフォーマットへの統合は行っていません。この用途には [jwt-pq](https://rubygems.org/gems/jwt-pq) のような専用 gem を検討してください（`pqc_rails` とは別々の liboqs を読み込むため、併用しても競合しません）。

より詳しい対応範囲・スコープ外は [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md#for-developers) を参照してください。

## 想定するユースケース

長期保存が必要なデータを扱う Rails アプリケーション全般が対象ですが、特に以下のような用途では緊急度が高くなります。

- 医療記録・法務文書など、10年20年単位で機密性が求められるデータを扱うアプリケーション
- 金融・暗号資産関連のセッション管理や取引履歴を扱うアプリケーション（秘密鍵・取引データの窃取が量子コンピュータ実用化後に致命的な損失に直結するため）

## 必要要件

- Ruby >= 3.2.0
- Rails >= 7.1
- RubyGems / Bundler >= 4.0.16 を推奨（rubygems.org は X25519MLKEM768 + ML-DSA-65 によるハイブリッド TLS を提供しており、4.0.16 未満では `Gem::Request` / `Bundler::Fetcher` のクライアント証明書鍵種別が RSA に決め打ちされる不具合の影響を受けます）
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

#### Cookie サイズについて

`HybridKem` の ciphertext を含むため、Cookie は Rails 標準（AES-256-GCM）より大きくなります。実測値（開発機、単純なセッション内容での計測）は次の通りです。

| 内容                          | pqc_rails（ML-KEM-768、デフォルト） | Rails 標準 |
| ----------------------------- | ------------------------------------ | ---------- |
| 空セッション                   | 約1,770 bytes                        | 約170 bytes |
| `user_id` + CSRF トークン程度 | 約1,850 bytes                        | 約260 bytes |

単一 Cookie の上限（多くのブラウザで4,096 bytes）には収まりますが、他の Cookie（analytics・A/B テスト用等）と合算されるリクエストヘッダ全体の上限（多くのサーバ/プロキシで8KB前後）には注意してください。

より小さいサイズが必要な場合、`pq_alg_name: :ml_kem_512` を指定するとサイズを抑えられます（NIST セキュリティレベルは768の「レベル3」から512の「レベル1」に下がります）。

```ruby
config.session_store :pqc_cookie_store, pq_alg_name: :ml_kem_512
```

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

`ActiveRecord::Encryption` の Cipher と KeyProvider を ML-KEM ベースの実装に置き換えます。新規導入の場合はそのまま利用できます。既存の ActiveRecord::Encryption（Rails デフォルト）で暗号化済みのデータがある場合、切り替え後はデフォルトでは復号できなくなります。一括での再暗号化が難しい場合は、Rails 標準の `previous:` スキーム機構を使って段階移行できます → [docs/MIGRATION.md](docs/MIGRATION.md)

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

このレジストリ経由の解決方式により、アプリケーションコードは liboqs の生の名前や個々のアルゴリズムの実装詳細に直接依存しません。将来 NIST 標準の追加・非推奨化や liboqs 側の命名変更があっても、レジストリ側の対応表を更新するだけで済みます。これはクリプトグラフィック・アジリティ（暗号アルゴリズムを迅速に切り替えられる性質）の実装例で、金融庁「預金取扱金融機関の耐量子計算機暗号への対応に関する検討会 報告書」が具体的な実現方法として挙げる「メインルーチンでは抽象化した暗号機能の呼び出しに留め、具体的なアルゴリズム・パラメータによる処理を分離しておく」という設計パターンに沿っています。

#### レジストリ未登録のアルゴリズムを使う（例: Classic McEliece）

シンボルレジストリに無いアルゴリズムでも、liboqs 側でビルドされていれば liboqs の生の名前を文字列で渡すことで利用できます。例えば符号ベース暗号の Classic McEliece（[ISO/IEC 18033-2:2006/Amd 2:2026](https://www.iso.org/standard/86890.html) として標準化済み）は次のように使えます。

```ruby
PqcRails::Kem.open("Classic-McEliece-348864") do |kem|
  keypair = kem.generate_keypair
  keypair.public_key.bytesize # => 261120（約255KB。ML-KEM-512の800バイトと比べ大幅に大きい）
end
```

公開鍵サイズが大きい（348864 パラメータセットで約255KB）ため TLS ハンドシェイクのような頻繁な鍵交換には向きませんが、鍵交換の頻度が低い長期保存データの暗号化では ML-KEM が万一破られた場合のバックアップとして選択肢になります。異なる数学的困難性（符号の復号問題）に安全性の根拠を置くため、ML-KEM（格子問題）とは異なるリスクプロファイルを持ちます。

同様に、NIST が ML-KEM のバックアップとして選定した符号ベースKEM「HQC」も liboqs 0.16.0 以降ではデフォルトで有効化されており、生の名前（`"HQC-1"` / `"HQC-3"` / `"HQC-5"`）を渡すことで利用できます。ただしHQCはまだNIST標準化作業中（FIPS番号未確定）のため、シンボルレジストリには未登録です。

```ruby
PqcRails::Kem.open("HQC-1") do |kem|
  keypair = kem.generate_keypair
  keypair.public_key.bytesize # => 2241
end
```

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
- liboqs 0.15.0 / 0.16.0

[CI](.github/workflows/test.yml) では Ruby 3.4 + Rails 8.1 + liboqs 0.15.0 の組み合わせを push・PR のたびに継続的に検証しています。liboqs 0.16.0、および他の Ruby/Rails バージョンの組み合わせは手動で動作確認済みです（CIのマトリクス化は今後の対応予定）。

## 開発

```bash
bin/setup
bundle exec rspec
```

## ライセンス

[Business Source License 1.1 (BSL)](LICENSE.txt) を採用しています。

- ソースコードは公開し、開発・検証・非商用利用は無料です
- 商用利用（対価を得る用途、または営利企業が事業活動の一環として使う用途）には別途ライセンス契約が必要です
- 各バージョンのリリースから4年後、自動的にオープンソースライセンス（Apache License 2.0）に移行します

詳細な条件は [LICENSE.txt](LICENSE.txt) を参照してください。商用利用に関するお問い合わせは contact@rubyquantum.dev までご連絡ください。

商用利用の判定基準（Additional Use Grant の文言）は、正式な法律レビューを経る前の暫定版です。実際に商用ライセンス契約を結ぶ段階までに見直す可能性があります。

## コントリビューション

Issue・Pull Request は [GitHub](https://github.com/mabutast/pqc_rails) で受け付けています。
