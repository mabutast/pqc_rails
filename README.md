# PqcRails

[![Gem Version](https://badge.fury.io/rb/pqc_rails.svg)](https://badge.fury.io/rb/pqc_rails)

**pqc_rails** は、既存の Ruby on Rails アプリケーションに耐量子暗号（PQC: Post-Quantum Cryptography）プリミティブを組み込むための gem です。[liboqs](https://github.com/open-quantum-safe/liboqs) への FFI バインディングを通じて、NIST 標準化アルゴリズムを Ruby ネイティブに呼び出します。

2030年前後に予想される PQC 対応の必須化を見据え、既存システムへの最小侵襲な導入を目標にしています。

## 現在の対応状況

| 機能                          | 状態                                |
| ----------------------------- | ----------------------------------- |
| KEM（鍵カプセル化機構）       | ✅ 対応済み（ML-KEM-512 で動作確認） |
| DSA（署名アルゴリズム）       | ✅ 対応済み（ML-DSA-44 で動作確認）  |
| Rack Middleware 連携          | 🚧 未対応・今後対応予定              |
| ActiveRecord::Encryption 連携 | 🚧 未対応・今後対応予定              |

KEM（鍵カプセル化機構）と DSA（署名アルゴリズム）の両方に対応しています。liboqs がサポートする他のアルゴリズムも、アルゴリズム名を文字列で指定するだけで利用できます（liboqs 側のビルド設定に依存します）。

## 必要要件

- Ruby >= 3.2.0
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
```

## 設定

liboqs の共有ライブラリへのパスを指定します。未設定の場合、環境変数 `LIBOQS_PATH`、それも無ければ OS ごとの一般的な場所（macOS: `/usr/local/lib/liboqs.dylib`、Linux: `/usr/local/lib/liboqs.so`）を仮定します。

```ruby
# config/initializers/pqc_rails.rb
PqcRails.configure do |config|
  config.liboqs_path = "/usr/local/lib/liboqs.dylib"
end
```

ライブラリパスは環境によって異なることが多いため、本番運用では明示的に設定することを推奨します。

## 使い方

### 鍵交換（KEM）の基本フロー

```ruby
PqcRails::Kem.open("ML-KEM-512") do |kem|
  # 受信側: 鍵ペアを生成
  keypair = kem.generate_keypair

  # 送信側: 受信側の公開鍵から共有秘密とciphertextを生成
  encapsulation = kem.encapsulate(keypair.public_key)

  # 受信側: ciphertextと自分の秘密鍵から共有秘密を復元
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

`verify` は、署名が無効な場合に例外を発生させず `false` を返します（liboqs の `OQS_SIG_verify` の挙動に準拠）。例外処理を書かずに、戻り値だけで検証結果を扱えます。

```ruby
sig.verify("tampered message", signature, keypair.public_key) # => false
```

`PqcRails::Sig` も `PqcRails::Kem` と同様、`open` によるブロック形式と `new` / `free` による手動管理の両方をサポートしています。

#### 鍵長・署名長の参照

```ruby
sig = PqcRails::Sig.new("ML-DSA-44")
sig.length_public_key # => 1312
sig.length_secret_key # => 2560
sig.length_signature  # => 2420（最大長。アルゴリズムによっては実際の署名がこれより短いことがあります）
```

## エラーハンドリング

- 未知のアルゴリズム名や、liboqs が有効化していないアルゴリズムを指定すると `PqcRails::Error` が発生します。
- `encapsulate` / `decapsulate` / `sign` に渡すバイト列の長さが不正な場合は `ArgumentError` が発生します。
- `free` 済みのインスタンスに対する操作は `PqcRails::Error` が発生します。
- `PqcRails::Sig#verify` は、署名が無効な場合でも例外を発生させず `false` を返します（KEM とは異なる設計です）。

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