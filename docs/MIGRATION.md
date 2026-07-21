# 既存データの移行（Dual-Stack）

`PqcRails::ActiveRecord::Context.install!` は `ActiveRecord::Encryption` のグローバル設定（cipher・key_provider）を置き換えます。既に Rails 標準の `ActiveRecord::Encryption`（AES-256-GCM + 導出鍵）で暗号化済みのデータがある場合、切り替え後はデフォルトでは復号できません。

一括で全レコードを再暗号化できない場合は、Rails 標準の `previous:` スキーム機構を使って段階移行できます。新しい書き込みは `pqc_rails` で暗号化しつつ、既存データは旧方式のまま読み出せる状態にする方法です。

## 設定

```ruby
class User < ApplicationRecord
  encrypts :email, previous: [
    {
      cipher: ActiveRecord::Encryption::Cipher.new,
      key_provider: ActiveRecord::Encryption::DerivedSecretKeyProvider.new(OLD_PRIMARY_KEY)
    }
  ]
end
```

- `OLD_PRIMARY_KEY` は、`pqc_rails` 導入前に使っていた `Rails.application.credentials.active_record_encryption.primary_key`（または `config.active_record.encryption.primary_key`）の値です。credentials から削除する前に控えておいてください。
- `cipher:` に Rails 標準の `ActiveRecord::Encryption::Cipher.new` を明示的に指定するのが要点です。`previous:` は `key_provider:` だけでなく `cipher:` も含めた実行コンテキストをまるごと差し替えるため、暗号化アルゴリズム自体が異なる pqc_rails 導入前後のデータを同じ属性宣言で両方読めるようになります。

## 動作

| 操作 | 挙動 |
| --- | --- |
| 新規レコードの書き込み | 現在の設定（`Context.install!` 後の pqc_rails の Cipher + KeyProvider）で暗号化される |
| pqc_rails 導入後に書き込まれたレコードの読み出し | 現在の設定でそのまま復号される |
| pqc_rails 導入前に書き込まれたレコードの読み出し | 現在の設定での復号に失敗すると、`previous:` に列挙したスキームを順番に試し、旧方式（AES-256-GCM + 導出鍵）で復号される |

読み出しのたびに現在の設定→`previous:`の順で試行するため、`previous:` に列挙するスキームが増えるほど、失敗した場合の復号コストが増える点には注意してください。移行が完了し旧方式のデータが残っていないことを確認できたら、`previous:` オプションと `OLD_PRIMARY_KEY` は削除して構いません。

## 一括再暗号化したい場合

段階移行ではなく一括で再暗号化したい場合は、Rails 標準の `bin/rails db:encryption:init` 相当の仕組みは pqc_rails には無いため、対象モデルの全レコードを読み出して `save!` するマイグレーションタスクを自前で用意してください（読み出し時に上記の `previous:` 機構で旧データが復号され、書き込み時には現在の設定＝pqc_rails で再暗号化されます）。

## 鍵ローテーション（pqc_rails鍵世代間）

上記の `previous:` は「pqc_rails 導入前の暗号方式」からの移行を扱いますが、ここで扱うのは「pqc_rails 導入後、鍵そのものを世代交代させたい」場合の手順です。セッション・DB のどちらも、現行鍵に加えて旧鍵世代を併用できます。

### DB（ActiveRecord::Encryption）

`PqcRails::ActiveRecord::KeyProvider#decryption_keys` は、現行鍵に続けて旧鍵世代を返します。ローテーションの手順は次の通りです。

1. 新しい鍵ペアを生成し、`PQC_RECORD_KEY`（または `pqc_record_key` credentials）に設定する
2. 元々 `PQC_RECORD_KEY` に設定していた値を `PQC_RECORD_PREVIOUS_KEYS`（または `pqc_record_previous_keys` credentials）に移す
3. アプリを再起動する。新規の暗号化は新しい鍵で行われ、旧鍵で暗号化済みのレコードもそのまま復号できる
4. 旧鍵で暗号化されたレコードが残っている間は `PQC_RECORD_PREVIOUS_KEYS` を維持する。全レコードを新しい鍵で再暗号化し終えたら（上記「一括再暗号化したい場合」の手順を新旧鍵の組で実行）、`PQC_RECORD_PREVIOUS_KEYS` を削除してよい

`PQC_RECORD_PREVIOUS_KEYS` は複数の旧鍵をカンマ区切りで指定できます（credentials の場合は配列）。世代数に上限はありません。

### セッション（PqcCookieStore）

`PqcCookieStore` は書き込み（`set_cookie`）には常に現行鍵のみを使い、読み込み（`get_cookie`）は現行鍵で復号できなかった場合に旧鍵世代を順に試します。手順は DB 側と同様に `PQC_SESSION_KEY` / `PQC_SESSION_PREVIOUS_KEYS`（または `pqc_session_key` / `pqc_session_previous_keys` credentials）を使います。

セッションは DB のレコードと異なり、Cookie の有効期限（`expire_after` 等）が過ぎれば自然に失効します。そのため `PQC_SESSION_PREVIOUS_KEYS` は「ローテーション後、旧鍵で発行されたセッションが有効期限切れになるまで」の一時的な設定として運用し、その期間を過ぎたら削除してください（DB側のような一括再暗号化の手順は不要です）。

### 外部鍵ソース（HSM等）への差し替えについて

鍵の取得元は、デフォルトでは `PqcRails::KeySource::EnvCredentials`（ENV → Rails credentials）です。`#current_keypair` / `#previous_keypairs` の2メソッドを実装したオブジェクトであれば差し替えられます。

- **DB側**: `PqcRails::ActiveRecord::KeyProvider.new(key_source: your_source)` のように、`Context.install!` に渡す `KeyProvider` へ直接注入できます。
- **セッション側**: `PqcRails::Session::KeyManager` はモジュール実装のため同様の注入口はありませんが、`PqcCookieStore` は `keypair:` / `previous_keypairs:` オプションで実際の鍵ペアを直接受け取れます（`KeyManager` を経由しない）。外部鍵ソースから取得した鍵ペアをこのオプションに渡すことで、同様に差し替え可能です。

将来 HSM/PKCS#11 経由の鍵管理と連携する場合の拡張ポイントとして用意していますが、pqc_rails 自体は具体的な HSM 連携実装を提供しません。
