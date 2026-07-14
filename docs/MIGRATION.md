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
