# 既存データの移行（Dual-Stack）

`PqcRails::ActiveRecord::Context.install!` は `ActiveRecord::Encryption` のグローバル設定（cipher・key_provider）を置き換えます。既に Rails 標準の `ActiveRecord::Encryption`（AES-256-GCM + 導出鍵）で暗号化済みのデータがある場合、切り替え後はデフォルトでは復号できません。

一括で全レコードを再暗号化できない場合は、Rails 標準の `previous:` スキーム機構を使って段階移行できます。新しい書き込みは `pqc_rails` で暗号化しつつ、既存データは旧方式のまま読み出せる状態にする方法です。

## 移行の前に列の型を確かめる

暗号文は短い値でも長くなります（ML-KEM-768 で13文字の値を暗号化すると1,643文字）。MySQL の `string` 列（255文字まで）には保存できないので、暗号化する列を先に `text` 型へ変更してください。`strict: false` の接続で変更せずに書き込むと、値が切れて保存され、元の値を復元できなくなります。

`rails pqc_rails:status` の「暗号文が入る列」で、変更が必要な列を確認できます。長さの上限がある `string` 列は、短い値が入っても長い値で上限を超えることがあるので、これも `text` 型を勧めます。

```ruby
class ChangeUsersEmailToText < ActiveRecord::Migration[8.1]
  def up
    change_column :users, :email, :text
  end

  def down
    change_column :users, :email, :string
  end
end
```

MySQL の `text` 列には、長さを指定しないインデックスを作成できません。列にインデックスがある場合は、変更の前に外してください。変更の前に DB のバックアップを取ってください。

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

段階移行ではなく一括で再暗号化したい場合は、Rails 標準の `bin/rails db:encryption:init` 相当の仕組みは pqc_rails には無いため、対象モデルの全レコードに対して自前でマイグレーションタスクを用意してください。

**`save!` ではなく `encrypt` を使ってください。** 単に読み出して `save!` するだけでは、多くの場合再暗号化されません。ActiveRecord の dirty tracking は「復号後の値（平文）が変わっていない」属性への `save!` を無視し、UPDATE 文自体を発行しないためです。`previous:` 機構で旧データが復号されても、その平文が変わらなければ書き込みはスキップされ、DB 上の暗号文は古い方式のまま残ります。`ActiveRecord::Encryption::EncryptableRecord#encrypt`（`record.encrypt`）は dirty tracking を経由せず、現在の設定（cipher + key_provider）で強制的に再暗号化して保存します。

```ruby
User.find_each { |user| user.with_lock { user.encrypt } }
```

`with_lock` を付けるのは、アプリケーションを動かしたまま再暗号化するためです。`encrypt` は読み込んだ時点の値を書き戻すので、読み込んでから書き戻すまでの間に同じレコードが更新されると、その更新を古い値で上書きします。`with_lock` はレコードをロックして読み直してから `encrypt` を呼ぶため、この上書きが起きません。アプリケーションを止めて行う場合は不要です。

再暗号化が残っているレコードは、復号せずに暗号文の鍵ID・形式を調べて見分けられます（[README「暗号文の形式」](../README.md#暗号文の形式)）。

```ruby
current_key_id = PqcRails::CiphertextFormat.key_id(
  ActiveRecord::Encryption.key_provider.encryption_key.secret.public_key
)
pending = User.find_each.select do |user|
  ciphertext = user.ciphertext_for(:email)
  next false if ciphertext.nil?

  info = PqcRails::ActiveRecord::CiphertextInfo.parse(ciphertext)
  info.nil? || info.legacy? || info.key_id != current_key_id
end
pending.size # => 0 なら、旧鍵を外し、accept_legacy_records = false にできる
```

0.3.0 以前の版から更新した場合、全レコードを再暗号化し終えたら、旧形式の暗号文を受け付けない設定にしてください。旧形式は作成元の認証を持たず、公開鍵だけで作れるためです（[README「暗号文の形式」](../README.md#暗号文の形式)参照）。

```ruby
PqcRails.configure do |config|
  config.accept_legacy_records = false
end
```

## RSA / ECDH による鍵のラップからの移行

データ鍵（データを暗号化する共通鍵）を RSA-OAEP や ECDH で包んで保存する方式（エンベロープ暗号）を自前で実装している場合は、その部分を pqc_rails の DB カラム暗号化に置き換えるのが最も簡単です。pqc_rails の暗号文は、データごとに ML-KEM と X25519 で鍵を作り（RSA / ECDH で包む部分に当たります）、AES-256-GCM で暗号化します。形式バージョン・アルゴリズムID・鍵ID・作成元の認証も pqc_rails が扱います。

1. 暗号化している値を、`encrypts` を宣言したカラムへ移す。移行の間は、旧方式で包んだ値のカラムを残す
2. 読み出し処理を「新しいカラムに値があればそれを使い、無ければ旧方式で復号する」形にする
3. 旧方式の値を順に復号し、新しいカラムへ書き込む（`find_each` で1件ずつ。アプリケーションを動かしたまま行う場合は `with_lock` の中で読み直してから書き込む）
4. 全件を移し終えたら、旧方式のカラムと、RSA / ECDH の鍵を削除する

`PqcRails::HybridKem` と `PqcRails::EnvelopeCipher` を直接使って同じ構成を組むことは勧めません。この2つは内部実装で（README「API の安定性」）、暗号文の形式バージョン・鍵ID・作成元の認証を持ちません。KEM は公開鍵だけで暗号化できるため、作成元の認証が無いと、公開鍵を知る者が正しく復号できる暗号文を作れます（[THREAT_MODEL.md](THREAT_MODEL.md) の「作成元の認証」）。

## 鍵ローテーション（pqc_rails鍵世代間）

上記の `previous:` は「pqc_rails 導入前の暗号方式」からの移行を扱いますが、ここで扱うのは「pqc_rails 導入後、鍵そのものを世代交代させたい」場合の手順です。セッション・DB のどちらも、現行鍵に加えて旧鍵世代を併用できます。

### DB（ActiveRecord::Encryption）

`PqcRails::ActiveRecord::KeyProvider#decryption_keys` は、現行鍵に続けて旧鍵世代を返します。ローテーションの手順は次の通りです。

1. 新しい鍵ペアを生成し、`PQC_RECORD_KEY`（または `pqc_record_key` credentials）に設定する
2. 元々 `PQC_RECORD_KEY` に設定していた値を `PQC_RECORD_PREVIOUS_KEYS`（または `pqc_record_previous_keys` credentials）に移す
3. アプリを再起動する。新規の暗号化は新しい鍵で行われ、旧鍵で暗号化済みのレコードもそのまま復号できる
4. 旧鍵で暗号化されたレコードが残っている間は `PQC_RECORD_PREVIOUS_KEYS` を維持する。全レコードを新しい鍵で再暗号化し終えたら（上記「一括再暗号化したい場合」の手順を新旧鍵の組で実行）、`PQC_RECORD_PREVIOUS_KEYS` を削除してよい

鍵の値（公開鍵・秘密鍵・認証鍵）は、暗号化・復号を行うアプリケーションだけが持ちます。暗号化も復号も同じアプリケーションで行うため、公開鍵を他のシステムへ配る手順はありません。公開鍵が外に漏れても、認証鍵が無ければ正しく復号できる暗号文は作れません。

`PQC_RECORD_PREVIOUS_KEYS` は複数の旧鍵をカンマ区切りで指定できます（credentials の場合は配列）。世代数に上限はありません。

### セッション（PqcCookieStore）

`PqcCookieStore` は書き込み（`set_cookie`）には常に現行鍵のみを使い、読み込み（`get_cookie`）は現行鍵で復号できなかった場合に旧鍵世代を順に試します。各鍵では、Cookie の鍵IDが一致する時だけ復号を行い、一致しない鍵は使わずに次の鍵へ進みます（DB 側の「鍵IDが一致する鍵だけを試す」と同じ判定）。手順は DB 側と同様に `PQC_SESSION_KEY` / `PQC_SESSION_PREVIOUS_KEYS`（または `pqc_session_key` / `pqc_session_previous_keys` credentials）を使います。

セッションは DB のレコードと異なり、Cookie の有効期限（`expire_after` 等）が過ぎれば自然に失効します。そのため `PQC_SESSION_PREVIOUS_KEYS` は「ローテーション後、旧鍵で発行されたセッションが有効期限切れになるまで」の一時的な設定として運用し、その期間を過ぎたら削除してください（DB側のような一括再暗号化の手順は不要です）。

### 0.3.0 以前からの更新

0.3.0 以前に生成した鍵は認証鍵を持たないため、新しい形式の暗号文を書けません。更新時に、新しい鍵を生成してローテーションします。新しい形式の鍵は、0.3.0 以前の版でも読めます（先頭の公開鍵・秘密鍵だけを使います）。ただし、更新後に書かれた新しい形式の暗号文は、0.3.0 以前の版では読めません。

セッションと DB に同じ鍵を設定している場合、更新後は旧形式の Cookie を読みません。`ciphertext_format = :v0` でも Cookie を書けないので、順番に更新する場合は、更新の前にセッションの鍵を DB と別の鍵に変えてください（この時点で既存のセッションは切れます）。この鍵は更新前の版で生成します。認証鍵を持つ鍵は `ciphertext_format = :v0` で使えません。同じ鍵のまま更新すると、期限を設定しても既存のセッションは保てません。

gem を 0.3.0 以前に戻す時は、鍵の設定も元の鍵に戻してください。**新しい鍵は消さずに保管してください。** 更新後に書かれた新しい形式の暗号文は、新しい鍵が無いと復号できません。新しい鍵のまま 0.3.0 以前の版で書いた値は、再度更新すると読めません。その場合は、同じ鍵から認証鍵を除いた鍵（`PqcRails::KeySource.encode(PqcRails::HybridKem::Keypair.new(new_keypair.public_key, new_keypair.secret_key))`、`new_keypair` は `PqcRails::KeySource.decode` で戻した新しい鍵）を旧鍵に足すと読めます。Cookie を読むには、あわせて `accept_legacy_cookies_until` の期限内である必要があります。

この鍵を旧鍵に足すと、その鍵宛の旧形式の値を再び受け付けます。旧形式は公開鍵だけで作れ、Cookie の中身は `Marshal.load` に渡るため、0.3.0 以前の鍵と同じ危険がこの鍵にも及びます。足すのは一時的にしてください。`accept_legacy_records` を有効にしている間に DB の値を再暗号化し、`accept_legacy_cookies_until` は近い日時にします。DB の値の再暗号化が済み、`accept_legacy_cookies_until` の日時を過ぎたら、この鍵を旧鍵から外します。

1. 更新後の版の gem で、新しい鍵を生成する（セッション用・DB 用それぞれ）。0.3.0 以前の版で生成した鍵は認証鍵を持たない。`:ml_kem_768` は、今の設定のアルゴリズムに合わせる

   ```ruby
   keypair = PqcRails::HybridKem.open(:ml_kem_768) { |hybrid| hybrid.generate_keypair }
   PqcRails::KeySource.encode(keypair) # => 新しい鍵の文字列
   ```

2. 1台だけで動かしている場合は、gem の更新と同時に、新しい鍵を `PQC_SESSION_KEY` / `PQC_RECORD_KEY` に、元の鍵を `PQC_SESSION_PREVIOUS_KEYS` / `PQC_RECORD_PREVIOUS_KEYS` に設定して再起動する。既存のセッションを保つ場合は、再起動の前に手順5の期限も設定する
3. 複数台を順番に更新する場合は、次の順で進める
   1. `config.ciphertext_format = :v0` を設定して gem を更新する。鍵は元のままでよい（旧形式は認証鍵を使わない）
   2. 全台の更新後、新しい鍵を `PQC_*_PREVIOUS_KEYS` に追加して全台を再起動する。これで、どのサーバーも新しい鍵の暗号文を読める
   3. 新しい鍵を `PQC_*_KEY` に、元の鍵を `PQC_*_PREVIOUS_KEYS` に入れ替え、`ciphertext_format = :v0` を削除して全台を再起動する。`:v0` を削除すると、期限が無い限り旧形式の Cookie は読まれない。既存のセッションを保つ場合は同時に手順5の期限を設定する。期限を設定しないと、再起動の途中は新しい設定のサーバーが旧形式の Cookie を拒否するので、利用者のログインが複数回切れることがある
4. `rails pqc_rails:status` で、鍵が「設定済み」になっていることを確かめる
5. 既存のセッションを保つ場合は、旧形式の Cookie を読む期限を設定する。設定しないと旧形式の Cookie は読まれず、そのセッションは切れる。期限には、旧形式の Cookie の発行が止まる日時（1台構成は更新の日時、順番に更新する場合は `:v0` を外した全台の再起動が終わる日時）に、最長のセッション有効期限を足した日時を設定する。その後は旧形式の Cookie を自動的に読まなくなる。読むのは認証鍵を持たない元の鍵宛の Cookie だけで、元の鍵は `PQC_SESSION_PREVIOUS_KEYS` に残しておく

   ```ruby
   PqcRails.configure do |config|
     config.accept_legacy_cookies_until = Time.utc(2026, 12, 1)
   end
   ```

6. DB は、全レコードを再暗号化した後（「一括再暗号化したい場合」）に `accept_legacy_records = false` を設定し、`PQC_RECORD_PREVIOUS_KEYS` から元の鍵を削除する
7. 手順5の期限を過ぎたら、`accept_legacy_cookies_until` の設定と、`PQC_SESSION_PREVIOUS_KEYS` の元の鍵を削除する

### アルゴリズム（パラメータセット）の変更

ML-KEM-768 から ML-KEM-1024 に変える場合のように、アルゴリズムを変更する手順です。暗号文は自身のアルゴリズムIDを持つため、設定を変えた後も、変更前のアルゴリズムで暗号化したデータを復号できます（[README「暗号文の形式」](../README.md#暗号文の形式)参照）。鍵ペアはアルゴリズムごとに異なるため、新しいアルゴリズムの鍵ペアを生成し、鍵ローテーションと同時に行います。

1. 0.3.0 以前の版で暗号化したレコードが残っていれば、先に「一括再暗号化したい場合」の手順で再暗号化し、アルゴリズムIDを持つ形式に書き換える。アルゴリズムIDを持たない暗号文は設定のアルゴリズムで復号されるため、設定を変えると復号できなくなる
2. 新しいアルゴリズムの鍵ペアを生成する

   ```ruby
   keypair = PqcRails::HybridKem.open(:ml_kem_1024) { |hybrid| hybrid.generate_keypair }
   PqcRails::KeySource.encode(keypair) # => PQC_RECORD_KEY に設定する文字列
   ```

3. 上記「鍵ローテーション」の手順 1〜2 と同じく、生成した鍵を `PQC_RECORD_KEY` に、元の鍵を `PQC_RECORD_PREVIOUS_KEYS` に設定する
4. アルゴリズムの設定を変更してアプリを再起動する

   ```ruby
   PqcRails::ActiveRecord::Context.install!(pq_alg_name: :ml_kem_1024)
   ```

5. 旧アルゴリズムのレコードを再暗号化し終えたら、`PQC_RECORD_PREVIOUS_KEYS` から元の鍵を削除する

セッションでは `config.session_store :pqc_cookie_store, pq_alg_name: :ml_kem_1024` に変え、鍵は `PQC_SESSION_KEY` / `PQC_SESSION_PREVIOUS_KEYS` で同様に入れ替えます。0.3.0 以前の版が発行した Cookie は、変更後は復号できず空のセッションとして扱われます（該当ユーザーは再ログインになります）。

### 外部鍵ソース（HSM等）への差し替えについて

鍵の取得元は、デフォルトでは `PqcRails::KeySource::EnvCredentials`（ENV → Rails credentials）です。`#current_keypair` / `#previous_keypairs` の2メソッドを実装したオブジェクトであれば差し替えられます。

- **DB側**: `PqcRails::ActiveRecord::Context.install!(key_provider: PqcRails::ActiveRecord::KeyProvider.new(key_source: your_source))` のように注入できます。
- **セッション側**: `PqcRails::Session::KeyManager` はモジュール実装のため同様の注入口はありませんが、`PqcCookieStore` は `keypair:` / `previous_keypairs:` オプションで実際の鍵ペアを直接受け取れます（`KeyManager` を経由しない）。外部鍵ソースから取得した鍵ペアをこのオプションに渡すことで、同様に差し替え可能です。

DB とセッションには別の鍵を設定してください。`Context` に設定した鍵ソースと、属性ごとに指定した `PqcRails::ActiveRecord::KeyProvider` は、旧形式の Cookie の「同じ鍵」の判定の対象です。この判定は、旧形式の Cookie を読む設定（`accept_legacy_cookies_until` の期限内、または `ciphertext_format = :v0`）の間だけ行います。読み込まれていないモデルの属性は判定の対象になりません。Rails 標準の `key_provider` は、持っている鍵がすべて AES の鍵なら対象外です。公開鍵（`#public_keys`）を返さない独自の `key_provider` や、pqc_rails の鍵ペアを入れた Rails 標準の `key_provider` を属性に指定している場合は、同じ鍵かを確かめられないため、旧形式の Cookie を読みません。

将来 HSM/PKCS#11 経由の鍵管理と連携する場合の拡張ポイントとして用意していますが、pqc_rails 自体は具体的な HSM 連携実装を提供しません。

## セッションの中身を JSON に切り替える

`session_serializer = :json` で書いた Cookie（形式 v2）は 0.6.0 以降の版だけが読めます。0.6.0 以降の版は、設定によらず v2 の Cookie を読みます。切り替えは次の順で進めます。

1. 全台を 0.6.0 以降に更新する。設定は変えない（既定の `:marshal` のまま）
2. `session_not_json_safe.pqc_rails` のイベントを購読し、JSON で書けない値をもつセッションのキーを確かめる。`Time` は `iso8601` の文字列か整数に、独自のオブジェクトはその ID などに置き換える。イベントが出なくなるまで直す
3. `session_serializer = :json` と、`accept_marshal_cookies_until` を設定して全台を再起動する。期限には、全台の再起動が終わる日時に、最長のセッション有効期限を足した日時を設定する。期限を設定しないと、それまでのセッション（Marshal で書かれた Cookie）は読まれず、利用者のログインが切れる。期限を過ぎて読まなかった Cookie も、復号の失敗（`decryption_failed.pqc_rails`）として通知されるので、期限の直後は通知が増える

   ```ruby
   PqcRails.configure do |config|
     config.session_serializer = :json
     config.accept_marshal_cookies_until = Time.utc(2027, 1, 15)
   end
   ```

4. 期限を過ぎたら、`accept_marshal_cookies_until` の設定を削除する。その後は Marshal で書かれた Cookie を読まない

再起動の途中で `:marshal` のサーバーと `:json` のサーバーが混ざっても、どちらも v1・v2 の両方を読むので、ログインは切れません。

`:marshal` に戻す時は、`session_serializer` の設定を削除して再起動します。v2 の Cookie はそのまま読めます。0.6.0 より前の版に戻すと、v2 の Cookie は読めず、そのセッションは切れます。

## 鍵の紛失・災害復旧

`PQC_RECORD_KEY` / `PQC_SESSION_KEY`（または対応する credentials）を紛失すると、その鍵で暗号化された DB カラム・セッション Cookie は二度と復号できません。pqc_rails 自体は鍵のエスクロー機能を持たず、liboqs にもその機能はないため、鍵のバックアップは利用者側の運用に完全に委ねられています。特に DB カラムは長期間残り続けるデータであるため、**鍵紛失イコールデータの永久喪失**に直結します。

以下は推奨する運用です。

- **Rails credentials 経由で鍵を管理する場合**：実質的な「鍵の鍵」は `config/master.key`（または `RAILS_MASTER_KEY`）です。`config/credentials.yml.enc` はリポジトリに含まれますが、`master.key` はバージョン管理から除外されるため、これ自体を通常のインフラ資産と同様のバックアップ体制（社内のシークレット管理システム、複数人でのオフライン保管等）に含めてください。
- **環境変数（`PQC_RECORD_KEY` 等）経由で管理する場合**：値そのものを手動でファイルに控えるのではなく、AWS Secrets Manager・HashiCorp Vault・GCP Secret Manager 等のシークレットマネージャが提供するバージョニング・自動バックアップ機能を利用してください。
- **定期的な復旧リハーサル**：バックアップした鍵が「存在すること」の確認だけでは不十分です。実際にその鍵をテスト環境へ復元し、既存の暗号化データを復号できることまで確認してください。バックアップ手順自体の欠陥（フォーマット破損、鍵の取り違え等）は、復旧を試みて初めて発覚します。
- **鍵ローテーションを平常運用に組み込む**：上記の鍵ローテーション手順を定期的に実施することで、単一世代の鍵に依存し続ける期間そのものを短くできます。

複数管理者による鍵の分散管理（Shamir's Secret Sharing 等による鍵分割）や鍵のエスクローが必要な場合、pqc_rails 自体はその機能を提供しないため、前述の外部鍵ソース差し替え機構を経由した HSM/KMS の利用を検討してください。

## ロールバック手順（pqc_rails 導入前の状態に戻す）

pqc_rails 導入後に、何らかの理由で導入前の状態へ戻す必要が生じた場合の手順です。

### DB（ActiveRecord::Encryption）

考え方は導入時の段階移行と対称です。`previous:` に pqc_rails 側のスキームを指定することで、新規の書き込みを Rails 標準方式に戻しつつ、pqc_rails で暗号化済みのデータも読み出せる状態にします。

```ruby
class User < ApplicationRecord
  encrypts :email, previous: [
    {
      cipher: PqcRails::Cipher.new(pq_alg_name: :ml_kem_768), # Context.install!に渡していたpq_alg_nameと一致させる
      key_provider: PqcRails::ActiveRecord::KeyProvider.new
    }
  ]
end
```

- `PqcRails::Cipher.new` の `pq_alg_name:` は、導入時に `Context.install!(pq_alg_name: ...)` へ渡していた値と一致させてください。省略するとデフォルト（`:ml_kem_768`）が使われ、README の案内に従って `:ml_kem_512` 等へ変更していた場合は KEM 暗号文の長さが合わず復号に失敗します。
- `Context.install!` を外す前に、Rails 標準の暗号化の `primary_key`・`deterministic_key`・`key_derivation_salt` を設定してください。導入前の値が残っていればそれを戻し、無ければ `bin/rails db:encryption:init` で生成します。設定が無いまま外すと、暗号化属性の保存と `record.encrypt` が `ActiveRecord::Encryption::Errors::Configuration` になります。
- `Context.install!` の呼び出し自体を削除（または呼ばない状態に戻す）することで、新規の暗号化は Rails 標準（AES-256-GCM + 導出鍵）に戻ります。
- 完全に pqc_rails 以前の状態へ戻したい場合は、上記「一括再暗号化したい場合」と同じ要領で全レコードに `record.encrypt` を実行し、Rails 標準方式で再暗号化してください（`save!` では再暗号化されません）。
- 移行が完了し pqc_rails 方式のデータが残っていないことを確認できるまで、`PQC_RECORD_KEY`（または `pqc_record_key` credentials）は削除しないでください。

### セッション（PqcCookieStore）

セッションには DB のような「既存データを段階的に読み替える」仕組みはそもそも必要ありません。セッション Cookie は元々 `expire_after` 等で有効期限が切れる一時的なデータであるためです。

`config.session_store` を `:pqc_cookie_store` から `:cookie_store`（Rails 標準）へ戻すだけでロールバックは完了しますが、これは導入時の移行と同様に**その時点で有効な全セッションが無効化される（全ユーザーが再ログインになる）**ことを意味します。これは不具合ではなく、導入時と対称な想定内の挙動です。段階的にロールバックしたい場合の仕組み（旧方式との併用）は現時点では提供していません。
