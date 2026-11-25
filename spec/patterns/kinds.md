# 壊し方の種類（pqc_rails の追加分）

最後に読んだ fix の commit：6a53d05

| 種類 | 例 | 由来 |
|---|---|---|
| 例外の種類を変える（呼び出し側の rescue の対象外にする） | `raise PqcRails::Error, "..." if kem_ciphertext.nil?` → ガードが無く `NoMethodError`。壊し方は `raise PqcRails::Error` → `raise RuntimeError`。rescue して投げ直す時に、元の型（`raise e.class, ...`）を親の型（`raise PqcRails::Error, ...`）に戻す形も含む | pqc_rails c1d2891（kem_ct の無い暗号文で、ActiveRecord の復号エラーではなく NoMethodError が漏れた）、03224e4（旧鍵の世代を読む時に SeedOnlyKeyError が PqcRails::Error に戻った） |
| フレームワークが呼ぶメソッドを消す | `def key_length = EnvelopeCipher::KEY_LENGTH` → 定義が無い | pqc_rails c1d2891（ActiveRecord::Encryption が呼ぶ key_length・iv_length が無く NoMethodError） |
| 前の値の引き継ぎを消す（既定値で上書きする） | `configure(primary_key: existing_config_value(:primary_key), ...)` → `configure(...)`（未指定が nil で上書きされる） | pqc_rails a362a53（install! が既存の primary_key などを nil に戻した） |
| メモ化を消す（呼ぶたびに新しいオブジェクトを返す） | `@public_tags ||= Properties.new` → `{}`（書き込んだ値が次の呼び出しで消える。8112ec2 は、普通の Hash では短い名前への置き換えも通らなかった） | pqc_rails 8112ec2（store_key_references を有効にしても鍵の参照が残らなかった） |
| 引数の配列をシェルの文字列にする | `sh!("cmake", "-S", src_dir, "-B", BUILD_DIR)` → `sh!("cmake -S #{src_dir} -B #{BUILD_DIR}")`（壊し方は `system(*cmd)` → `system(cmd.join(" "))`） | pqc_rails e9ab3f0（インストール先のパスに空白があると liboqs のビルドが失敗した） |
| 鍵の導出を通さない・入力を1つ外す | `hkdf(shared_secret + authentication_key, info)` → `shared_secret`（共有鍵をそのまま AES 鍵にする）、または `hkdf(shared_secret, info)`。info・追加認証データから用途（record / session）を外す形も含む | pqc_rails db3f113（公開鍵だけで、正しく復号できる暗号文を作れた）、6a53d05（DB の値をセッションの Cookie として渡すと読めた） |
| 後始末（ゼロ埋め・解放）を消す | `ensure pointer&.clear`（SecretBuffer.with）→ 消す。`SecretBuffer.wipe(raw)` → 消す | pqc_rails c212139・ac2c3b2（liboqs に渡した秘密の領域が、使い終えた後も残った）、3aa3810（Base64 から戻したバイト列を消していなかった） |
| 戻り値の文字コード・型を変える | `return clear_text.force_encoding(Encoding::UTF_8)` → `return clear_text`（BINARY のまま返す） | pqc_rails eca261b（復号した日本語の値が BINARY で返った） |
| 元の領域を返す（コピーを作らない） | `copy(blob, 4, n)` → `blob.byteslice(4, n)`（切り出した値が元のバイト列と領域を共有する） | pqc_rails 3aa3810（取り出した秘密鍵が元の領域と共有され、後でゼロ埋めしても残った） |
| 確かめる前に使う（処理の順番を入れ替える） | 長さの確認より前にコピーする（確認の順番を後ろにずらす） | pqc_rails 7ee3546（長さが足りない時も秘密鍵のコピーを作ってしまった） |
| 公開してよい一覧を、伏せる一覧にする（一覧に漏れた値が出る） | `return "[FILTERED]" unless PUBLIC_MEMBERS.include?(name)` → `return "[FILTERED]" if SECRET_MEMBERS.include?(name)`（伏せる一覧から1つ抜くと、その秘密が出る。壊し方では、抜いた値が生の値で出るよう表示の行も添える） | pqc_rails 1378750（伏せる秘密を列挙していたため、後から増える秘密のメンバーを伏せられない作りだった。漏れの前に直した） |
| 例外の原因（cause）を残す | `raise invalid_key_error(raw), cause: nil` → `raise invalid_key_error(raw)`（rescue 中の送出は元の例外を cause に付け、そのメッセージの秘密も報告に出る） | pqc_rails 99da34f（鍵の値の先頭4バイトを長さとして読んだ数が、BlobPacking のエラーのメッセージとして cause から出た） |
