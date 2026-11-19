# 壊し方の種類（pqc_rails の追加分）

最後に読んだ fix の commit：bde83c7

| 種類 | 例 | 由来 |
|---|---|---|
| 例外の種類を変える（呼び出し側の rescue の対象外にする） | `raise PqcRails::Error, "..." if kem_ciphertext.nil?` → ガードが無く `NoMethodError`。壊し方は `raise PqcRails::Error` → `raise RuntimeError` | pqc_rails c1d2891（kem_ct の無い暗号文で、ActiveRecord の復号エラーではなく NoMethodError が漏れた） |
| フレームワークが呼ぶメソッドを消す | `def key_length = EnvelopeCipher::KEY_LENGTH` → 定義が無い | pqc_rails c1d2891（ActiveRecord::Encryption が呼ぶ key_length・iv_length が無く NoMethodError） |
| 前の値の引き継ぎを消す（既定値で上書きする） | `configure(primary_key: existing_config_value(:primary_key), ...)` → `configure(...)`（未指定が nil で上書きされる） | pqc_rails a362a53（install! が既存の primary_key などを nil に戻した） |
| メモ化を消す（呼ぶたびに新しいオブジェクトを返す） | `@public_tags ||= Properties.new` → `{}`（書き込んだ値が次の呼び出しで消える） | pqc_rails 8112ec2（store_key_references を有効にしても鍵の参照が残らなかった） |
| 引数の配列をシェルの文字列にする | `system(*cmd)` → `system(cmd.join(" "))` | pqc_rails e9ab3f0（インストール先のパスに空白があると liboqs のビルドが失敗した） |
| 鍵の導出を通さない・入力を1つ外す | `hkdf(shared_secret + authentication_key, info)` → `shared_secret`（共有鍵をそのまま AES 鍵にする）、または `hkdf(shared_secret, info)` | pqc_rails db3f113（公開鍵だけで、正しく復号できる暗号文を作れた） |
