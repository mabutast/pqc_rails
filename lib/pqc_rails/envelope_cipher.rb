# frozen_string_literal: true

require "openssl"
require_relative "length_validation"

module PqcRails
  # AES-256-GCMによるエンベロープ暗号化。HybridKem等で導出した32バイトの共有鍵を使って
  # 実際のデータ(平文)を暗号化/復号する。「鍵交換」と「データ暗号化」を分離するのは、
  # 後でActiveRecord::Encryption統合(Phase 3)で「鍵→暗号化結果」のインターフェースとして
  # そのまま使えるようにするため。
  #
  # 暗号文のフォーマット: IV(12byte) + 認証タグ(16byte) + 暗号文本体
  # この3つを1本のバイト列にまとめて返すことで、DBカラム等に1カラムでそのまま保存できる。
  #
  # 使い方:
  #   cipher = PqcRails::EnvelopeCipher.new(key) # 32バイトの鍵
  #   encrypted = cipher.encrypt("secret")
  #   cipher.decrypt(encrypted) # => "secret"
  class EnvelopeCipher
    include LengthValidation

    CIPHER_NAME = "aes-256-gcm"
    KEY_LENGTH = 32
    IV_LENGTH = 12
    TAG_LENGTH = 16

    def initialize(key)
      validate_length!(key, KEY_LENGTH, "key")
      @key = key
    end

    def encrypt(plaintext, associated_data: nil)
      cipher = OpenSSL::Cipher.new(CIPHER_NAME)
      cipher.encrypt
      cipher.key = @key
      iv = cipher.random_iv
      cipher.auth_data = associated_data if associated_data

      ciphertext = cipher.update(plaintext) + cipher.final

      iv + cipher.auth_tag + ciphertext
    end

    def decrypt(encrypted, associated_data: nil)
      iv         = encrypted[0, IV_LENGTH]
      tag        = encrypted[IV_LENGTH, TAG_LENGTH]
      ciphertext = encrypted[(IV_LENGTH + TAG_LENGTH)..]

      cipher = OpenSSL::Cipher.new(CIPHER_NAME)
      cipher.decrypt
      cipher.key = @key
      cipher.iv = iv
      cipher.auth_tag = tag
      cipher.auth_data = associated_data if associated_data

      cipher.update(ciphertext) + cipher.final
    end
  end
end
