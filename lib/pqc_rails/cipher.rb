# frozen_string_literal: true

require "active_record"
require_relative "hybrid_kem"
require_relative "envelope_cipher"
require_relative "session/encryptor"

module PqcRails
  # ActiveRecord::Encryption::Cipher互換のインターフェースを持つ独立したクラス。
  # ActiveRecord::Encryption.configure(cipher: PqcRails::Cipher.new, key_provider: ...)で
  # デフォルトのAES-256-GCM単体実装を完全に置き換える。
  #
  # ActiveRecord::Encryptionの`key:`は「鍵そのもの」をそのまま渡してくる設計
  # (KeyProvider#encryption_key.secretの値がそのまま渡る)。本実装ではKeyProvider側で
  # `key.secret`がPqcRails::HybridKem::Keypair(公開鍵・秘密鍵のペア)を返すように
  # 揃えてあるので、ここではそのKeypairを直接受け取れる。
  #
  # 内部的にはPhase 2と同じKEM-DEM構成(HybridKem+EnvelopeCipher)。
  # Session::Encryptorを再利用しないのは、ARはCipher層に外から`key:`を渡す設計のため
  # 鍵の持ち方が異なるから(Session::Encryptorは自分でKeypairを保持する)。
  class Cipher
    DEFAULT_PQ_ALG_NAME = PqcRails::Session::Encryptor::DEFAULT_PQ_ALG_NAME

    def initialize(pq_alg_name: DEFAULT_PQ_ALG_NAME)
      @pq_alg_name = pq_alg_name
    end

    def encrypt(clear_text, key:, deterministic: false)
      raise ArgumentError, "PqcRails::Cipher does not support deterministic encryption" if deterministic

      HybridKem.open(@pq_alg_name) do |hybrid|
        encap = hybrid.encapsulate(key.public_key)
        envelope = EnvelopeCipher.new(encap.shared_secret).encrypt(clear_text)

        ::ActiveRecord::Encryption::Message.new(payload: envelope).tap do |message|
          message.headers[:kem_ct] = encap.ciphertext
        end
      end
    end

    def decrypt(encrypted_message, key:)
      keypairs = key.is_a?(::Array) ? key : [key]
      last_error = nil

      keypairs.each do |keypair|
        return decrypt_with(encrypted_message, keypair)
      rescue OpenSSL::Cipher::CipherError, PqcRails::Error, ArgumentError, TypeError => e
        last_error = e
      end

      raise ::ActiveRecord::Encryption::Errors::Decryption, last_error&.message
    end

    private

    def decrypt_with(encrypted_message, keypair)
      HybridKem.open(@pq_alg_name) do |hybrid|
        shared_secret = hybrid.decapsulate(encrypted_message.headers[:kem_ct], keypair.secret_key)
        EnvelopeCipher.new(shared_secret).decrypt(encrypted_message.payload)
      end
    end
  end
end
