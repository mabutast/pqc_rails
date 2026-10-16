# frozen_string_literal: true

require "active_record"
require_relative "hybrid_kem"
require_relative "envelope_cipher"
require_relative "ciphertext_format"
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
  # 内部的にはSession::Encryptorと同じKEM-DEM構成(HybridKem+EnvelopeCipher)。
  # Session::Encryptorを再利用しないのは、ARはCipher層に外から`key:`を渡す設計のため
  # 鍵の持ち方が異なるから(Session::Encryptorは自分でKeypairを保持する)。
  #
  # 暗号文の形式(v1)はheadersに、KEM暗号文(kem_ct)に加えて形式バージョン(pv)・アルゴリズムID(alg)・
  # 鍵ID(kid)を持つ。各値の意味と検証はCiphertextFormatを参照。
  class Cipher
    DEFAULT_PQ_ALG_NAME = PqcRails::Session::Encryptor::DEFAULT_PQ_ALG_NAME

    def initialize(pq_alg_name: DEFAULT_PQ_ALG_NAME)
      @pq_alg_name = pq_alg_name
    end

    def encrypt(clear_text, key:, deterministic: false)
      raise ArgumentError, "PqcRails::Cipher does not support deterministic encryption" if deterministic
      return encrypt_legacy(clear_text, key) if CiphertextFormat.write_legacy?

      algorithm_id = CiphertextFormat.algorithm_id(@pq_alg_name)
      key_id = CiphertextFormat.key_id(key.public_key)
      associated_data = CiphertextFormat.associated_data(algorithm_id: algorithm_id, key_id: key_id)

      HybridKem.open(CiphertextFormat.canonical_pq_alg_name(@pq_alg_name)) do |hybrid|
        encap = hybrid.encapsulate(key.public_key)
        envelope = EnvelopeCipher.new(encap.shared_secret).encrypt(clear_text, associated_data: associated_data)

        ::ActiveRecord::Encryption::Message.new(payload: envelope).tap do |message|
          message.headers[:kem_ct] = encap.ciphertext
          message.headers[:pv] = CiphertextFormat::VERSION
          message.headers[:alg] = algorithm_id
          message.headers[:kid] = key_id
        end
      end
    end

    # 形式バージョンのヘッダーがあればv1として、無ければ旧形式(v0)として復号する。
    # v1では、暗号文に書かれたアルゴリズムで復号し、鍵IDが一致する鍵だけを試す。
    def decrypt(encrypted_message, key:)
      keypairs = key.is_a?(::Array) ? key : [key]
      version = header(encrypted_message, :pv)

      case version
      when nil then decrypt_legacy(encrypted_message, keypairs)
      when CiphertextFormat::VERSION then decrypt_v1(encrypted_message, keypairs)
      else raise PqcRails::Error, "unsupported ciphertext format version: #{version.inspect}"
      end
    rescue PqcRails::Error, ArgumentError, TypeError => e
      raise ::ActiveRecord::Encryption::Errors::Decryption, e.message
    end

    def key_length
      EnvelopeCipher::KEY_LENGTH
    end

    def iv_length
      EnvelopeCipher::IV_LENGTH
    end

    private

    def encrypt_legacy(clear_text, keypair)
      HybridKem.open(@pq_alg_name) do |hybrid|
        encap = hybrid.encapsulate(keypair.public_key)
        envelope = EnvelopeCipher.new(encap.shared_secret).encrypt(clear_text)

        ::ActiveRecord::Encryption::Message.new(payload: envelope).tap do |message|
          message.headers[:kem_ct] = encap.ciphertext
        end
      end
    end

    def decrypt_legacy(encrypted_message, keypairs)
      try_keypairs(encrypted_message, keypairs, pq_alg_name: @pq_alg_name, associated_data: nil)
    end

    def decrypt_v1(encrypted_message, keypairs)
      algorithm_id = header(encrypted_message, :alg)
      key_id = header(encrypted_message, :kid)
      pq_alg_name = CiphertextFormat.pq_alg_name_for(algorithm_id, configured: @pq_alg_name)
      candidates = keypairs.select { |keypair| CiphertextFormat.key_id(keypair.public_key) == key_id }
      associated_data = CiphertextFormat.associated_data(algorithm_id: algorithm_id, key_id: key_id)

      try_keypairs(encrypted_message, candidates, pq_alg_name: pq_alg_name, associated_data: associated_data)
    end

    def try_keypairs(encrypted_message, keypairs, pq_alg_name:, associated_data:)
      raise PqcRails::Error, "no decryption key matches the message's key id" if keypairs.empty?

      kem_ciphertext = header(encrypted_message, :kem_ct)
      raise PqcRails::Error, "message is missing the kem_ct header" if kem_ciphertext.nil?

      last_error = nil
      HybridKem.open(pq_alg_name) do |hybrid|
        keypairs.each do |keypair|
          shared_secret = hybrid.decapsulate(kem_ciphertext, keypair.secret_key)
          return EnvelopeCipher.new(shared_secret).decrypt(encrypted_message.payload, associated_data: associated_data)
        rescue OpenSSL::Cipher::CipherError, PqcRails::Error, ArgumentError, TypeError => e
          last_error = e
        end
      end

      raise PqcRails::Error, last_error.message
    end

    # MessageSerializerで読み戻したMessageのheadersは、キーが文字列になる。
    def header(encrypted_message, name)
      encrypted_message.headers[name] || encrypted_message.headers[name.to_s]
    end
  end
end
