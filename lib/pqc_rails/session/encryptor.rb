# frozen_string_literal: true

require "base64"
require_relative "../blob_packing"
require_relative "../hybrid_kem"
require_relative "../envelope_cipher"

module PqcRails
  module Session
    # HybridKem(KEM) + EnvelopeCipher(DEM)によるKEM-DEM構成のハイブリッド公開鍵暗号。
    #
    # セッションストアは同一サーバがencrypt(Cookie書き込み時)とdecrypt(Cookie読み込み時)の
    # 両方を行うため、二者間のインタラクティブな鍵交換ではなく、毎回encapsulateし直す
    # ランダム化された公開鍵暗号として使う。これにより、長期鍵(secret_key)はサーバにしか無くても、
    # Cookieごとに異なるciphertextが作られる(per-cookieのforward secrecy的な性質を持つ)。
    class Encryptor
      DEFAULT_PQ_ALG_NAME = :ml_kem_768

      def initialize(keypair, pq_alg_name: DEFAULT_PQ_ALG_NAME)
        @keypair = keypair
        @pq_alg_name = pq_alg_name
      end

      def encrypt(data)
        serialized = Marshal.dump(data)

        HybridKem.open(@pq_alg_name) do |hybrid|
          encap = hybrid.encapsulate(@keypair.public_key)
          encrypted = EnvelopeCipher.new(encap.shared_secret).encrypt(serialized)

          Base64.strict_encode64(BlobPacking.pack(encap.ciphertext, encrypted))
        end
      end

      def decrypt(blob)
        ciphertext, encrypted = BlobPacking.unpack(Base64.strict_decode64(blob))

        HybridKem.open(@pq_alg_name) do |hybrid|
          shared_secret = hybrid.decapsulate(ciphertext, @keypair.secret_key)
          Marshal.load(EnvelopeCipher.new(shared_secret).decrypt(encrypted))
        end
      end
    end
  end
end
