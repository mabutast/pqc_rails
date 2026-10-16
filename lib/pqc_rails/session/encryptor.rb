# frozen_string_literal: true

require "base64"
require_relative "../blob_packing"
require_relative "../hybrid_kem"
require_relative "../envelope_cipher"
require_relative "../ciphertext_format"

module PqcRails
  module Session
    # HybridKem(KEM) + EnvelopeCipher(DEM)によるKEM-DEM構成のハイブリッド公開鍵暗号。
    #
    # セッションストアは同一サーバがencrypt(Cookie書き込み時)とdecrypt(Cookie読み込み時)の
    # 両方を行うため、二者間のインタラクティブな鍵交換ではなく、毎回encapsulateし直す
    # ランダム化された公開鍵暗号として使う。これにより、Cookieごとに異なるciphertext・
    # 異なるAES鍵が作られる(鍵の一意性・鮮度)。ただし復号は常に同じ静的secret_keyだけで
    # 決定的に行えるため、forward secrecy(将来secret_keyが漏洩しても過去の暗号文を守れる性質)は
    # 持たない。TLSの(EC)DHEのような使い捨ての一時鍵は存在しない。
    class Encryptor
      DEFAULT_PQ_ALG_NAME = :ml_kem_768

      def initialize(keypair, pq_alg_name: DEFAULT_PQ_ALG_NAME)
        @keypair = keypair
        @pq_alg_name = pq_alg_name
      end

      def encrypt(data)
        serialized = Marshal.dump(data)
        return Base64.strict_encode64(seal_legacy(serialized)) if CiphertextFormat.write_legacy?

        Base64.strict_encode64(seal_v1(serialized))
      end

      # 先頭バイトで形式を判別する。旧形式(v0)は先頭がKEM暗号文の4バイト長(ビッグエンディアン)で、
      # KEM暗号文は16MB未満のため先頭バイトは必ず0になる。1以上なら形式バージョンとして読む。
      def decrypt(blob)
        bytes = Base64.strict_decode64(blob)

        serialized =
          case bytes.getbyte(0)
          when 0 then open_legacy(bytes)
          when CiphertextFormat::VERSION then open_v1(bytes)
          else raise PqcRails::Error, "unsupported ciphertext format version: #{bytes.getbyte(0).inspect}"
          end

        Marshal.load(serialized)
      end

      private

      # 旧形式(v0): [4バイト長][KEM暗号文][4バイト長][AES暗号文]
      def seal_legacy(serialized)
        HybridKem.open(@pq_alg_name) do |hybrid|
          encap = hybrid.encapsulate(@keypair.public_key)
          BlobPacking.pack(encap.ciphertext, EnvelopeCipher.new(encap.shared_secret).encrypt(serialized))
        end
      end

      def open_legacy(bytes)
        ciphertext, encrypted = BlobPacking.unpack(bytes)

        HybridKem.open(@pq_alg_name) do |hybrid|
          shared_secret = hybrid.decapsulate(ciphertext, @keypair.secret_key)
          EnvelopeCipher.new(shared_secret).decrypt(encrypted)
        end
      end

      # v1: [形式バージョン 1B][アルゴリズムIDの長さ 1B][アルゴリズムID][鍵ID 2B][v0と同じ本体]
      def seal_v1(serialized)
        algorithm_id = CiphertextFormat.algorithm_id(@pq_alg_name)
        key_id = CiphertextFormat.key_id(@keypair.public_key)
        associated_data = CiphertextFormat.associated_data(algorithm_id: algorithm_id, key_id: key_id)
        header = [CiphertextFormat::VERSION, algorithm_id.bytesize].pack("CC") + algorithm_id + [key_id].pack("H4")

        HybridKem.open(CiphertextFormat.canonical_pq_alg_name(@pq_alg_name)) do |hybrid|
          encap = hybrid.encapsulate(@keypair.public_key)
          encrypted = EnvelopeCipher.new(encap.shared_secret).encrypt(serialized, associated_data: associated_data)
          header + BlobPacking.pack(encap.ciphertext, encrypted)
        end
      end

      def open_v1(bytes)
        algorithm_id_length = bytes.getbyte(1)
        algorithm_id = bytes[2, algorithm_id_length]
        key_id = bytes[2 + algorithm_id_length, 2].unpack1("H4")
        body = bytes[(4 + algorithm_id_length)..]

        if key_id != CiphertextFormat.key_id(@keypair.public_key)
          raise PqcRails::Error, "the cookie was encrypted with a different key id (#{key_id})"
        end

        pq_alg_name = CiphertextFormat.pq_alg_name_for(algorithm_id, configured: @pq_alg_name)
        associated_data = CiphertextFormat.associated_data(algorithm_id: algorithm_id, key_id: key_id)
        ciphertext, encrypted = BlobPacking.unpack(body)

        HybridKem.open(pq_alg_name) do |hybrid|
          shared_secret = hybrid.decapsulate(ciphertext, @keypair.secret_key)
          EnvelopeCipher.new(shared_secret).decrypt(encrypted, associated_data: associated_data)
        rescue OpenSSL::Cipher::CipherError, ArgumentError => e
          raise PqcRails::Error, e.message
        end
      end
    end
  end
end
