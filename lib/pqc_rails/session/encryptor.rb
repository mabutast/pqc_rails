# frozen_string_literal: true

require "base64"
require_relative "../blob_packing"
require_relative "../hybrid_kem"
require_relative "../envelope_cipher"
require_relative "../ciphertext_format"
require_relative "../active_record/key_provider"
require_relative "json_payload"

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

      # session_serializerが:jsonなら形式v2(中身はJSON)、:marshalならv1(ciphertext_formatが:v0ならv0)で書く。
      def encrypt(data)
        return Base64.strict_encode64(seal_json(data)) if PqcRails.configuration.session_serializer == :json

        notify_not_json_safe(data)
        serialized = Marshal.dump(data)
        return Base64.strict_encode64(seal_legacy(serialized)) if CiphertextFormat.write_legacy?

        Base64.strict_encode64(seal_v1(serialized))
      end

      # 先頭バイトで形式を判別する。旧形式(v0)は先頭がKEM暗号文の4バイト長(ビッグエンディアン)で、
      # KEM暗号文は16MB未満のため先頭バイトは必ず0になる。1以上なら形式バージョンとして読む。
      # 途中で切れた・壊れたCookieは、どの段で見つかってもPqcRails::Errorにする。
      # v2はJSONとして読み、Marshal.loadに渡さない。v0・v1(Marshal)は、session_serializerが:jsonの間は期限内だけ読む。
      def decrypt(blob)
        bytes = Base64.strict_decode64(blob)
        if bytes.getbyte(0) == CiphertextFormat::SESSION_JSON_VERSION
          JsonPayload.load(open_cookie(bytes))
        else
          CiphertextFormat.ensure_marshal_cookie_accepted!
          Marshal.load(open_cookie(bytes))
        end
      end

      # この鍵で旧形式のCookieを書けない理由(読み戻せないため)。書ける場合はnil。
      def legacy_write_blocker
        return "the key has an authentication key" unless @keypair.authentication_key.nil?

        "the key is also configured for records" if shared_with_records?
      end

      private

      # 既定の鍵の置き場所と、Context.install!の鍵ソース、ActiveRecord::Encryptionの今のコンテキストの鍵ソースを見る。
      # 属性ごとに指定したkey_providerは対象外。
      def shared_with_records?
        public_key = @keypair.public_key.b
        default_record_public_keys.include?(public_key) || configured_record_public_keys.include?(public_key)
      end

      # 既定の鍵の置き場所はプロセスの間変わらないので、読み込みは1回だけにする。
      def default_record_public_keys
        @default_record_public_keys ||= ActiveRecord::KeyProvider.new.public_keys.map(&:b)
      end

      # コンテキストはスレッドや処理の範囲で変わるので、結果を覚えない。
      def configured_record_public_keys
        ActiveRecord::KeyProvider.configured.flat_map(&:public_keys).map(&:b)
      end

      # :marshalで書く間に、:jsonへ切り替えると書けなくなる値があれば、最上位のキーの名前だけを知らせる。
      def notify_not_json_safe(data)
        keys = JsonPayload.unsafe_keys(data)
        return if keys.empty?

        ActiveSupport::Notifications.instrument("session_not_json_safe.pqc_rails", keys: keys)
      end

      def open_cookie(bytes)
        case bytes.getbyte(0)
        when 0 then open_legacy(bytes)
        when CiphertextFormat::VERSION then open_versioned(bytes, CiphertextFormat::VERSION)
        when CiphertextFormat::SESSION_JSON_VERSION then open_versioned(bytes, CiphertextFormat::SESSION_JSON_VERSION)
        else raise PqcRails::Error, "unsupported ciphertext format version: #{bytes.getbyte(0).inspect}"
        end
      rescue OpenSSL::Cipher::CipherError, ArgumentError => e
        raise PqcRails::Error, e.message
      end

      # 旧形式(v0): [4バイト長][KEM暗号文][4バイト長][AES暗号文]
      def seal_legacy(serialized)
        blocker = legacy_write_blocker
        raise PqcRails::Error, "ciphertext_format :v0 cannot write session cookies: #{blocker}; see docs/MIGRATION.md" if blocker

        HybridKem.open(@pq_alg_name) do |hybrid|
          encap = hybrid.encapsulate(@keypair.public_key)
          BlobPacking.pack(encap.ciphertext, EnvelopeCipher.new(encap.shared_secret).encrypt(serialized))
        end
      end

      def open_legacy(bytes)
        CiphertextFormat.ensure_legacy_cookie_accepted!(@keypair, shared_with_records: shared_with_records?)
        ciphertext, encrypted = BlobPacking.unpack(bytes, exact: true)

        HybridKem.open(@pq_alg_name) do |hybrid|
          shared_secret = hybrid.decapsulate(ciphertext, @keypair.secret_key)
          EnvelopeCipher.new(shared_secret).decrypt(encrypted)
        end
      end

      def seal_json(data)
        if CiphertextFormat.write_legacy?
          raise PqcRails::Error,
                "session_serializer :json cannot be used while ciphertext_format is :v0 " \
                "(servers on pqc_rails 0.3.0 or earlier cannot read it); see docs/MIGRATION.md"
        end

        seal_versioned(JsonPayload.dump(data), CiphertextFormat::SESSION_JSON_VERSION)
      end

      def seal_v1(serialized) = seal_versioned(serialized, CiphertextFormat::VERSION)

      # v1・v2: [形式バージョン 1B][アルゴリズムIDの長さ 1B][アルゴリズムID][鍵ID 2B][v0と同じ本体]
      # v1の中身はMarshal、v2の中身はJSON。形式バージョンはAES鍵の導出と追加認証データに入る。
      def seal_versioned(serialized, version)
        algorithm_id = CiphertextFormat.algorithm_id(@pq_alg_name)
        key_id = CiphertextFormat.key_id(@keypair.public_key)
        associated_data = CiphertextFormat.associated_data(algorithm_id: algorithm_id, key_id: key_id,
                                                           purpose: :session, version: version)
        header = [version, algorithm_id.bytesize].pack("CC") + algorithm_id + [key_id].pack("H4")

        HybridKem.open(CiphertextFormat.canonical_pq_alg_name(@pq_alg_name)) do |hybrid|
          encap = hybrid.encapsulate(@keypair.public_key)
          data_key = CiphertextFormat.data_key(encap.shared_secret, @keypair.authentication_key,
                                               purpose: :session, version: version)
          encrypted = EnvelopeCipher.new(data_key).encrypt(serialized, associated_data: associated_data)
          header + BlobPacking.pack(encap.ciphertext, encrypted)
        end
      end

      def open_versioned(bytes, version)
        algorithm_id_length = bytes.getbyte(1)
        if algorithm_id_length.nil? || bytes.bytesize < 4 + algorithm_id_length
          raise PqcRails::Error, "the cookie is truncated: missing the format header"
        end

        algorithm_id = bytes[2, algorithm_id_length]
        key_id = bytes[2 + algorithm_id_length, 2].unpack1("H4")
        body = bytes[(4 + algorithm_id_length)..]

        if key_id != CiphertextFormat.key_id(@keypair.public_key)
          raise PqcRails::Error, "the cookie was encrypted with a different key id (#{key_id})"
        end

        pq_alg_name = CiphertextFormat.pq_alg_name_for(algorithm_id, configured: @pq_alg_name)
        associated_data = CiphertextFormat.associated_data(algorithm_id: algorithm_id, key_id: key_id,
                                                           purpose: :session, version: version)
        ciphertext, encrypted = BlobPacking.unpack(body, exact: true)

        HybridKem.open(pq_alg_name) do |hybrid|
          shared_secret = hybrid.decapsulate(ciphertext, @keypair.secret_key)
          data_key = CiphertextFormat.data_key(shared_secret, @keypair.authentication_key,
                                               purpose: :session, version: version)
          EnvelopeCipher.new(data_key).decrypt(encrypted, associated_data: associated_data)
        end
      end
    end
  end
end
