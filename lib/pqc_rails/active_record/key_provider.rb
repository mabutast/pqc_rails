# frozen_string_literal: true

require "digest"
require_relative "../key_source"
require_relative "../session/key_manager"

module PqcRails
  module ActiveRecord
    class MissingKeyError < PqcRails::Error; end

    # ActiveRecord::Encryption::KeyProvider互換。HybridKemの鍵ペアを1つだけ返す最小実装。
    #
    # 既存のActiveRecord::Encryption::KeyProvider(Key#secretが単一の不透明な文字列)は
    # 公開鍵/秘密鍵という「鍵ペア」の概念を持たないため、ML-KEMを使う余地が無い。
    # そのためKeyProvider自体を独自実装し、`key.secret`がPqcRails::HybridKem::Keypair
    # (公開鍵・秘密鍵のペア)を返すようにしている。
    #
    # 鍵のソース(環境変数→Rails credentials)はSession::KeyManagerと同じ仕組みを使うが、
    # セッション用の鍵とは異なるENV変数名/credentialsキーを使い、用途ごとに鍵を分離する。
    #
    # 複数世代の鍵によるローテーションはPhase 4で#decryption_keysを拡張して対応する。
    # 現時点では#encryption_keyと同じ単一鍵のみを返す。
    class KeyProvider
      ENV_VAR = "PQC_RECORD_KEY"
      CREDENTIALS_KEY = :pqc_record_key

      Key = Struct.new(:secret) do
        def id
          Digest::SHA1.hexdigest(secret.public_key).first(4)
        end

        def public_tags
          @public_tags ||= ::ActiveRecord::Encryption::Properties.new
        end
      end

      def encryption_key
        @encryption_key ||= Key.new(keypair).tap do |key|
          key.public_tags.encrypted_data_key_id = key.id if ::ActiveRecord::Encryption.config.store_key_references
        end
      end

      def decryption_keys(_encrypted_message)
        [encryption_key]
      end

      private

      def keypair
        encoded = PqcRails::KeySource.fetch(env_var: ENV_VAR, credentials_key: CREDENTIALS_KEY)
        if encoded.nil?
          raise MissingKeyError,
                "PQC record key not found. Set ENV['#{ENV_VAR}'] or run `rails generate pqc_rails:install`."
        end

        PqcRails::Session::KeyManager.decode(encoded)
      end
    end
  end
end
