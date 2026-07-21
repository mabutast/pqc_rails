# frozen_string_literal: true

require "digest"
require_relative "../key_source"

module PqcRails
  module ActiveRecord
    # ActiveRecord::Encryption::KeyProvider互換。HybridKemの鍵ペアを返す実装。
    #
    # 既存のActiveRecord::Encryption::KeyProvider(Key#secretが単一の不透明な文字列)は
    # 公開鍵/秘密鍵という「鍵ペア」の概念を持たないため、ML-KEMを使う余地が無い。
    # そのためKeyProvider自体を独自実装し、`key.secret`がPqcRails::HybridKem::Keypair
    # (公開鍵・秘密鍵のペア)を返すようにしている。
    #
    # 鍵のソース(環境変数→Rails credentials→decode)はKeySourceに一本化されており、
    # セッション用の鍵とは異なるENV変数名/credentialsキーを渡すことで用途ごとに鍵を分離する。
    #
    # 鍵ローテーションは#decryption_keysが現行鍵に続けて旧鍵世代を返すことで対応する
    # (ActiveRecord::Encryption::Cipher互換の#decryptは配列の各鍵を順に試すため、
    # PqcRails::Cipher#decryptは変更不要)。旧鍵はPQC_RECORD_PREVIOUS_KEYS(ENV)または
    # pqc_record_previous_keys(credentials)から読み込む。
    class KeyProvider
      ENV_VAR = "PQC_RECORD_KEY"
      PREVIOUS_ENV_VAR = "PQC_RECORD_PREVIOUS_KEYS"
      CREDENTIALS_KEY = :pqc_record_key
      PREVIOUS_CREDENTIALS_KEY = :pqc_record_previous_keys

      Key = Struct.new(:secret) do
        def id
          Digest::SHA1.hexdigest(secret.public_key).first(4)
        end

        def public_tags
          @public_tags ||= ::ActiveRecord::Encryption::Properties.new
        end
      end

      def initialize(key_source: default_key_source)
        @key_source = key_source
      end

      def encryption_key
        @encryption_key ||= build_key(@key_source.current_keypair)
      end

      def decryption_keys(_encrypted_message)
        [encryption_key] + @key_source.previous_keypairs.map { |keypair| build_key(keypair) }
      end

      private

      def default_key_source
        PqcRails::KeySource::EnvCredentials.new(
          env_var: ENV_VAR, previous_env_var: PREVIOUS_ENV_VAR,
          credentials_key: CREDENTIALS_KEY, previous_credentials_key: PREVIOUS_CREDENTIALS_KEY,
          label: "record"
        )
      end

      def build_key(keypair)
        Key.new(keypair).tap do |key|
          key.public_tags.encrypted_data_key_id = key.id if ::ActiveRecord::Encryption.config.store_key_references
        end
      end
    end
  end
end
