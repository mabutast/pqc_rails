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

      class << self
        # Context.install!で設定したKeyProvider。with_encryption_contextの中でも判定から外れないように持つ。
        attr_accessor :installed

        # install!で設定したものと、今のコンテキストのもののうち、pqc_railsの鍵を返すKeyProvider。
        def configured
          [installed, current_context_provider].compact.uniq.select { |provider| provider.respond_to?(:public_keys) }
        end

        # 読み込まれたモデルの暗号化属性に指定したKeyProvider(previous:の分も含む)のうち、pqc_railsの鍵を返すもの。
        # key_providerを指定していない属性(既定のKeyProviderを使う属性)は含まない。既定のものはconfiguredで見る。
        # 属性の型を読むので、スキーマが読み込まれていなければDBに問い合わせる。
        # 遅延読み込みでまだ読み込まれていないモデルは含まれない。
        def per_attribute
          encrypted_models.flat_map { |model| attribute_providers(model) }.uniq.select { |provider| provider.respond_to?(:public_keys) }
        end

        # encryptsで暗号化属性を持つ、読み込まれたモデル(抽象クラスを除く)。
        def encrypted_models
          return [] unless defined?(::ActiveRecord::Base)

          ::ActiveRecord::Base.descendants
                              .reject(&:abstract_class?)
                              .select { |model| model.respond_to?(:encrypted_attributes) && model.encrypted_attributes.present? }
        end

        private

        # テーブルの無いモデルと、DBの接続が定義されていないモデルには暗号化した値が無いので、鍵を比べる対象から外す。
        # DBに接続できない時(接続は定義済み)は例外をそのまま送出する。
        def attribute_providers(model)
          return [] unless connection_defined?(model) && model.table_exists?

          model.encrypted_attributes.flat_map do |name|
            scheme = model.type_for_attribute(name).scheme
            [scheme, *scheme.previous_schemes].filter_map { |each_scheme| each_scheme.to_h[:key_provider] }
          end
        end

        def connection_defined?(model)
          model.connection_handler.connection_pool_names.include?(model.connection_specification_name)
        end

        def current_context_provider
          return unless defined?(::ActiveRecord::Encryption)

          ::ActiveRecord::Encryption.context.key_provider
        rescue ::ActiveRecord::Encryption::Errors::Configuration
          nil
        end
      end

      def initialize(key_source: default_key_source)
        @key_source = key_source
      end

      # 属性ごとにkey_providerを指定すると、Railsの6.1のMarshalの形式はレコードの属性の型からこのオブジェクトまでたどる。
      # 覚えた鍵(@encryption_key)は書かず、鍵ソースだけを書く。読み戻した後は、最初の呼び出しで鍵を読み直す。
      def marshal_dump
        @key_source
      end

      def marshal_load(key_source)
        @key_source = key_source
      end

      def encryption_key
        @encryption_key ||= build_key(@key_source.current_keypair)
      end

      def decryption_keys(_encrypted_message)
        [encryption_key] + @key_source.previous_keypairs.map { |keypair| build_key(keypair) }
      end

      # 現行鍵と旧鍵の公開鍵。鍵が未設定なら含めない。
      def public_keys
        current = begin
          [@key_source.current_keypair]
        rescue PqcRails::MissingKeyError
          []
        end
        (current + @key_source.previous_keypairs).map(&:public_key)
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
