# frozen_string_literal: true

require "rails"
require "base64"
require_relative "blob_packing"
require_relative "hybrid_kem"

module PqcRails
  class MissingKeyError < PqcRails::Error; end

  # 環境変数、次いでRails credentialsの順で鍵を読み込み、HybridKem::Keypairへデコードするまでの
  # 共通処理。Session::KeyManagerとActiveRecord::KeyProviderは、いずれも鍵の取得を
  # このモジュールに委譲する。環境変数を優先するのは、コンテナのsecret注入のように
  # credentialsファイルを介さずに鍵を渡せるようにするため。
  module KeySource
    module_function

    def fetch(env_var:, credentials_key:)
      ENV.fetch(env_var, nil) || credentials_value(credentials_key)
    end

    # fetchと同様に鍵を取得する。値が見つからない場合はMissingKeyErrorを送出する。
    def fetch!(env_var:, credentials_key:, label:)
      fetch(env_var: env_var, credentials_key: credentials_key) ||
        raise(MissingKeyError,
              "PQC #{label} key not found. Set ENV['#{env_var}'] or run `rails generate pqc_rails:install`.")
    end

    # fetch!で鍵を取得し、decodeまで行った上でHybridKem::Keypairを返す。
    def fetch_keypair!(env_var:, credentials_key:, label:)
      decode(fetch!(env_var: env_var, credentials_key: credentials_key, label: label))
    end

    def credentials_value(credentials_key)
      return nil unless Rails.respond_to?(:application) && Rails.application

      Rails.application.credentials[credentials_key]
    end

    # HybridKem::Keypairのシリアライズ形式。鍵の保存形式そのものであり、
    # セッション・ActiveRecordの両方の鍵管理から利用する。
    def encode(keypair)
      Base64.strict_encode64(BlobPacking.pack(keypair.public_key, keypair.secret_key))
    end

    def decode(encoded)
      public_key, secret_key = BlobPacking.unpack(Base64.strict_decode64(encoded))
      HybridKem::Keypair.new(public_key, secret_key)
    end

    # ENV、またはRails credentialsから現行鍵・旧鍵世代を読み込む、デフォルトの鍵ソース。
    #
    # Session::KeyManagerとActiveRecord::KeyProviderは、鍵の取得をこのクラスのインスタンスに
    # 委譲する。`#current_keypair`/`#previous_keypairs`の2メソッドを実装するオブジェクトであれば
    # 差し替え可能(例: HSM/PKCS#11経由の鍵ソース)。
    #
    # 旧鍵世代は、ENVではカンマ区切りの文字列、credentialsでは配列として指定する
    # (ENVは文字列しか保持できないため)。世代数に上限はない。鍵のローテーションを
    # 完了したら、previous_env_var/previous_credentials_keyを空にすることで旧鍵を無効化できる。
    class EnvCredentials
      def initialize(env_var:, previous_env_var:, credentials_key:, previous_credentials_key:, label:)
        @env_var = env_var
        @previous_env_var = previous_env_var
        @credentials_key = credentials_key
        @previous_credentials_key = previous_credentials_key
        @label = label
      end

      def current_keypair
        KeySource.fetch_keypair!(env_var: @env_var, credentials_key: @credentials_key, label: @label)
      end

      def previous_keypairs
        raw = KeySource.fetch(env_var: @previous_env_var, credentials_key: @previous_credentials_key)
        return [] if raw.nil?

        entries = raw.is_a?(::Array) ? raw : raw.split(",")
        entries.map { |encoded| KeySource.decode(encoded.strip) }
      end
    end
  end
end
