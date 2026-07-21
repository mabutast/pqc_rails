# frozen_string_literal: true

require "rails"
require "base64"
require_relative "blob_packing"
require_relative "hybrid_kem"

module PqcRails
  class MissingKeyError < PqcRails::Error; end

  # 環境変数→Rails credentialsの順で鍵を読み込み、HybridKem::Keypairへデコードするまでの
  # 共通処理。Session::KeyManagerとActiveRecord::KeyProviderで同じ手順(fetch→無ければ例外→decode)
  # が必要になるため共通化している。環境変数を優先するのは本番運用でcredentialsファイルを
  # 使わずに鍵を渡せるようにするため(コンテナのsecret注入等と相性が良い)。
  module KeySource
    module_function

    def fetch(env_var:, credentials_key:)
      ENV.fetch(env_var, nil) || credentials_value(credentials_key)
    end

    # fetchした値がnilならMissingKeyErrorを送出する版。
    def fetch!(env_var:, credentials_key:, label:)
      fetch(env_var: env_var, credentials_key: credentials_key) ||
        raise(MissingKeyError,
              "PQC #{label} key not found. Set ENV['#{env_var}'] or run `rails generate pqc_rails:install`.")
    end

    # fetch! + decodeまでを1回で行う。Session::KeyManager#keypairとActiveRecord::KeyProvider#keypairの
    # 両方が同じ「fetch→無ければ例外→decode」という処理列を重複実装していたため、ここに統合した。
    def fetch_keypair!(env_var:, credentials_key:, label:)
      decode(fetch!(env_var: env_var, credentials_key: credentials_key, label: label))
    end

    def credentials_value(credentials_key)
      return nil unless Rails.respond_to?(:application) && Rails.application

      Rails.application.credentials[credentials_key]
    end

    # HybridKem::Keypairのシリアライズ形式。セッション固有の処理ではなく鍵の保存形式そのものなので、
    # Session::KeyManagerではなくここに置く(セッション/AR両方から使われる)。
    def encode(keypair)
      Base64.strict_encode64(BlobPacking.pack(keypair.public_key, keypair.secret_key))
    end

    def decode(encoded)
      public_key, secret_key = BlobPacking.unpack(Base64.strict_decode64(encoded))
      HybridKem::Keypair.new(public_key, secret_key)
    end

    # ENV/Rails credentialsから現行鍵・旧鍵世代を読み込むデフォルトの鍵ソース。
    #
    # Session::KeyManagerとActiveRecord::KeyProviderは、鍵の取得元をこのクラスのインスタンスに
    # 委譲する。`#current_keypair`/`#previous_keypairs`という2メソッドさえ実装すれば、
    # 将来HSM/PKCS#11経由の鍵ソースにも差し替えられる(実装はしないが、この分離だけで済むように
    # しておく、というPhase4での抽象化)。
    #
    # 旧鍵世代は、ENVではカンマ区切りの文字列、credentialsでは配列として持たせる(ENVは
    # 文字列しか持てないため)。世代数に上限は設けない。ローテーション完了後は運用側が
    # previous_env_var/previous_credentials_keyを空にすることで旧鍵を無効化する。
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
