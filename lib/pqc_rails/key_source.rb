# frozen_string_literal: true

require "rails"
require "base64"
require_relative "blob_packing"
require_relative "secret_buffer"
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
    # [公開鍵][秘密鍵][認証鍵]をBlobPacking.pack_allでまとめる。0.3.0以前の鍵は認証鍵を持たない2要素の形で、
    # 0.3.0以前の版は先頭の2要素だけを読むため、3要素の鍵も読める。
    def encode(keypair)
      parts = [keypair.public_key, keypair.secret_key, keypair.authentication_key].compact
      Base64.strict_encode64(BlobPacking.pack_all(*parts))
    end

    # Base64から戻したバイト列は、鍵を取り出した後にゼロで埋める(鍵ペアが持つのは取り出したコピーだけ)。
    def decode(encoded)
      raw = Base64.strict_decode64(encoded)
      public_key, secret_key, authentication_key = BlobPacking.unpack_all(raw)
      HybridKem::Keypair.new(public_key, secret_key, authentication_key)
    ensure
      SecretBuffer.wipe(raw)
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

      # 鍵は最初の呼び出しで1回だけ復元し、以後は同じ鍵ペアを返す。呼び出しのたびに復元すると、
      # 秘密鍵のコピーが作られては消されずに解放され、メモリに溜まるため。ENV・credentialsは
      # プロセスの起動後に変わらない前提で、鍵を替える時はプロセスを再起動する。
      def current_keypair
        @current_keypair ||= KeySource.fetch_keypair!(env_var: @env_var, credentials_key: @credentials_key,
                                                      label: @label)
      end

      def previous_keypairs
        @previous_keypairs ||= begin
          raw = KeySource.fetch(env_var: @previous_env_var, credentials_key: @previous_credentials_key)
          entries = raw.nil? ? [] : (raw.is_a?(::Array) ? raw : raw.split(","))
          entries.map { |encoded| KeySource.decode(encoded.strip) }
        end
      end
    end
  end
end
