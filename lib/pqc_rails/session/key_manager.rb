# frozen_string_literal: true

require "base64"
require_relative "../blob_packing"
require_relative "../hybrid_kem"
require_relative "../key_source"

module PqcRails
  module Session
    class MissingKeyError < PqcRails::Error; end

    # セッション暗号化用のHybridKemキーペアを、環境変数またはRails credentialsから読み込む。
    # 環境変数を優先するのは本番運用でcredentialsファイルを使わずに鍵を渡せるようにするため
    # (コンテナのsecret注入等と相性が良い)。
    module KeyManager
      ENV_VAR = "PQC_SESSION_KEY"
      CREDENTIALS_KEY = :pqc_session_key

      module_function

      def keypair
        encoded = KeySource.fetch(env_var: ENV_VAR, credentials_key: CREDENTIALS_KEY)
        if encoded.nil?
          raise MissingKeyError,
                "PQC session key not found. Set ENV['#{ENV_VAR}'] or run `rails generate pqc_rails:install`."
        end

        decode(encoded)
      end

      def encode(keypair)
        Base64.strict_encode64(BlobPacking.pack(keypair.public_key, keypair.secret_key))
      end

      def decode(encoded)
        public_key, secret_key = BlobPacking.unpack(Base64.strict_decode64(encoded))
        HybridKem::Keypair.new(public_key, secret_key)
      end
    end
  end
end
