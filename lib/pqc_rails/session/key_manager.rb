# frozen_string_literal: true

require_relative "../key_source"

module PqcRails
  module Session
    # セッション暗号化用のHybridKemキーペアを、環境変数またはRails credentialsから読み込む。
    # 実際のfetch/decode処理はKeySourceに一本化されており、ここはセッション用の
    # ENV変数名/credentialsキーを添えて委譲するだけ。
    module KeyManager
      ENV_VAR = "PQC_SESSION_KEY"
      CREDENTIALS_KEY = :pqc_session_key

      module_function

      def keypair
        KeySource.fetch_keypair!(env_var: ENV_VAR, credentials_key: CREDENTIALS_KEY, label: "session")
      end

      def encode(keypair) = KeySource.encode(keypair)
      def decode(encoded) = KeySource.decode(encoded)
    end
  end
end
