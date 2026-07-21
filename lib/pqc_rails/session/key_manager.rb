# frozen_string_literal: true

require_relative "../key_source"

module PqcRails
  module Session
    # セッション暗号化用のHybridKemキーペアを、環境変数またはRails credentialsから読み込む。
    # 実際のfetch/decode処理はKeySource::EnvCredentialsに一本化されており、ここはセッション用の
    # ENV変数名/credentialsキーを添えて委譲するだけ。
    #
    # 鍵ローテーション時は#previous_keypairsが旧鍵世代を返す。PqcCookieStoreはこれを使って
    # 現行鍵で復号できなかったCookieを旧鍵で試す。セッションはDBと違い自然に失効するため、
    # ロールバック期間(概ね最長セッション有効期限)を過ぎたら運用側がPREVIOUS_ENV_VARを
    # 空にすれば旧鍵は自動的に無効化される。
    module KeyManager
      ENV_VAR = "PQC_SESSION_KEY"
      PREVIOUS_ENV_VAR = "PQC_SESSION_PREVIOUS_KEYS"
      CREDENTIALS_KEY = :pqc_session_key
      PREVIOUS_CREDENTIALS_KEY = :pqc_session_previous_keys

      module_function

      def keypair
        key_source.current_keypair
      end

      def previous_keypairs
        key_source.previous_keypairs
      end

      def encode(keypair) = KeySource.encode(keypair)
      def decode(encoded) = KeySource.decode(encoded)

      def key_source
        KeySource::EnvCredentials.new(
          env_var: ENV_VAR, previous_env_var: PREVIOUS_ENV_VAR,
          credentials_key: CREDENTIALS_KEY, previous_credentials_key: PREVIOUS_CREDENTIALS_KEY,
          label: "session"
        )
      end
    end
  end
end
