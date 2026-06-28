# frozen_string_literal: true

require "rails"

module PqcRails
  # 環境変数→Rails credentialsの順で値を読み込む共通処理。
  # Session::KeyManagerとActiveRecord::KeyProviderで同じ手順が必要になるため共通化している。
  # 環境変数を優先するのは本番運用でcredentialsファイルを使わずに鍵を渡せるようにするため
  # (コンテナのsecret注入等と相性が良い)。
  module KeySource
    module_function

    def fetch(env_var:, credentials_key:)
      ENV.fetch(env_var, nil) || credentials_value(credentials_key)
    end

    def credentials_value(credentials_key)
      return nil unless Rails.respond_to?(:application) && Rails.application

      Rails.application.credentials[credentials_key]
    end
  end
end
