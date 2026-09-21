# frozen_string_literal: true

require_relative "key_source"
require_relative "session/key_manager"
require_relative "active_record/key_provider"

module PqcRails
  # `rails pqc_rails:status` から呼ばれる、実行時の設定状況の自己診断。
  #
  # 鍵未設定(MissingKeyError)はセッション/DBの暗号化・復号が実際に走るまで発覚しない
  # 遅延的なエラーのため、デプロイ前・導入直後に能動的に確認できる手段として用意する。
  # liboqs自体の読み込みはgem require時(FFI::Library#ffi_lib)に即座に失敗するため、
  # このチェックが実行できている時点で既に成功している。ここでは参考情報として
  # 実際に使われているパスのみ報告する。
  class StatusCheck
    Result = Struct.new(:name, :ok, :detail, keyword_init: true)

    def self.run
      new.run
    end

    def run
      [
        liboqs_result,
        key_result(name: "セッション鍵 (PQC_SESSION_KEY)",
                   env_var: Session::KeyManager::ENV_VAR, credentials_key: Session::KeyManager::CREDENTIALS_KEY),
        previous_keys_result(name: "セッション旧鍵 (PQC_SESSION_PREVIOUS_KEYS)",
                              env_var: Session::KeyManager::PREVIOUS_ENV_VAR,
                              credentials_key: Session::KeyManager::PREVIOUS_CREDENTIALS_KEY),
        key_result(name: "DBレコード鍵 (PQC_RECORD_KEY)",
                   env_var: ActiveRecord::KeyProvider::ENV_VAR, credentials_key: ActiveRecord::KeyProvider::CREDENTIALS_KEY),
        previous_keys_result(name: "DBレコード旧鍵 (PQC_RECORD_PREVIOUS_KEYS)",
                              env_var: ActiveRecord::KeyProvider::PREVIOUS_ENV_VAR,
                              credentials_key: ActiveRecord::KeyProvider::PREVIOUS_CREDENTIALS_KEY),
        session_store_result,
        active_record_encryption_result
      ]
    end

    private

    def liboqs_result
      Result.new(name: "liboqs", ok: true, detail: "#{PqcRails.configuration.liboqs_path} を使用中")
    end

    def key_result(name:, env_var:, credentials_key:)
      if KeySource.fetch(env_var: env_var, credentials_key: credentials_key)
        Result.new(name: name, ok: true, detail: "設定済み")
      else
        Result.new(name: name, ok: false,
                   detail: "未設定です。`rails generate pqc_rails:install` を実行したか確認してください")
      end
    end

    def previous_keys_result(name:, env_var:, credentials_key:)
      raw = KeySource.fetch(env_var: env_var, credentials_key: credentials_key)
      count = raw.nil? ? 0 : (raw.is_a?(::Array) ? raw.size : raw.split(",").size)

      if count.zero?
        Result.new(name: name, ok: true, detail: "未設定(ローテーション中ではありません)")
      else
        Result.new(name: name, ok: true, detail: "#{count}世代の旧鍵を保持中(鍵ローテーション中)")
      end
    end

    def session_store_result
      unless defined?(::Rails) && ::Rails.respond_to?(:application) && ::Rails.application
        return Result.new(name: "セッションストア", ok: false, detail: "Rails.applicationが初期化されていません")
      end

      if ::Rails.application.middleware.any? { |m| m.klass == PqcRails::Session::PqcCookieStore }
        Result.new(name: "セッションストア", ok: true, detail: ":pqc_cookie_store が有効です")
      else
        Result.new(name: "セッションストア", ok: false,
                   detail: "config.session_store :pqc_cookie_store が設定されていません")
      end
    rescue StandardError => e
      Result.new(name: "セッションストア", ok: false, detail: "確認できませんでした(#{e.message})")
    end

    def active_record_encryption_result
      return Result.new(name: "ActiveRecord::Encryption", ok: false, detail: "activerecordが読み込まれていません") unless defined?(::ActiveRecord::Encryption)

      if ::ActiveRecord::Encryption.context.cipher.is_a?(PqcRails::Cipher)
        Result.new(name: "ActiveRecord::Encryption", ok: true, detail: "PqcRails::Cipher が設定されています")
      else
        Result.new(name: "ActiveRecord::Encryption", ok: false,
                   detail: "PqcRails::ActiveRecord::Context.install! が呼ばれていません")
      end
    rescue StandardError => e
      Result.new(name: "ActiveRecord::Encryption", ok: false, detail: "確認できませんでした(#{e.message})")
    end
  end
end
