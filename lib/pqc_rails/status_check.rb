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
        active_record_encryption_result,
        encrypted_attributes_result,
        algorithms_result
      ]
    end

    private

    def liboqs_result
      Result.new(name: "liboqs", ok: true,
                 detail: "#{PqcRails.configuration.liboqs_path} を使用中(版 #{PqcRails.liboqs_version})")
    end

    def key_result(name:, env_var:, credentials_key:)
      encoded = KeySource.fetch(env_var: env_var, credentials_key: credentials_key)
      state = encoded && key_state(encoded)
      if state == :truncated
        Result.new(name: name, ok: false, detail: "鍵の値が途中で切れています。鍵の値を最後まで貼り直してください")
      elsif state == :legacy
        Result.new(name: name, ok: false,
                   detail: "認証鍵を持たない0.3.0以前の形式の鍵です。新しい鍵を生成してローテーションしてください(docs/MIGRATION.md)")
      elsif encoded
        Result.new(name: name, ok: true, detail: "設定済み")
      else
        Result.new(name: name, ok: false,
                   detail: "未設定です。`rails generate pqc_rails:install` を実行したか確認してください")
      end
    end

    # 途中で切れた鍵なら:truncated、認証鍵を持たない(0.3.0以前に生成した)鍵なら:legacyを返す。
    # Base64として読めない等の値は、ここでは判定しない(nil)。
    def key_state(encoded)
      :legacy if KeySource.decode(encoded).authentication_key.nil?
    rescue PqcRails::Error
      :truncated
    rescue ArgumentError, TypeError, NoMethodError
      nil
    end

    def previous_keys_result(name:, env_var:, credentials_key:)
      raw = KeySource.fetch(env_var: env_var, credentials_key: credentials_key)
      entries = raw.nil? ? [] : (raw.is_a?(::Array) ? raw : raw.split(","))
      count = entries.size
      truncated = entries.index { |encoded| key_state(encoded.strip) == :truncated }

      if truncated
        Result.new(name: name, ok: false,
                   detail: "#{truncated + 1}世代目の旧鍵の値が途中で切れています。鍵の値を最後まで貼り直してください")
      elsif count.zero?
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

    # encryptsで暗号化している属性の一覧。件数・暗号文の内訳は数えない(pqc_rails Proのpqc_rails:pro:inventory)。
    # rakeタスクの:environmentはモデルを読み込まないので、一覧を作る前にeager_load!する。
    def encrypted_attributes_result
      name = "暗号化している属性"
      return Result.new(name: name, ok: true, detail: "activerecordが読み込まれていません") unless defined?(::ActiveRecord::Base)

      app = rails_application
      app.eager_load! if app.respond_to?(:eager_load!)
      listed = encrypted_models.map { |model| "#{model.name}(#{model.encrypted_attributes.map(&:to_s).sort.join(', ')})" }
      if listed.empty?
        Result.new(name: name, ok: true,
                   detail: "見つかりません。encrypts を書いたモデルが読み込まれているか確認してください")
      else
        Result.new(name: name, ok: true, detail: listed.join(", "))
      end
    rescue StandardError => e
      Result.new(name: name, ok: false, detail: "確認できませんでした(#{e.message})")
    end

    def encrypted_models
      ::ActiveRecord::Base.descendants
                          .reject { |model| model.abstract_class? || model.name.nil? }
                          .select { |model| model.respond_to?(:encrypted_attributes) && model.encrypted_attributes.present? }
                          .sort_by(&:name)
    end

    # DBとセッションが新しく暗号化する時に暗号文へ書くアルゴリズムID。
    def algorithms_result
      Result.new(name: "使うアルゴリズム", ok: true,
                 detail: "DB: #{record_algorithm_id}、セッション: #{session_algorithm_id}")
    end

    def record_algorithm_id
      cipher = defined?(::ActiveRecord::Encryption) && ::ActiveRecord::Encryption.context.cipher
      cipher.is_a?(PqcRails::Cipher) ? cipher.algorithm_id : "pqc_railsを使っていません"
    rescue StandardError
      "確認できませんでした"
    end

    def session_algorithm_id
      app = rails_application
      item = app&.middleware&.find { |m| m.klass == PqcRails::Session::PqcCookieStore }
      return "pqc_railsを使っていません" unless item

      options = item.respond_to?(:args) ? item.args.grep(::Hash).last : nil
      CiphertextFormat.algorithm_id((options || {})[:pq_alg_name] || Session::Encryptor::DEFAULT_PQ_ALG_NAME)
    rescue StandardError
      "確認できませんでした"
    end

    def rails_application
      ::Rails.application if defined?(::Rails) && ::Rails.respond_to?(:application)
    end
  end
end
