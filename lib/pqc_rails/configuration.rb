# frozen_string_literal: true

module PqcRails
  # gem全体の設定。Railsアプリ側からは以下のように使う想定:
  #
  #   # config/initializers/pqc_rails.rb
  #   PqcRails.configure do |config|
  #     config.liboqs_path = "/usr/local/lib/liboqs.dylib"
  #   end
  class Configuration
    # liboqsの共有ライブラリへのパス。
    # 未設定の場合、環境変数 LIBOQS_PATH、それも無ければOS標準の場所を仮定する。
    attr_accessor :liboqs_path

    CIPHERTEXT_FORMATS = %i[v1 v0].freeze

    # 暗号化時に書く暗号文の形式。復号は設定によらず両方の形式を読める。
    # :v1 形式バージョン・アルゴリズムID・鍵IDを持つ形式(既定)
    # :v0 0.3.0以前と同じ旧形式。複数台のサーバーへ順番にデプロイする間、まだ旧版のgemが動いている
    #     サーバーにも読める暗号文を書くために使う。全台の更新後に:v1へ戻す
    attr_reader :ciphertext_format

    # 旧形式(v0)の暗号文を復号するかどうか(既定はtrue)。
    # 旧形式は作成元の認証を持たず、公開鍵だけで正しく復号できる暗号文を作れる。
    # 旧形式のデータが残っていない状態(DBは全レコードの再暗号化後、Cookieは最長のセッション有効期限の経過後)に
    # なったらfalseにし、旧形式の暗号文を受け付けないようにする。
    attr_reader :accept_legacy_ciphertexts

    def initialize
      @liboqs_path = ENV["LIBOQS_PATH"] || default_liboqs_path
      @ciphertext_format = :v1
      @accept_legacy_ciphertexts = true
    end

    def ciphertext_format=(format)
      unless CIPHERTEXT_FORMATS.include?(format)
        raise ArgumentError, "ciphertext_format must be one of #{CIPHERTEXT_FORMATS.inspect}, got #{format.inspect}"
      end

      @ciphertext_format = format
    end

    def accept_legacy_ciphertexts=(value)
      unless [true, false].include?(value)
        raise ArgumentError, "accept_legacy_ciphertexts must be true or false, got #{value.inspect}"
      end

      @accept_legacy_ciphertexts = value
    end

    private

    # liboqsのデフォルトパス。
    # bundle install時にext/pqc_rails/extconf.rbが自前でビルドしたliboqsが見つかれば
    # それを優先する(gemを介した自動ビルド、Phase5 Step3のプロトタイプ)。
    # 見つからない場合はOS別の「よくあるインストール場所」を当て推量するが、
    # 本番運用では明示的に liboqs_path を設定することを強く推奨する。
    def default_liboqs_path
      bundled_liboqs_path || os_default_liboqs_path
    end

    # gemのインストールディレクトリ配下、ext/pqc_rails/extconf.rbがビルド後にコピーした
    # 共有ライブラリがあれば、そのパスを返す(gem_dir、Gem::Specification#extension_dirでは
    # ない点に注意。extconf.rbはビルド成果物を自身のカレントディレクトリ=ext/pqc_rails/へ
    # コピーしており、RubyGemsが`make install`経由でextension_dirへ配置する仕組みには
    # 乗せていないため)。gemとしてインストールされていない場合(このリポジトリを直接bundle
    # pathで使う開発時等)はnilを返し、呼び出し元がOS標準パスへフォールバックする。
    def bundled_liboqs_path
      spec = Gem.loaded_specs["pqc_rails"]
      return nil unless spec

      %w[liboqs.dylib liboqs.so].map { |name| File.join(spec.gem_dir, "ext", "pqc_rails", name) }
                                 .find { |path| File.exist?(path) }
    rescue Gem::Exception
      nil
    end

    def os_default_liboqs_path
      case RbConfig::CONFIG["host_os"]
      when /darwin/
        "/usr/local/lib/liboqs.dylib"
      when /linux/
        "/usr/local/lib/liboqs.so"
      else
        raise PqcRails::Error,
              "liboqs_path is not set and no default is known for this OS (#{RbConfig::CONFIG['host_os']}). " \
              "Set PqcRails.configure { |c| c.liboqs_path = '...' } explicitly."
      end
    end
  end

  class << self
    def configuration
      @configuration ||= Configuration.new
    end

    def configure
      yield(configuration)
    end
  end
end