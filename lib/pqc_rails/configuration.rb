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

    def initialize
      @liboqs_path = ENV["LIBOQS_PATH"] || default_liboqs_path
    end

    private

    # OS別のliboqsデフォルトパス。
    # あくまで「よくあるインストール場所」の当て推量であり、
    # 本番運用では明示的に liboqs_path を設定することを強く推奨する。
    def default_liboqs_path
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