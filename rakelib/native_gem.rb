# frozen_string_literal: true

require "rubygems/package"

module PqcRails
  # ビルド済みのliboqsを同梱した、プラットフォーム別のgem(x86_64-linux-gnu等)を作る。
  #
  # ソースのgem(platform: ruby)はインストール時にliboqsをビルドするため、CMakeとCコンパイラが要る。
  # プラットフォーム別のgemはビルド済みのliboqs(lib/pqc_rails/native/)を持ち、拡張のビルドを行わない。
  # liboqsはFFIで読み込むため、Rubyの版ごとのビルドは要らない。
  module NativeGem
    PLATFORMS = %w[x86_64-linux-gnu aarch64-linux-gnu x86_64-linux-musl aarch64-linux-musl arm64-darwin].freeze

    module_function

    # baseのgemspecを複製し、platformのgemにする。libsはgemに入れるビルド済みのliboqs(1つ)。
    def specification(base, platform:, libs:)
      raise ArgumentError, "ビルド済みのliboqsが1つではありません: #{libs.inspect}" unless libs.size == 1

      base.dup.tap do |spec|
        spec.platform = Gem::Platform.new(platform)
        spec.extensions = []
        spec.files = base.files.reject { |file| file.start_with?("ext/") } + libs
      end
    end

    # gemを作り、pkg/に置いてそのパスを返す。
    def build(base, platform:, libs:, out_dir: "pkg")
      spec = specification(base, platform: platform, libs: libs)
      FileUtils.mkdir_p(out_dir)
      file = Gem::Package.build(spec)
      FileUtils.mv(file, out_dir)
      File.join(out_dir, file)
    end
  end
end
