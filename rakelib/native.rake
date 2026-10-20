# frozen_string_literal: true

require_relative "native_gem"

namespace :native do
  desc "Build liboqs for this machine into lib/pqc_rails/native (run rake vendor:liboqs first)"
  task :liboqs do
    sh "script/build-native-liboqs"
  end

  desc "Package a platform gem with the prebuilt liboqs, e.g. rake native:gem[arm64-darwin]"
  task :gem, [:platform] do |_task, args|
    platform = args[:platform] or abort "プラットフォームを指定してください: #{PqcRails::NativeGem::PLATFORMS.join(', ')}"
    abort "未対応のプラットフォームです: #{platform}" unless PqcRails::NativeGem::PLATFORMS.include?(platform)

    libs = Dir.glob("lib/pqc_rails/native/liboqs.{so,dylib}")
    begin
      puts PqcRails::NativeGem.build(Bundler.load_gemspec("pqc_rails.gemspec"), platform: platform, libs: libs)
    ensure
      # 開発中のこのリポジトリが、別のプラットフォーム向けにビルドしたliboqsを読み込まないように消す
      rm_rf "lib/pqc_rails/native"
    end
  end
end
