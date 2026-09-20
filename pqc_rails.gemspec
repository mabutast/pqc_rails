# frozen_string_literal: true

require_relative "lib/pqc_rails/version"

Gem::Specification.new do |spec|
  spec.name = "pqc_rails"
  spec.version = PqcRails::VERSION
  spec.authors = ["mabutast"]
  spec.email = ["contact@rubyquantum.dev"]

  spec.summary = "Post-quantum cryptography (PQC) integration for Ruby on Rails, built on liboqs."
  spec.description = "pqc_rails provides zero-downtime-friendly post-quantum cryptography primitives " \
                      "(NIST-standardized algorithms such as ML-KEM and ML-DSA) for existing Rails " \
                      "applications, via native FFI bindings to liboqs."
  spec.homepage = "https://github.com/mabutast/pqc_rails"
  spec.license = "Nonstandard" # Business Source License 1.1、詳細はLICENSE.txt参照
  spec.required_ruby_version = ">= 3.2.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"
  spec.metadata["rubygems_mfa_required"] = "true"

  gemspec = File.basename(__FILE__)
  tracked_files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ spec/ .github/ Gemfile .gitignore .rspec .pre-commit-config.yaml
                           .gitleaks.toml .secrets.baseline])
    end
  end
  # `rake vendor:liboqs` が取得したliboqsソース(ext/pqc_rails/vendor/)は、サイズが大きいため
  # pqc_rails自身のgit履歴には含めていない(.gitignore参照)。git ls-filesには出てこないため、
  # ここでDir.globにより明示的にgemパッケージへ追加する。リリース前に必ず`rake vendor:liboqs`を
  # 実行しておくこと(release-checklist.html参照)。未実行の場合はこのリストが空になり、
  # 利用者側は`bundle install`時にextconf.rbのgit clone開発フォールバックに頼ることになる。
  # liboqsのCMakeビルドスクリプトはドット始まりのディレクトリ(.CMake/)を含むため、
  # File::FNM_DOTMATCHを付けないとDir.globが黙って取りこぼす(実際に取りこぼしてCMake configureが
  # 失敗する事象を確認済み)。
  vendored_files = Dir.glob("ext/pqc_rails/vendor/**/*", base: __dir__, flags: File::FNM_DOTMATCH)
                       .select { |f| File.file?(File.join(__dir__, f)) }
  spec.files = tracked_files + vendored_files
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]
  spec.extensions = ["ext/pqc_rails/extconf.rb"]

  spec.add_dependency "actionpack", ">= 7.1", "< 9"
  spec.add_dependency "activerecord", ">= 7.1", "< 9"
  spec.add_dependency "ffi", "~> 1.16"
  spec.add_dependency "railties", ">= 7.1", "< 9"
end