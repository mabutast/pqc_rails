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
  spec.homepage = "https://github.com/mabutast/pqc_rails" # TODO: 実際のリポジトリURLに差し替え
  spec.required_ruby_version = ">= 3.2.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"
  spec.metadata["rubygems_mfa_required"] = "true"

  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ Gemfile .gitignore])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "actionpack", ">= 7.1", "< 9"
  spec.add_dependency "ffi", "~> 1.16"
  spec.add_dependency "railties", ">= 7.1", "< 9"
end