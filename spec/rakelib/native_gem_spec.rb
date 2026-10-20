# frozen_string_literal: true

require_relative "../../rakelib/native_gem"

RSpec.describe PqcRails::NativeGem do
  let(:base) do
    Gem::Specification.new do |spec|
      spec.name = "pqc_rails"
      spec.version = "1.0.0"
      spec.summary = "test"
      spec.authors = ["test"]
      spec.files = %w[lib/pqc_rails.rb ext/pqc_rails/extconf.rb ext/pqc_rails/vendor/liboqs/CMakeLists.txt README.md]
      spec.extensions = ["ext/pqc_rails/extconf.rb"]
    end
  end

  describe ".specification" do
    subject(:spec) do
      described_class.specification(base, platform: "x86_64-linux-gnu", libs: ["lib/pqc_rails/native/liboqs.so"])
    end

    it "指定したプラットフォームのgemにする" do
      expect(spec.platform).to eq(Gem::Platform.new("x86_64-linux-gnu"))
    end

    it "インストール時にliboqsをビルドしない(拡張を持たない)" do
      expect(spec.extensions).to be_empty
    end

    it "liboqsのソースとビルド用のファイル(ext/)を含めず、ビルド済みのliboqsを含める" do
      expect(spec.files).to contain_exactly("lib/pqc_rails.rb", "README.md", "lib/pqc_rails/native/liboqs.so")
    end

    it "元のgemspecを書き換えない" do
      spec
      expect(base.platform).to eq(Gem::Platform::RUBY)
      expect(base.extensions).to eq(["ext/pqc_rails/extconf.rb"])
    end
  end

  describe "PLATFORMS" do
    it "Linuxのglibc・musl(x86_64・arm64)とmacOS arm64" do
      expect(described_class::PLATFORMS).to eq(%w[x86_64-linux-gnu aarch64-linux-gnu x86_64-linux-musl
                                                   aarch64-linux-musl arm64-darwin])
    end
  end

  it "ビルド済みのliboqsが1つでなければ止まる" do
    expect { described_class.specification(base, platform: "arm64-darwin", libs: []) }
      .to raise_error(ArgumentError, /liboqs/)
  end
end
