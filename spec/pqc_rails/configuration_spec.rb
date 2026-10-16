# frozen_string_literal: true

RSpec.describe PqcRails::Configuration do
  around do |example|
    original = ENV.fetch("LIBOQS_PATH", nil)
    example.run
  ensure
    ENV["LIBOQS_PATH"] = original
  end

  describe "#liboqs_path" do
    it "ENV['LIBOQS_PATH']が設定されていれば最優先で使う" do
      ENV["LIBOQS_PATH"] = "/custom/path/liboqs.dylib"

      expect(described_class.new.liboqs_path).to eq("/custom/path/liboqs.dylib")
    end

    context "ENV未設定で、gemとしてインストールされ、ext/pqc_rails/にビルド済みliboqsがある場合" do
      it "bundle installでビルドされたliboqsを優先して使う" do
        ENV.delete("LIBOQS_PATH")
        fake_spec = instance_double(Gem::Specification, gem_dir: "/fake/gems/pqc_rails-0.1.0")
        allow(Gem).to receive(:loaded_specs).and_return({ "pqc_rails" => fake_spec })
        bundled_path = "/fake/gems/pqc_rails-0.1.0/ext/pqc_rails/liboqs.dylib"
        allow(File).to receive(:exist?).and_call_original
        allow(File).to receive(:exist?).with(bundled_path).and_return(true)

        expect(described_class.new.liboqs_path).to eq(bundled_path)
      end
    end

    context "ENV未設定で、bundle済みliboqsも見つからない場合" do
      before do
        ENV.delete("LIBOQS_PATH")
        allow(Gem).to receive(:loaded_specs).and_return({})
      end

      it "macOSではOS標準パスにフォールバックする" do
        stub_const("RbConfig::CONFIG", RbConfig::CONFIG.merge("host_os" => "darwin24"))

        expect(described_class.new.liboqs_path).to eq("/usr/local/lib/liboqs.dylib")
      end

      it "LinuxではOS標準パスにフォールバックする" do
        stub_const("RbConfig::CONFIG", RbConfig::CONFIG.merge("host_os" => "linux-gnu"))

        expect(described_class.new.liboqs_path).to eq("/usr/local/lib/liboqs.so")
      end

      it "未知のOSではPqcRails::Errorを送出する" do
        stub_const("RbConfig::CONFIG", RbConfig::CONFIG.merge("host_os" => "some-unknown-os"))

        expect { described_class.new }.to raise_error(PqcRails::Error, /no default is known/)
      end
    end

    context "gemとしてインストールされていない場合(開発時のbundle path参照等)" do
      it "Gem.loaded_specsに'pqc_rails'が無ければOS標準パスにフォールバックする" do
        ENV.delete("LIBOQS_PATH")
        allow(Gem).to receive(:loaded_specs).and_return({})
        stub_const("RbConfig::CONFIG", RbConfig::CONFIG.merge("host_os" => "darwin24"))

        expect(described_class.new.liboqs_path).to eq("/usr/local/lib/liboqs.dylib")
      end
    end
  end

  describe "#ciphertext_format" do
    it "既定は:v1(形式バージョン・アルゴリズムID・鍵IDを持つ新形式)" do
      expect(described_class.new.ciphertext_format).to eq(:v1)
    end

    it ":v0(旧形式)を設定できる" do
      config = described_class.new
      config.ciphertext_format = :v0

      expect(config.ciphertext_format).to eq(:v0)
    end

    it "未知の値はArgumentErrorを送出する" do
      expect { described_class.new.ciphertext_format = :v2 }.to raise_error(ArgumentError, /ciphertext_format/)
    end
  end

  describe "#accept_legacy_ciphertexts" do
    it "既定はtrue(旧形式の暗号文も読む)" do
      expect(described_class.new.accept_legacy_ciphertexts).to be(true)
    end

    it "falseを設定できる" do
      config = described_class.new
      config.accept_legacy_ciphertexts = false

      expect(config.accept_legacy_ciphertexts).to be(false)
    end

    it "true/false以外はArgumentErrorを送出する" do
      expect { described_class.new.accept_legacy_ciphertexts = "no" }
        .to raise_error(ArgumentError, /accept_legacy_ciphertexts/)
    end
  end
end
