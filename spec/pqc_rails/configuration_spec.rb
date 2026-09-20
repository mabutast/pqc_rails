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
end
