# frozen_string_literal: true

require "objspace"
require "json"

RSpec.describe PqcRails::KeySource do
  let(:env_var) { "PQC_TEST_KEY_SOURCE" }
  let(:credentials_key) { :pqc_test_key_source }
  let(:keypair) { PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair } }

  describe ".encode / .decode" do
    it "Keypairを文字列にエンコードし、デコードすると元の鍵ペアに戻る" do
      encoded = described_class.encode(keypair)

      expect(encoded).to be_a(String)
      decoded = described_class.decode(encoded)
      expect(decoded.public_key).to eq(keypair.public_key)
      expect(decoded.secret_key).to eq(keypair.secret_key)
      expect(decoded.authentication_key).to eq(keypair.authentication_key)
    end

    it "認証鍵を持たない0.3.0以前の形式の鍵は、authentication_keyがnilの鍵ペアとして読む" do
      legacy = Base64.strict_encode64(PqcRails::BlobPacking.pack(keypair.public_key, keypair.secret_key))

      decoded = described_class.decode(legacy)
      expect(decoded.public_key).to eq(keypair.public_key)
      expect(decoded.authentication_key).to be_nil
    end
  end

  around do |example|
    original = ENV.fetch(env_var, nil)
    example.run
  ensure
    ENV[env_var] = original
  end

  describe ".decode の途中のバイト列" do
    it "Base64から戻した鍵の値(公開鍵・秘密鍵・認証鍵を連結したもの)を、取り出した後にゼロで埋める" do
      raw = PqcRails::BlobPacking.pack_all(keypair.public_key, keypair.secret_key, keypair.authentication_key)
      wiped = []
      shared = []
      allow(PqcRails::SecretBuffer).to receive(:wipe).and_wrap_original do |original, *strings|
        strings.compact.each { |string| shared << JSON.parse(ObjectSpace.dump(string)).fetch("shared", false) }
        wiped.concat(strings.compact.map { |string| [string, string.dup] })
        original.call(*strings)
      end

      decoded = described_class.decode(described_class.encode(keypair))

      before, after = wiped.find { |(_, copy)| copy == raw }&.then { |string, copy| [copy, string] }
      expect(before).to eq(raw)
      expect(after).to eq("\x00" * raw.bytesize)
      # 共有の状態の文字列に書き込むと、元の領域ではなく新しいコピーが消されるため
      expect(shared).to all(be(false))
      expect(decoded.secret_key).to eq(keypair.secret_key)
    end
  end

  describe ".fetch" do
    it "環境変数が設定されていればそれを返す" do
      ENV[env_var] = "from-env"

      expect(described_class.fetch(env_var: env_var, credentials_key: credentials_key)).to eq("from-env")
    end

    it "環境変数が無い場合はRails.application.credentialsから読む" do
      ENV.delete(env_var)
      fake_app = double("Rails.application", credentials: { credentials_key => "from-credentials" })
      allow(Rails).to receive(:application).and_return(fake_app)

      expect(described_class.fetch(env_var: env_var, credentials_key: credentials_key)).to eq("from-credentials")
    end

    it "環境変数が優先される" do
      ENV[env_var] = "from-env"
      fake_app = double("Rails.application", credentials: { credentials_key => "from-credentials" })
      allow(Rails).to receive(:application).and_return(fake_app)

      expect(described_class.fetch(env_var: env_var, credentials_key: credentials_key)).to eq("from-env")
    end

    it "どちらにも値が無い場合はnilを返す" do
      ENV.delete(env_var)
      allow(Rails).to receive(:application).and_return(nil)

      expect(described_class.fetch(env_var: env_var, credentials_key: credentials_key)).to be_nil
    end
  end
end
