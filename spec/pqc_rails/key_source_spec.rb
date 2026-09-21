# frozen_string_literal: true

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
    end
  end

  around do |example|
    original = ENV.fetch(env_var, nil)
    example.run
  ensure
    ENV[env_var] = original
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
