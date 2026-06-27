# frozen_string_literal: true

RSpec.describe PqcRails::Session::KeyManager do
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

  describe ".keypair" do
    around do |example|
      original = ENV.fetch(described_class::ENV_VAR, nil)
      example.run
    ensure
      ENV[described_class::ENV_VAR] = original
    end

    it "環境変数PQC_SESSION_KEYが設定されていればそれを使う" do
      ENV[described_class::ENV_VAR] = described_class.encode(keypair)

      expect(described_class.keypair.public_key).to eq(keypair.public_key)
    end

    it "環境変数が無い場合はRails.application.credentialsから読む" do
      ENV.delete(described_class::ENV_VAR)
      fake_app = double("Rails.application", credentials: { pqc_session_key: described_class.encode(keypair) })
      allow(Rails).to receive(:application).and_return(fake_app)

      expect(described_class.keypair.public_key).to eq(keypair.public_key)
    end

    it "環境変数が優先される(両方設定されている場合)" do
      ENV[described_class::ENV_VAR] = described_class.encode(keypair)
      other_keypair = PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair }
      fake_app = double("Rails.application", credentials: { pqc_session_key: described_class.encode(other_keypair) })
      allow(Rails).to receive(:application).and_return(fake_app)

      expect(described_class.keypair.public_key).to eq(keypair.public_key)
    end

    it "どちらにも鍵が無い場合はMissingKeyErrorを送出する" do
      ENV.delete(described_class::ENV_VAR)
      allow(Rails).to receive(:application).and_return(nil)

      expect { described_class.keypair }.to raise_error(PqcRails::Session::MissingKeyError, /PQC_SESSION_KEY/)
    end
  end
end
