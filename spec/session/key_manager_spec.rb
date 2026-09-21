# frozen_string_literal: true

RSpec.describe PqcRails::Session::KeyManager do
  let(:keypair) { PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair } }

  describe ".keypair" do
    around do |example|
      original = ENV.fetch(described_class::ENV_VAR, nil)
      example.run
    ensure
      ENV[described_class::ENV_VAR] = original
    end

    it "環境変数PQC_SESSION_KEYが設定されていればそれを使う" do
      ENV[described_class::ENV_VAR] = PqcRails::KeySource.encode(keypair)

      expect(described_class.keypair.public_key).to eq(keypair.public_key)
    end

    it "環境変数が無い場合はRails.application.credentialsから読む" do
      ENV.delete(described_class::ENV_VAR)
      fake_app = double("Rails.application", credentials: { pqc_session_key: PqcRails::KeySource.encode(keypair) })
      allow(Rails).to receive(:application).and_return(fake_app)

      expect(described_class.keypair.public_key).to eq(keypair.public_key)
    end

    it "環境変数が優先される(両方設定されている場合)" do
      ENV[described_class::ENV_VAR] = PqcRails::KeySource.encode(keypair)
      other_keypair = PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair }
      fake_app = double("Rails.application", credentials: { pqc_session_key: PqcRails::KeySource.encode(other_keypair) })
      allow(Rails).to receive(:application).and_return(fake_app)

      expect(described_class.keypair.public_key).to eq(keypair.public_key)
    end

    it "どちらにも鍵が無い場合はMissingKeyErrorを送出する" do
      ENV.delete(described_class::ENV_VAR)
      allow(Rails).to receive(:application).and_return(nil)

      expect { described_class.keypair }.to raise_error(PqcRails::MissingKeyError, /PQC_SESSION_KEY/)
    end
  end

  describe ".previous_keypairs" do
    around do |example|
      original = ENV.fetch(described_class::PREVIOUS_ENV_VAR, nil)
      example.run
    ensure
      ENV[described_class::PREVIOUS_ENV_VAR] = original
    end

    it "未設定の場合は空配列を返す(ローテーション対象外の既定状態)" do
      ENV.delete(described_class::PREVIOUS_ENV_VAR)
      allow(Rails).to receive(:application).and_return(nil)

      expect(described_class.previous_keypairs).to eq([])
    end

    it "設定されている場合はデコードした旧鍵ペアの配列を返す" do
      ENV[described_class::PREVIOUS_ENV_VAR] = PqcRails::KeySource.encode(keypair)

      keypairs = described_class.previous_keypairs

      expect(keypairs.map(&:public_key)).to eq([keypair.public_key])
    end
  end
end
