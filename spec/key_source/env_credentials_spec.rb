# frozen_string_literal: true

RSpec.describe PqcRails::KeySource::EnvCredentials do
  let(:keypair) { PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair } }
  let(:previous_keypair) { PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair } }
  let(:another_previous_keypair) { PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair } }

  subject(:source) do
    described_class.new(
      env_var: "PQC_TEST_KEY",
      previous_env_var: "PQC_TEST_PREVIOUS_KEYS",
      credentials_key: :pqc_test_key,
      previous_credentials_key: :pqc_test_previous_keys,
      label: "test"
    )
  end

  around do |example|
    original = ENV.fetch("PQC_TEST_KEY", nil)
    original_previous = ENV.fetch("PQC_TEST_PREVIOUS_KEYS", nil)
    example.run
  ensure
    ENV["PQC_TEST_KEY"] = original
    ENV["PQC_TEST_PREVIOUS_KEYS"] = original_previous
  end

  describe "#current_keypair" do
    it "環境変数からデコードした鍵ペアを返す" do
      ENV["PQC_TEST_KEY"] = PqcRails::KeySource.encode(keypair)

      expect(source.current_keypair.public_key).to eq(keypair.public_key)
    end

    it "環境変数が無い場合はRails.application.credentialsから読む" do
      ENV.delete("PQC_TEST_KEY")
      fake_app = double("Rails.application", credentials: { pqc_test_key: PqcRails::KeySource.encode(keypair) })
      allow(Rails).to receive(:application).and_return(fake_app)

      expect(source.current_keypair.public_key).to eq(keypair.public_key)
    end

    it "どちらにも鍵が無い場合はMissingKeyErrorを送出する" do
      ENV.delete("PQC_TEST_KEY")
      allow(Rails).to receive(:application).and_return(nil)

      expect { source.current_keypair }.to raise_error(PqcRails::MissingKeyError, /PQC_TEST_KEY/)
    end
  end

  describe "#previous_keypairs" do
    it "未設定の場合は空配列を返す(ローテーション対象外の既定状態)" do
      ENV.delete("PQC_TEST_PREVIOUS_KEYS")
      allow(Rails).to receive(:application).and_return(nil)

      expect(source.previous_keypairs).to eq([])
    end

    it "環境変数がカンマ区切りの場合、それぞれデコードした鍵ペアの配列を返す" do
      encoded = [previous_keypair, another_previous_keypair].map { |kp| PqcRails::KeySource.encode(kp) }.join(",")
      ENV["PQC_TEST_PREVIOUS_KEYS"] = encoded

      keypairs = source.previous_keypairs

      expect(keypairs.map(&:public_key)).to eq([previous_keypair.public_key, another_previous_keypair.public_key])
    end

    it "credentialsが配列の場合、それぞれデコードした鍵ペアの配列を返す" do
      ENV.delete("PQC_TEST_PREVIOUS_KEYS")
      encoded = [previous_keypair, another_previous_keypair].map { |kp| PqcRails::KeySource.encode(kp) }
      fake_app = double("Rails.application", credentials: { pqc_test_previous_keys: encoded })
      allow(Rails).to receive(:application).and_return(fake_app)

      keypairs = source.previous_keypairs

      expect(keypairs.map(&:public_key)).to eq([previous_keypair.public_key, another_previous_keypair.public_key])
    end

    it "世代数に上限は無い(3世代以上でもそのまま返す)" do
      third_previous_keypair = PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair }
      encoded = [previous_keypair, another_previous_keypair, third_previous_keypair]
                .map { |kp| PqcRails::KeySource.encode(kp) }.join(",")
      ENV["PQC_TEST_PREVIOUS_KEYS"] = encoded

      expect(source.previous_keypairs.size).to eq(3)
    end
  end
end
