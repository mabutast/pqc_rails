# frozen_string_literal: true

RSpec.describe PqcRails::ActiveRecord::KeyProvider do
  let(:keypair) { PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair } }

  around do |example|
    original = ENV.fetch(described_class::ENV_VAR, nil)
    original_previous = ENV.fetch(described_class::PREVIOUS_ENV_VAR, nil)
    example.run
  ensure
    ENV[described_class::ENV_VAR] = original
    ENV[described_class::PREVIOUS_ENV_VAR] = original_previous
  end

  describe "#encryption_key" do
    it "ActiveRecord::Encryption::KeyProvider互換(secret/public_tagsを持つ)のキーを返す" do
      ENV[described_class::ENV_VAR] = PqcRails::Session::KeyManager.encode(keypair)

      key = described_class.new.encryption_key

      expect(key.secret.public_key).to eq(keypair.public_key)
      expect(key.secret.secret_key).to eq(keypair.secret_key)
      expect(key.public_tags).to eq({})
    end

    it "環境変数が無い場合はRails.application.credentialsから読む" do
      ENV.delete(described_class::ENV_VAR)
      fake_app = double("Rails.application",
                         credentials: { described_class::CREDENTIALS_KEY => PqcRails::Session::KeyManager.encode(keypair) })
      allow(Rails).to receive(:application).and_return(fake_app)

      key = described_class.new.encryption_key

      expect(key.secret.public_key).to eq(keypair.public_key)
    end

    it "どちらにも鍵が無い場合はMissingKeyErrorを送出する" do
      ENV.delete(described_class::ENV_VAR)
      allow(Rails).to receive(:application).and_return(nil)

      expect { described_class.new.encryption_key }.to raise_error(PqcRails::MissingKeyError, /PQC_RECORD_KEY/)
    end

    it "store_key_referencesが有効な場合、public_tagsに鍵参照(encrypted_data_key_id)が設定される" do
      ENV[described_class::ENV_VAR] = PqcRails::Session::KeyManager.encode(keypair)
      allow(::ActiveRecord::Encryption.config).to receive(:store_key_references).and_return(true)

      key = described_class.new.encryption_key

      expect(key.public_tags.encrypted_data_key_id).to be_a(String)
    end
  end

  describe "#decryption_keys" do
    it "旧鍵が設定されていない場合は現行鍵のみを配列で返す" do
      ENV[described_class::ENV_VAR] = PqcRails::Session::KeyManager.encode(keypair)
      ENV.delete(described_class::PREVIOUS_ENV_VAR)
      provider = described_class.new

      keys = provider.decryption_keys(double("message"))

      expect(keys).to eq([provider.encryption_key])
    end

    it "旧鍵が設定されている場合は現行鍵に続けて旧鍵世代を返す(鍵ローテーション対応)" do
      previous_keypair = PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair }
      ENV[described_class::ENV_VAR] = PqcRails::Session::KeyManager.encode(keypair)
      ENV[described_class::PREVIOUS_ENV_VAR] = PqcRails::Session::KeyManager.encode(previous_keypair)
      provider = described_class.new

      keys = provider.decryption_keys(double("message"))

      expect(keys.size).to eq(2)
      expect(keys[0].secret.public_key).to eq(keypair.public_key)
      expect(keys[1].secret.public_key).to eq(previous_keypair.public_key)
    end
  end
end
