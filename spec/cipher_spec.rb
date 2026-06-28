# frozen_string_literal: true

require "active_record"

RSpec.describe PqcRails::Cipher do
  let(:keypair) { PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair } }
  let(:cipher)  { described_class.new(pq_alg_name: :ml_kem_512) }

  describe "#encrypt" do
    it "ActiveRecord::Encryption::Messageを返し、KEMのciphertextをheadersに持つ" do
      message = cipher.encrypt("hello", key: keypair)

      expect(message).to be_a(ActiveRecord::Encryption::Message)
      expect(message.payload).to be_a(String)
      expect(message.headers[:kem_ct]).to be_a(String)
    end

    it "deterministic: trueを渡すとArgumentErrorを送出する(KEMはランダム化されるためサポートしない)" do
      expect do
        cipher.encrypt("hello", key: keypair, deterministic: true)
      end.to raise_error(ArgumentError, /deterministic/)
    end
  end

  describe "#encrypt / #decrypt" do
    it "ラウンドトリップできる" do
      message = cipher.encrypt("hello pqc", key: keypair)

      expect(cipher.decrypt(message, key: keypair)).to eq("hello pqc")
    end

    it "Railsのkey:インターフェースに準拠し、keyが配列でも復号できる(鍵ローテーション互換)" do
      other_keypair = PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair }
      message = cipher.encrypt("hello pqc", key: keypair)

      expect(cipher.decrypt(message, key: [other_keypair, keypair])).to eq("hello pqc")
    end

    it "異なる鍵では復号できず、ActiveRecord::Encryption::Errors::Decryptionを送出する" do
      other_keypair = PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair }
      message = cipher.encrypt("hello pqc", key: keypair)

      expect do
        cipher.decrypt(message, key: other_keypair)
      end.to raise_error(ActiveRecord::Encryption::Errors::Decryption)
    end
  end
end
