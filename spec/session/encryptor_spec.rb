# frozen_string_literal: true

RSpec.describe PqcRails::Session::Encryptor do
  let(:keypair) { PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair } }
  let(:encryptor) { described_class.new(keypair, pq_alg_name: :ml_kem_512) }

  describe "#encrypt / #decrypt" do
    it "セッションハッシュをラウンドトリップできる" do
      session = { "user_id" => 42, "_csrf_token" => "abc123" }

      blob = encryptor.encrypt(session)

      expect(encryptor.decrypt(blob)).to eq(session)
    end

    it "暗号化結果はBase64文字列を返す(Cookie値として安全に扱える)" do
      blob = encryptor.encrypt({ "user_id" => 1 })

      expect(blob).to be_a(String)
      expect { Base64.strict_decode64(blob) }.not_to raise_error
    end

    it "空のセッションハッシュも扱える" do
      blob = encryptor.encrypt({})

      expect(encryptor.decrypt(blob)).to eq({})
    end

    it "暗号化するたびに異なるBase64文字列になる(KEMが毎回再ランダム化されるため)" do
      session = { "user_id" => 42 }

      blob_a = encryptor.encrypt(session)
      blob_b = encryptor.encrypt(session)

      expect(blob_a).not_to eq(blob_b)
    end

    it "異なる鍵ペアのEncryptorでは復号できない" do
      other_keypair = PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair }
      other_encryptor = described_class.new(other_keypair, pq_alg_name: :ml_kem_512)

      blob = encryptor.encrypt({ "user_id" => 42 })

      expect { other_encryptor.decrypt(blob) }.to raise_error(OpenSSL::Cipher::CipherError)
    end
  end
end
