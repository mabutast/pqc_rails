# frozen_string_literal: true

RSpec.describe PqcRails::EnvelopeCipher do
  let(:key)       { OpenSSL::Random.random_bytes(32) }
  let(:plaintext) { "Hello, post-quantum world!" }

  describe "#initialize" do
    it "32バイト以外の鍵を渡すとArgumentErrorを送出する" do
      expect do
        described_class.new("too_short")
      end.to raise_error(ArgumentError, /key has wrong length/)
    end
  end

  describe "#encrypt / #decrypt" do
    it "暗号化した結果を復号すると元の平文に戻る" do
      cipher = described_class.new(key)

      encrypted = cipher.encrypt(plaintext)
      decrypted = cipher.decrypt(encrypted)

      expect(decrypted).to eq(plaintext)
    end

    it "暗号化のたびに異なるIVを使うため暗号文も毎回変わる" do
      cipher = described_class.new(key)

      encrypted_a = cipher.encrypt(plaintext)
      encrypted_b = cipher.encrypt(plaintext)

      expect(encrypted_a).not_to eq(encrypted_b)
    end

    it "associated_dataを指定して暗号化・復号できる" do
      cipher = described_class.new(key)
      aad = "record-id:42"

      encrypted = cipher.encrypt(plaintext, associated_data: aad)
      decrypted = cipher.decrypt(encrypted, associated_data: aad)

      expect(decrypted).to eq(plaintext)
    end

    it "associated_dataが復号時に異なるとOpenSSL::Cipher::CipherErrorを送出する" do
      cipher = described_class.new(key)
      encrypted = cipher.encrypt(plaintext, associated_data: "record-id:42")

      expect do
        cipher.decrypt(encrypted, associated_data: "record-id:43")
      end.to raise_error(OpenSSL::Cipher::CipherError)
    end

    it "異なる鍵で復号するとOpenSSL::Cipher::CipherErrorを送出する" do
      cipher_a = described_class.new(key)
      cipher_b = described_class.new(OpenSSL::Random.random_bytes(32))
      encrypted = cipher_a.encrypt(plaintext)

      expect do
        cipher_b.decrypt(encrypted)
      end.to raise_error(OpenSSL::Cipher::CipherError)
    end

    it "暗号文が改竄されているとOpenSSL::Cipher::CipherErrorを送出する(認証付き暗号)" do
      cipher = described_class.new(key)
      encrypted = cipher.encrypt(plaintext)

      tampered = encrypted.dup
      tampered.setbyte(tampered.bytesize - 1, tampered.getbyte(tampered.bytesize - 1) ^ 0xFF)

      expect do
        cipher.decrypt(tampered)
      end.to raise_error(OpenSSL::Cipher::CipherError)
    end
  end
end
