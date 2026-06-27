# frozen_string_literal: true

RSpec.describe PqcRails::DhKem do
  describe "#initialize" do
    it "デフォルトでX25519を使う" do
      dh_kem = described_class.new
      expect(dh_kem.curve).to eq("X25519")
    end
  end

  describe "鍵長の参照" do
    it "X25519の仕様通り公開鍵・秘密鍵・暗号文・共有鍵がいずれも32バイト" do
      dh_kem = described_class.new

      expect(dh_kem.length_public_key).to eq(32)
      expect(dh_kem.length_secret_key).to eq(32)
      expect(dh_kem.length_ciphertext).to eq(32)
      expect(dh_kem.length_shared_secret).to eq(32)
    end
  end

  describe "#generate_keypair" do
    it "仕様通りの長さの公開鍵・秘密鍵を生成する" do
      dh_kem = described_class.new
      keypair = dh_kem.generate_keypair

      expect(keypair.public_key.bytesize).to eq(32)
      expect(keypair.secret_key.bytesize).to eq(32)
    end

    it "呼ぶたびに異なる鍵を生成する(乱数性の素朴な確認)" do
      dh_kem = described_class.new

      first  = dh_kem.generate_keypair
      second = dh_kem.generate_keypair

      expect(first.public_key).not_to eq(second.public_key)
    end
  end

  describe "#encapsulate / #decapsulate" do
    it "encapsulateの共有鍵とdecapsulateの共有鍵が一致する(ECDH-as-KEM)" do
      dh_kem = described_class.new
      keypair = dh_kem.generate_keypair

      encap = dh_kem.encapsulate(keypair.public_key)
      shared = dh_kem.decapsulate(encap.ciphertext, keypair.secret_key)

      expect(shared).to eq(encap.shared_secret)
      expect(encap.ciphertext.bytesize).to eq(32)
      expect(encap.shared_secret.bytesize).to eq(32)
    end

    it "encapsulateごとに異なる一時鍵(ciphertext)を使う" do
      dh_kem = described_class.new
      keypair = dh_kem.generate_keypair

      encap_a = dh_kem.encapsulate(keypair.public_key)
      encap_b = dh_kem.encapsulate(keypair.public_key)

      expect(encap_a.ciphertext).not_to eq(encap_b.ciphertext)
      expect(encap_a.shared_secret).not_to eq(encap_b.shared_secret)
    end

    it "異なる鍵ペアのsecret_keyでdecapsulateすると異なる共有鍵になる" do
      dh_kem = described_class.new
      keypair_a = dh_kem.generate_keypair
      keypair_b = dh_kem.generate_keypair

      encap = dh_kem.encapsulate(keypair_a.public_key)
      wrong_shared = dh_kem.decapsulate(encap.ciphertext, keypair_b.secret_key)

      expect(wrong_shared).not_to eq(encap.shared_secret)
    end
  end

  describe "入力バリデーション" do
    it "長さが不正なpublic_keyでencapsulateするとArgumentErrorを送出する" do
      dh_kem = described_class.new

      expect do
        dh_kem.encapsulate("too_short")
      end.to raise_error(ArgumentError, /public_key has wrong length/)
    end

    it "長さが不正なsecret_keyでdecapsulateするとArgumentErrorを送出する" do
      dh_kem = described_class.new

      expect do
        dh_kem.decapsulate("\x00" * 32, "too_short")
      end.to raise_error(ArgumentError, /secret_key has wrong length/)
    end
  end
end
