# frozen_string_literal: true

RSpec.describe PqcRails::HybridKem do
  let(:pq_alg_name) { :ml_kem_512 }

  describe "#initialize" do
    it "PQアルゴリズムと古典曲線(デフォルトX25519)を保持する" do
      described_class.open(pq_alg_name) do |hybrid|
        expect(hybrid.pq_alg_name).to eq(pq_alg_name)
        expect(hybrid.classical_curve).to eq("X25519")
      end
    end
  end

  describe "#generate_keypair" do
    it "公開鍵・秘密鍵をバイト列(古典+PQをパックしたblob)として返す" do
      described_class.open(pq_alg_name) do |hybrid|
        keypair = hybrid.generate_keypair

        expect(keypair.public_key).to be_a(String)
        expect(keypair.secret_key).to be_a(String)
      end
    end

    it "呼ぶたびに異なる鍵を生成する" do
      described_class.open(pq_alg_name) do |hybrid|
        first  = hybrid.generate_keypair
        second = hybrid.generate_keypair

        expect(first.public_key).not_to eq(second.public_key)
      end
    end
  end

  describe "#encapsulate / #decapsulate" do
    it "encapsulateとdecapsulateで同じ32バイトの共有鍵が導出される" do
      described_class.open(pq_alg_name) do |hybrid|
        keypair = hybrid.generate_keypair

        encap  = hybrid.encapsulate(keypair.public_key)
        shared = hybrid.decapsulate(encap.ciphertext, keypair.secret_key)

        expect(shared).to eq(encap.shared_secret)
        expect(shared.bytesize).to eq(32)
      end
    end

    it "encapsulateごとに異なる共有鍵になる(古典側が毎回一時鍵を使うため)" do
      described_class.open(pq_alg_name) do |hybrid|
        keypair = hybrid.generate_keypair

        encap_a = hybrid.encapsulate(keypair.public_key)
        encap_b = hybrid.encapsulate(keypair.public_key)

        expect(encap_a.shared_secret).not_to eq(encap_b.shared_secret)
      end
    end

    it "異なる鍵ペアのsecret_keyでdecapsulateすると異なる共有鍵になる" do
      described_class.open(pq_alg_name) do |hybrid|
        keypair_a = hybrid.generate_keypair
        keypair_b = hybrid.generate_keypair

        encap = hybrid.encapsulate(keypair_a.public_key)
        wrong_shared = hybrid.decapsulate(encap.ciphertext, keypair_b.secret_key)

        expect(wrong_shared).not_to eq(encap.shared_secret)
      end
    end

    it "導出した共有鍵をEnvelopeCipherにそのまま渡してデータを暗号化・復号できる" do
      described_class.open(pq_alg_name) do |hybrid|
        keypair = hybrid.generate_keypair
        encap   = hybrid.encapsulate(keypair.public_key)
        shared  = hybrid.decapsulate(encap.ciphertext, keypair.secret_key)

        cipher    = PqcRails::EnvelopeCipher.new(encap.shared_secret)
        encrypted = cipher.encrypt("secret payload")

        decipher = PqcRails::EnvelopeCipher.new(shared)
        expect(decipher.decrypt(encrypted)).to eq("secret payload")
      end
    end
  end

  describe "#free" do
    it "free後にencapsulateを呼ぶとPqcRails::Errorを送出する" do
      hybrid = described_class.new(pq_alg_name)
      keypair = hybrid.generate_keypair
      hybrid.free

      expect { hybrid.encapsulate(keypair.public_key) }.to raise_error(PqcRails::Error, /already been freed/)
    end

    it "freeを複数回呼んでもエラーにならない" do
      hybrid = described_class.new(pq_alg_name)
      hybrid.free

      expect { hybrid.free }.not_to raise_error
    end
  end
end
