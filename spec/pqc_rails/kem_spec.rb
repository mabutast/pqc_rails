# frozen_string_literal: true

RSpec.describe PqcRails::Kem do
  let(:alg_name) { "ML-KEM-512" }

  describe "#initialize" do
    it "成功時にアルゴリズム名を保持する" do
      kem = described_class.new(alg_name)
      expect(kem.alg_name).to eq(alg_name)
    ensure
      kem&.free
    end

    it "未知のアルゴリズム名を渡すとPqcRails::Errorを送出する" do
      expect do
        described_class.new("NOT-A-REAL-ALGORITHM")
      end.to raise_error(PqcRails::Error, /OQS_KEM_new failed/)
    end
  end

  describe "鍵長の参照" do
    it "ML-KEM-512のNIST仕様値と一致する" do
      described_class.open(alg_name) do |kem|
        expect(kem.length_public_key).to eq(800)
        expect(kem.length_secret_key).to eq(1632)
        expect(kem.length_ciphertext).to eq(768)
        expect(kem.length_shared_secret).to eq(32)
      end
    end
  end

  describe "#generate_keypair" do
    it "仕様通りの長さの公開鍵・秘密鍵を生成する" do
      described_class.open(alg_name) do |kem|
        keypair = kem.generate_keypair

        expect(keypair.public_key.bytesize).to eq(kem.length_public_key)
        expect(keypair.secret_key.bytesize).to eq(kem.length_secret_key)
      end
    end

    it "呼ぶたびに異なる鍵を生成する(乱数性の素朴な確認)" do
      described_class.open(alg_name) do |kem|
        first  = kem.generate_keypair
        second = kem.generate_keypair

        expect(first.public_key).not_to eq(second.public_key)
      end
    end
  end

  describe "鍵交換の一巡(encapsulate → decapsulate)" do
    it "送信側と受信側で共有秘密が一致する" do
      described_class.open(alg_name) do |kem|
        keypair = kem.generate_keypair
        encap   = kem.encapsulate(keypair.public_key)
        decapped_secret = kem.decapsulate(encap.ciphertext, keypair.secret_key)

        expect(decapped_secret).to eq(encap.shared_secret)
      end
    end

    it "誤った秘密鍵でdecapsulateすると別の共有秘密になる(改竄検知の素朴な確認)" do
      described_class.open(alg_name) do |kem|
        keypair_a = kem.generate_keypair
        keypair_b = kem.generate_keypair

        encap = kem.encapsulate(keypair_a.public_key)
        wrong_secret = kem.decapsulate(encap.ciphertext, keypair_b.secret_key)

        expect(wrong_secret).not_to eq(encap.shared_secret)
      end
    end
  end

  describe "入力バリデーション" do
    it "長さが不正なpublic_keyを渡すとArgumentErrorを送出する" do
      described_class.open(alg_name) do |kem|
        expect do
          kem.encapsulate("too_short")
        end.to raise_error(ArgumentError, /public_key has wrong length/)
      end
    end

    it "長さが不正なciphertextを渡すとArgumentErrorを送出する" do
      described_class.open(alg_name) do |kem|
        keypair = kem.generate_keypair

        expect do
          kem.decapsulate("too_short", keypair.secret_key)
        end.to raise_error(ArgumentError, /ciphertext has wrong length/)
      end
    end
  end

  describe "#free" do
    it "free後にメソッドを呼ぶとPqcRails::Errorを送出する" do
      kem = described_class.new(alg_name)
      kem.free

      expect { kem.generate_keypair }.to raise_error(PqcRails::Error, /already been freed/)
    end

    it "freeを複数回呼んでもエラーにならない" do
      kem = described_class.new(alg_name)
      kem.free

      expect { kem.free }.not_to raise_error
    end
  end
end