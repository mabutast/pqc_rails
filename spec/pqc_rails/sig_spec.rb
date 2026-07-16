# frozen_string_literal: true

RSpec.describe PqcRails::Sig do
  let(:alg_name) { "ML-DSA-44" }
  let(:message) { "Hello, post-quantum world!" }

  describe "#initialize" do
    it "成功時にアルゴリズム名を保持する" do
      sig = described_class.new(alg_name)
      expect(sig.alg_name).to eq(alg_name)
    ensure
      sig&.free
    end

    it "未知のアルゴリズム名を渡すとPqcRails::Errorを送出する" do
      expect do
        described_class.new("NOT-A-REAL-ALGORITHM")
      end.to raise_error(PqcRails::Error, /OQS_SIG_new failed/)
    end

    it "シンボルでもアルゴリズムを指定できる(アルゴリズム抽象化レイヤー経由)" do
      sig = described_class.new(:ml_dsa_44)
      expect(sig.alg_name).to eq(:ml_dsa_44)
      expect(sig.length_public_key).to eq(1312)
    ensure
      sig&.free
    end

    it "未知のシンボルを渡すとUnknownAlgorithmErrorを送出する" do
      expect do
        described_class.new(:not_a_real_sig)
      end.to raise_error(PqcRails::Algorithms::UnknownAlgorithmError, /unknown SIG algorithm/)
    end
  end

  describe "鍵長・署名長の参照" do
    it "ML-DSA-44のNIST仕様値と一致する" do
      described_class.open(alg_name) do |sig|
        expect(sig.length_public_key).to eq(1312)
        expect(sig.length_secret_key).to eq(2560)
        expect(sig.length_signature).to eq(2420)
      end
    end
  end

  describe "#generate_keypair" do
    it "仕様通りの長さの公開鍵・秘密鍵を生成する" do
      described_class.open(alg_name) do |sig|
        keypair = sig.generate_keypair

        expect(keypair.public_key.bytesize).to eq(sig.length_public_key)
        expect(keypair.secret_key.bytesize).to eq(sig.length_secret_key)
      end
    end

    it "呼ぶたびに異なる鍵を生成する(乱数性の素朴な確認)" do
      described_class.open(alg_name) do |sig|
        first  = sig.generate_keypair
        second = sig.generate_keypair

        expect(first.public_key).not_to eq(second.public_key)
      end
    end
  end

  describe "#sign" do
    it "署名のバイト長がlength_signature以下である" do
      described_class.open(alg_name) do |sig|
        keypair   = sig.generate_keypair
        signature = sig.sign(message, keypair.secret_key)

        expect(signature.bytesize).to be <= sig.length_signature
      end
    end

    it "同じメッセージでも署名のたびに異なる署名になりうる(ML-DSAはランダム化署名)" do
      described_class.open(alg_name) do |sig|
        keypair = sig.generate_keypair

        signature_a = sig.sign(message, keypair.secret_key)
        signature_b = sig.sign(message, keypair.secret_key)

        # ML-DSAはランダム化(hedged)署名がデフォルトのため、
        # 同じメッセージ・同じ鍵でも毎回異なる署名になりうる。
        # ただしいずれの署名もverifyは成功する必要がある。
        expect(sig.verify(message, signature_a, keypair.public_key)).to be true
        expect(sig.verify(message, signature_b, keypair.public_key)).to be true
      end
    end
  end

  describe "#verify" do
    it "正しいメッセージ・署名・公開鍵の組み合わせではtrueを返す" do
      described_class.open(alg_name) do |sig|
        keypair   = sig.generate_keypair
        signature = sig.sign(message, keypair.secret_key)

        expect(sig.verify(message, signature, keypair.public_key)).to be true
      end
    end

    it "メッセージが改竄されているとfalseを返す(例外は発生しない)" do
      described_class.open(alg_name) do |sig|
        keypair   = sig.generate_keypair
        signature = sig.sign(message, keypair.secret_key)

        expect do
          expect(sig.verify("Tampered message!", signature, keypair.public_key)).to be false
        end.not_to raise_error
      end
    end

    it "異なる鍵ペアの公開鍵で検証するとfalseを返す" do
      described_class.open(alg_name) do |sig|
        keypair_a = sig.generate_keypair
        keypair_b = sig.generate_keypair
        signature = sig.sign(message, keypair_a.secret_key)

        expect(sig.verify(message, signature, keypair_b.public_key)).to be false
      end
    end

    it "署名のバイト列自体が改竄されているとfalseを返す" do
      described_class.open(alg_name) do |sig|
        keypair   = sig.generate_keypair
        signature = sig.sign(message, keypair.secret_key)

        # 署名の先頭1バイトを反転させて改竄する
        tampered_signature = signature.dup
        tampered_signature.setbyte(0, tampered_signature.getbyte(0) ^ 0xFF)

        expect(sig.verify(message, tampered_signature, keypair.public_key)).to be false
      end
    end

    it "signatureがlength_signatureを超える長さの場合、liboqsに渡す前にfalseを返す(例外は発生しない)" do
      described_class.open(alg_name) do |sig|
        keypair = sig.generate_keypair
        oversized_signature = ("\x00" * (sig.length_signature + 1))

        expect do
          expect(sig.verify(message, oversized_signature, keypair.public_key)).to be false
        end.not_to raise_error
      end
    end

    it "signatureがlength_signatureを超える場合、OQS_SIG_verify自体を呼ばない(pqc_rails自身が事前に弾く)" do
      described_class.open(alg_name) do |sig|
        keypair = sig.generate_keypair
        oversized_signature = ("\x00" * (sig.length_signature + 1))

        expect(PqcRails::Ffi::Sig).not_to receive(:OQS_SIG_verify)

        sig.verify(message, oversized_signature, keypair.public_key)
      end
    end

    it "signatureが空文字列の場合もfalseを返す(例外は発生しない)" do
      described_class.open(alg_name) do |sig|
        keypair = sig.generate_keypair

        expect do
          expect(sig.verify(message, "", keypair.public_key)).to be false
        end.not_to raise_error
      end
    end
  end

  describe "入力バリデーション" do
    it "長さが不正なsecret_keyでsignするとArgumentErrorを送出する" do
      described_class.open(alg_name) do |sig|
        expect do
          sig.sign(message, "too_short")
        end.to raise_error(ArgumentError, /secret_key has wrong length/)
      end
    end

    it "長さが不正なpublic_keyでverifyするとArgumentErrorを送出する" do
      described_class.open(alg_name) do |sig|
        keypair   = sig.generate_keypair
        signature = sig.sign(message, keypair.secret_key)

        expect do
          sig.verify(message, signature, "too_short")
        end.to raise_error(ArgumentError, /public_key has wrong length/)
      end
    end
  end

  describe "#free" do
    it "free後にメソッドを呼ぶとPqcRails::Errorを送出する" do
      sig = described_class.new(alg_name)
      sig.free

      expect { sig.generate_keypair }.to raise_error(PqcRails::Error, /already been freed/)
    end

    it "freeを複数回呼んでもエラーにならない" do
      sig = described_class.new(alg_name)
      sig.free

      expect { sig.free }.not_to raise_error
    end
  end
end
