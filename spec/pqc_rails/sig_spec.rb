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

    it "署名の最後のバイトが改竄されていてもfalseを返す" do
      described_class.open(alg_name) do |sig|
        keypair   = sig.generate_keypair
        signature = sig.sign(message, keypair.secret_key)

        tampered_signature = signature.dup
        tampered_signature.setbyte(-1, tampered_signature.getbyte(-1) ^ 0x01)

        expect(sig.verify(message, tampered_signature, keypair.public_key)).to be false
      end
    end

    it "signatureがlength_signatureより1バイト短い場合もfalseを返す(例外は発生しない)" do
      described_class.open(alg_name) do |sig|
        keypair   = sig.generate_keypair
        signature = sig.sign(message, keypair.secret_key)

        expect(sig.verify(message, signature.byteslice(0, signature.bytesize - 1), keypair.public_key)).to be false
      end
    end
  end

  describe "空のメッセージ" do
    it "空のメッセージにも署名・検証でき、別のメッセージの署名としては通らない" do
      described_class.open(alg_name) do |sig|
        keypair   = sig.generate_keypair
        signature = sig.sign("", keypair.secret_key)

        expect(sig.verify("", signature, keypair.public_key)).to be true
        expect(sig.verify("x", signature, keypair.public_key)).to be false
      end
    end
  end

  describe "パラメータセットごとの往復" do
    [
      [:ml_dsa_44, { public_key: 1312, secret_key: 2560, signature: 2420 }, "ml_dsa_44は公開鍵1312・秘密鍵2560・署名2420バイトで往復できる"],
      [:ml_dsa_65, { public_key: 1952, secret_key: 4032, signature: 3309 }, "ml_dsa_65は公開鍵1952・秘密鍵4032・署名3309バイトで往復できる"],
      [:ml_dsa_87, { public_key: 2592, secret_key: 4896, signature: 4627 }, "ml_dsa_87は公開鍵2592・秘密鍵4896・署名4627バイトで往復できる"]
    ].each do |name, lengths, description|
      it description do
        described_class.open(name) do |sig|
          keypair   = sig.generate_keypair
          signature = sig.sign(message, keypair.secret_key)

          expect([keypair.public_key.bytesize, keypair.secret_key.bytesize, signature.bytesize])
            .to eq([lengths[:public_key], lengths[:secret_key], lengths[:signature]])
          expect(sig.verify(message, signature, keypair.public_key)).to be true
        end
      end
    end
  end

  describe "入力バリデーション" do
    it "空・1バイト長い・1バイト短いsecret_keyでsignすると、どれもArgumentErrorを送出する" do
      described_class.open(alg_name) do |sig|
        secret_key = sig.generate_keypair.secret_key

        ["", secret_key + "\x00", secret_key.byteslice(0, secret_key.bytesize - 1)].each do |bad|
          expect { sig.sign(message, bad) }.to raise_error(ArgumentError, /secret_key has wrong length/)
        end
      end
    end

    it "空・1バイト長い・1バイト短いpublic_keyでverifyすると、どれもArgumentErrorを送出する" do
      described_class.open(alg_name) do |sig|
        keypair   = sig.generate_keypair
        signature = sig.sign(message, keypair.secret_key)
        public_key = keypair.public_key

        ["", public_key + "\x00", public_key.byteslice(0, public_key.bytesize - 1)].each do |bad|
          expect { sig.verify(message, signature, bad) }.to raise_error(ArgumentError, /public_key has wrong length/)
        end
      end
    end

    it "nilの鍵を渡すとArgumentErrorを送出する(NoMethodErrorにしない)" do
      described_class.open(alg_name) do |sig|
        keypair   = sig.generate_keypair
        signature = sig.sign(message, keypair.secret_key)

        expect { sig.sign(message, nil) }.to raise_error(ArgumentError, /secret_key must be a String/)
        expect { sig.verify(message, signature, nil) }.to raise_error(ArgumentError, /public_key must be a String/)
      end
    end

    it "文字列でない署名(nil・数値)でverifyするとfalseを返す(例外は発生しない)" do
      described_class.open(alg_name) do |sig|
        keypair = sig.generate_keypair

        [nil, 123].each do |bad|
          expect(sig.verify(message, bad, keypair.public_key)).to be(false)
        end
      end
    end

    it "文字列でないメッセージ(nil・数値)でsignすると、ArgumentErrorを送出する" do
      described_class.open(alg_name) do |sig|
        secret_key = sig.generate_keypair.secret_key

        [nil, 123].each do |bad|
          expect { sig.sign(bad, secret_key) }.to raise_error(ArgumentError, /message must be a String/)
        end
      end
    end

    it "文字列でないメッセージ(nil・数値)でverifyすると、ArgumentErrorを送出する" do
      described_class.open(alg_name) do |sig|
        keypair   = sig.generate_keypair
        signature = sig.sign(message, keypair.secret_key)

        [nil, 123].each do |bad|
          expect { sig.verify(bad, signature, keypair.public_key) }.to raise_error(ArgumentError, /message must be a String/)
        end
      end
    end
  end

  describe "#free" do
    it "free後にメソッドを呼ぶとPqcRails::Errorを送出する" do
      sig = described_class.new(alg_name)
      sig.free

      expect { sig.generate_keypair }.to raise_error(PqcRails::Error, /already been freed/)
    end

    it "free後のsign・verifyもPqcRails::Errorを送出する(解放済みのポインタをliboqsに渡さない)" do
      sig = described_class.new(alg_name)
      keypair   = sig.generate_keypair
      signature = sig.sign(message, keypair.secret_key)
      sig.free

      expect { sig.sign(message, keypair.secret_key) }.to raise_error(PqcRails::Error, /already been freed/)
      expect { sig.verify(message, signature, keypair.public_key) }.to raise_error(PqcRails::Error, /already been freed/)
    end

    it "freeを複数回呼んでもエラーにならない" do
      sig = described_class.new(alg_name)
      sig.free

      expect { sig.free }.not_to raise_error
    end
  end

  describe "liboqsが失敗を返した時" do
    let(:sig) { described_class.new(alg_name) }

    after { sig.free }

    it "鍵の生成が失敗したら、PqcRails::Errorを送出する" do
      allow(PqcRails::Ffi::Sig).to receive(:OQS_SIG_keypair).and_return(-1)

      expect { sig.generate_keypair }.to raise_error(PqcRails::Error, /OQS_SIG_keypair failed \(status=-1\)/)
    end

    it "署名が失敗したら、署名を返さずにPqcRails::Errorを送出する" do
      secret_key = sig.generate_keypair.secret_key
      allow(PqcRails::Ffi::Sig).to receive(:OQS_SIG_sign).and_return(-1)

      expect { sig.sign(message, secret_key) }.to raise_error(PqcRails::Error, /OQS_SIG_sign failed \(status=-1\)/)
    end
  end

  describe "署名の長さ" do
    it "liboqsが書いた長さの分だけを署名として返す(最大長のバッファの残りを含めない)" do
      described_class.open(alg_name) do |sig|
        secret_key = sig.generate_keypair.secret_key
        allow(PqcRails::Ffi::Sig).to receive(:OQS_SIG_sign) do |_sig_ptr, signature_ptr, signature_len_ptr, *|
          signature_ptr.put_bytes(0, "\xAB".b * 100)
          signature_len_ptr.write(:size_t, 100)
          0
        end

        expect(sig.sign(message, secret_key)).to eq("\xAB".b * 100)
      end
    end
  end

  describe ".open" do
    it "アルゴリズムの生成が失敗したら、その例外をそのまま伝える(後始末でNoMethodErrorにしない)" do
      expect do
        described_class.open("NOT-A-REAL-SIG") { nil }
      end.to raise_error(PqcRails::Error, /OQS_SIG_new failed/)
    end

    it "ブロックを抜けたら解放する" do
      sig = described_class.open(alg_name) { _1 }

      expect { sig.generate_keypair }.to raise_error(PqcRails::Error, /already been freed/)
    end
  end
end
