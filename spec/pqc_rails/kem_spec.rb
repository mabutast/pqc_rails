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

    it "シンボルでもアルゴリズムを指定できる(アルゴリズム抽象化レイヤー経由)" do
      kem = described_class.new(:ml_kem_512)
      expect(kem.alg_name).to eq(:ml_kem_512)
      expect(kem.length_public_key).to eq(800)
    ensure
      kem&.free
    end

    it "未知のシンボルを渡すとUnknownAlgorithmErrorを送出する" do
      expect do
        described_class.new(:not_a_real_kem)
      end.to raise_error(PqcRails::Algorithms::UnknownAlgorithmError, /unknown KEM algorithm/)
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

  # ML-KEM(FIPS 203)のdecapsulateは、暗号文を再暗号化して受け取った暗号文と比較し、一致しなければ
  # 例外を出さずに秘密鍵中のzと暗号文から導いた別の共有鍵を返す(暗黙的拒否、FIPS 203 Algorithm 18)。
  # 比較が暗号文の一部しか見ない実装では、細工した暗号文への応答から秘密鍵を復元されうる
  # (例: wolfSSLのML-KEM-1024 AVX2実装が末尾32バイトを比較しなかったCVE-2026-10097)。
  # ここでは各パラメータセットで、先頭・中央・末尾32バイトの各位置を1バイト改変して確かめる。
  describe "改ざんした暗号文のdecapsulate(暗黙的拒否)" do
    %w[ML-KEM-512 ML-KEM-768 ML-KEM-1024].each do |name|
      context name do
        it "どの位置を1バイト改変しても、例外を出さずに元と異なる共有鍵を返す" do
          described_class.open(name) do |kem|
            keypair = kem.generate_keypair
            encap   = kem.encapsulate(keypair.public_key)
            length  = kem.length_ciphertext
            positions = [0, length / 2] + ((length - 32)...length).to_a

            results = positions.map do |position|
              tampered = encap.ciphertext.dup
              tampered.setbyte(position, tampered.getbyte(position) ^ 0x01)
              shared = kem.decapsulate(tampered, keypair.secret_key)

              expect(shared.bytesize).to eq(kem.length_shared_secret), "position #{position}"
              expect(shared).not_to eq(encap.shared_secret), "position #{position}"
              shared
            end

            expect(results.uniq.size).to eq(positions.size)
          end
        end

        it "同じ改ざん暗号文には毎回同じ共有鍵を返す(拒否用の鍵が秘密鍵と暗号文から決まる)" do
          described_class.open(name) do |kem|
            keypair  = kem.generate_keypair
            tampered = kem.encapsulate(keypair.public_key).ciphertext.dup
            tampered.setbyte(tampered.bytesize - 1, tampered.getbyte(tampered.bytesize - 1) ^ 0x01)

            expect(kem.decapsulate(tampered, keypair.secret_key))
              .to eq(kem.decapsulate(tampered, keypair.secret_key))
          end
        end
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