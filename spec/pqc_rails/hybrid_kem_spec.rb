# frozen_string_literal: true

require "objspace"
require "json"

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

    it "暗号文の作成元の認証に使う32バイトの認証鍵を、鍵ペアごとにランダムに生成する" do
      described_class.open(pq_alg_name) do |hybrid|
        first  = hybrid.generate_keypair
        second = hybrid.generate_keypair

        expect(first.authentication_key.bytesize).to eq(32)
        expect(first.authentication_key).not_to eq(second.authentication_key)
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

  describe "対応するパラメータセット" do
    it "ML-KEM-512・768・1024のどれでも、鍵生成・カプセル化・復元が往復する" do
      %i[ml_kem_512 ml_kem_768 ml_kem_1024].each do |alg|
        described_class.open(alg) do |hybrid|
          keypair = hybrid.generate_keypair
          encap = hybrid.encapsulate(keypair.public_key)

          expect(hybrid.decapsulate(encap.ciphertext, keypair.secret_key)).to eq(encap.shared_secret)
        end
      end
    end

    it "別のパラメータセットの暗号文・公開鍵はArgumentErrorを送出する" do
      ciphertext, public_key = described_class.open(:ml_kem_512) do |h|
        other_public_key = h.generate_keypair.public_key
        [h.encapsulate(other_public_key).ciphertext, other_public_key]
      end

      described_class.open(:ml_kem_768) do |hybrid|
        keypair = hybrid.generate_keypair
        expect { hybrid.decapsulate(ciphertext, keypair.secret_key) }.to raise_error(ArgumentError, /wrong length/)
        expect { hybrid.encapsulate(public_key) }.to raise_error(ArgumentError, /wrong length/)
      end
    end

    it "未登録のアルゴリズムはPqcRails::Errorを送出する" do
      expect { described_class.open(:no_such_algorithm) { raise "not reached" } }.to raise_error(PqcRails::Error)
      expect { described_class.open("No-Such-KEM") { raise "not reached" } }.to raise_error(PqcRails::Error)
    end
  end

  describe "共有鍵の導出" do
    it "X25519・ML-KEMの順に連結した共有鍵を、ラベル・曲線・アルゴリズム・両方の暗号文を束ねたinfoでHKDF-SHA256にかける" do
      described_class.open(pq_alg_name) do |hybrid|
        keypair = hybrid.generate_keypair
        encap = hybrid.encapsulate(keypair.public_key)
        classical_ciphertext, pq_ciphertext = PqcRails::BlobPacking.unpack(encap.ciphertext)
        classical_secret_key, pq_secret_key = PqcRails::BlobPacking.unpack(keypair.secret_key)
        classical_shared = PqcRails::DhKem.new("X25519").decapsulate(classical_ciphertext, classical_secret_key)
        pq_kem = PqcRails::Kem.new(pq_alg_name)
        pq_shared = pq_kem.decapsulate(pq_ciphertext, pq_secret_key)
        info = ["pqc_rails-hybrid-kem-v1", "X25519", pq_alg_name.to_s, classical_ciphertext, pq_ciphertext].join("\x00")
        expected = OpenSSL::KDF.hkdf(classical_shared + pq_shared, salt: "", info: info, length: 32, hash: "SHA256")

        expect(encap.shared_secret).to eq(expected)
        expect(hybrid.decapsulate(encap.ciphertext, keypair.secret_key)).to eq(expected)
      ensure
        pq_kem&.free
      end
    end

    it "公開鍵・秘密鍵・暗号文は、X25519・ML-KEMの順に、ML-KEM-512・768・1024のそれぞれで正しい長さに詰める" do
      %i[ml_kem_512 ml_kem_768 ml_kem_1024].each do |alg|
        described_class.open(alg) do |hybrid|
          keypair = hybrid.generate_keypair
          ciphertext = hybrid.encapsulate(keypair.public_key).ciphertext
          pq_kem = PqcRails::Kem.new(alg)

          expect(PqcRails::BlobPacking.unpack(keypair.public_key).map(&:bytesize)).to eq([32, pq_kem.length_public_key])
          expect(PqcRails::BlobPacking.unpack(keypair.secret_key).map(&:bytesize)).to eq([32, pq_kem.length_secret_key])
          expect(PqcRails::BlobPacking.unpack(ciphertext).map(&:bytesize)).to eq([32, pq_kem.length_ciphertext])
        ensure
          pq_kem&.free
        end
      end
    end
  end

  describe ".open" do
    it "ブロックの戻り値を返し、抜けた後はインスタンスを解放する" do
      kept = nil

      expect(described_class.open(pq_alg_name) { |hybrid| (kept = hybrid) && :result }).to eq(:result)
      expect { kept.generate_keypair }.to raise_error(PqcRails::Error, /HybridKem instance has already been freed/)
    end

    it "ブロックで例外が起きても解放し、例外はそのまま伝える" do
      kept = nil

      expect do
        described_class.open(pq_alg_name) do |hybrid|
          kept = hybrid
          raise IOError, "boom"
        end
      end.to raise_error(IOError, "boom")
      expect { kept.generate_keypair }.to raise_error(PqcRails::Error, /HybridKem instance has already been freed/)
    end

    it "インスタンスを作れない時は、作る時の例外をそのまま伝える" do
      allow(PqcRails::Kem).to receive(:new).and_raise(PqcRails::Error, "unsupported")

      expect { described_class.open(pq_alg_name) { raise "not reached" } }
        .to raise_error(PqcRails::Error, "unsupported")
    end
  end

  describe "decapsulateで作る秘密鍵のコピー" do
    it "X25519とML-KEMの秘密鍵に分けたコピーを、使い終わりにゼロで埋め、渡された秘密鍵は壊さない" do
      described_class.open(pq_alg_name) do |hybrid|
        keypair = hybrid.generate_keypair
        classical_secret, pq_secret = PqcRails::BlobPacking.unpack(keypair.secret_key)
        original_secret_key = keypair.secret_key.dup
        wiped = []
        allow(PqcRails::SecretBuffer).to receive(:wipe).and_wrap_original do |original, *strings|
          wiped.concat(strings.compact.map { |string| [string.dup, string] })
          original.call(*strings)
        end

        2.times do
          encap = hybrid.encapsulate(keypair.public_key)
          expect(hybrid.decapsulate(encap.ciphertext, keypair.secret_key)).to eq(encap.shared_secret)
        end

        [classical_secret, pq_secret].each do |secret|
          copies = wiped.select { |(before, _)| before == secret }
          expect(copies.size).to eq(2)
          copies.each { |(_, after)| expect(after).to eq("\x00" * secret.bytesize) }
        end
        expect(keypair.secret_key).to eq(original_secret_key)
      end
    end
  end

  describe "改ざんした暗号文のdecapsulate" do
    def flip_last_byte(bytes)
      bytes.dup.tap { |copy| copy.setbyte(copy.bytesize - 1, copy.getbyte(copy.bytesize - 1) ^ 0x01) }
    end

    it "ML-KEM側の暗号文の末尾を改変すると、例外を出さずに元と異なる共有鍵を返す(暗黙的拒否)" do
      described_class.open(:ml_kem_1024) do |hybrid|
        keypair = hybrid.generate_keypair
        encap   = hybrid.encapsulate(keypair.public_key)
        classical_ciphertext, pq_ciphertext = PqcRails::BlobPacking.unpack(encap.ciphertext)
        tampered = PqcRails::BlobPacking.pack(classical_ciphertext, flip_last_byte(pq_ciphertext))

        shared = hybrid.decapsulate(tampered, keypair.secret_key)

        expect(shared.bytesize).to eq(32)
        expect(shared).not_to eq(encap.shared_secret)
      end
    end

    it "X25519側の暗号文を改変しても、元と異なる共有鍵になる" do
      described_class.open(:ml_kem_1024) do |hybrid|
        keypair = hybrid.generate_keypair
        encap   = hybrid.encapsulate(keypair.public_key)
        classical_ciphertext, pq_ciphertext = PqcRails::BlobPacking.unpack(encap.ciphertext)
        tampered = PqcRails::BlobPacking.pack(flip_last_byte(classical_ciphertext), pq_ciphertext)

        expect(hybrid.decapsulate(tampered, keypair.secret_key)).not_to eq(encap.shared_secret)
      end
    end
  end

  describe "壊れた入力" do
    it "空・nil・長さの欄だけ・古典側だけの公開鍵・暗号文・秘密鍵は、どれもArgumentErrorを送出する" do
      described_class.open(pq_alg_name) do |hybrid|
        keypair = hybrid.generate_keypair
        ciphertext = hybrid.encapsulate(keypair.public_key).ciphertext

        { public_key: keypair.public_key, ciphertext: ciphertext, secret_key: keypair.secret_key }.each do |name, valid|
          [nil, "", "\x00".b, valid[0, 4], valid[0, 36], valid[0..-2]].each do |bad|
            call = lambda do
              case name
              when :public_key then hybrid.encapsulate(bad)
              when :ciphertext then hybrid.decapsulate(bad, keypair.secret_key)
              else hybrid.decapsulate(ciphertext, bad)
              end
            end
            expect(&call).to raise_error(ArgumentError, /truncated|wrong length|must be a String/)
          end
        end
      end
    end

    it "末尾に余分なバイトがある公開鍵・暗号文はArgumentErrorを送出する" do
      described_class.open(pq_alg_name) do |hybrid|
        keypair = hybrid.generate_keypair
        ciphertext = hybrid.encapsulate(keypair.public_key).ciphertext

        expect { hybrid.encapsulate(keypair.public_key + "\x00".b) }.to raise_error(ArgumentError, /trailing/)
        expect { hybrid.decapsulate(ciphertext + "\x00".b, keypair.secret_key) }
          .to raise_error(ArgumentError, /trailing/)
      end
    end

    it "秘密鍵は、末尾に余分なバイトがあっても今までどおり読む" do
      described_class.open(pq_alg_name) do |hybrid|
        keypair = hybrid.generate_keypair
        encap = hybrid.encapsulate(keypair.public_key)

        expect(hybrid.decapsulate(encap.ciphertext, keypair.secret_key + "\x00".b)).to eq(encap.shared_secret)
      end
    end
  end

  describe "#free" do
    it "free後にencapsulateを呼ぶとPqcRails::Errorを送出する" do
      hybrid = described_class.new(pq_alg_name)
      keypair = hybrid.generate_keypair
      hybrid.free

      expect { hybrid.encapsulate(keypair.public_key) }.to raise_error(PqcRails::Error, /HybridKem instance has already been freed/)
    end

    it "free後にgenerate_keypair・decapsulateを呼ぶとPqcRails::Errorを送出する" do
      hybrid = described_class.new(pq_alg_name)
      keypair = hybrid.generate_keypair
      ciphertext = hybrid.encapsulate(keypair.public_key).ciphertext
      hybrid.free

      expect { hybrid.generate_keypair }.to raise_error(PqcRails::Error, /HybridKem instance has already been freed/)
      expect { hybrid.decapsulate(ciphertext, keypair.secret_key) }
        .to raise_error(PqcRails::Error, /HybridKem instance has already been freed/)
    end

    it "freeを複数回呼んでもエラーにならない" do
      hybrid = described_class.new(pq_alg_name)
      hybrid.free

      expect { hybrid.free }.not_to raise_error
    end

    it "freeを複数回呼んでも、ML-KEM側は1回だけ解放する" do
      hybrid = described_class.new(pq_alg_name)
      pq_kem = hybrid.instance_variable_get(:@pq)
      allow(pq_kem).to receive(:free).and_call_original

      2.times { hybrid.free }

      expect(pq_kem).to have_received(:free).once
    end
  end
end
