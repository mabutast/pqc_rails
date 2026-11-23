# frozen_string_literal: true

RSpec.describe PqcRails::CiphertextFormat do
  describe ".algorithm_id" do
    it "古典側の曲線とliboqs名を+でつないだ文字列を返す" do
      expect(described_class.algorithm_id(:ml_kem_768)).to eq("X25519+ML-KEM-768")
    end

    it "liboqsの生の名前もそのまま使える" do
      expect(described_class.algorithm_id("ML-KEM-1024")).to eq("X25519+ML-KEM-1024")
    end
  end

  describe ".pq_alg_name_for" do
    it "レジストリに登録されたアルゴリズムのIDから、レジストリのシンボルを返す" do
      expect(described_class.pq_alg_name_for("X25519+ML-KEM-1024", configured: :ml_kem_768)).to eq(:ml_kem_1024)
    end

    it "レジストリ未登録でも、設定で指定したアルゴリズムと同じなら受け付ける" do
      expect(described_class.pq_alg_name_for("X25519+HQC-1", configured: "HQC-1")).to eq("HQC-1")
    end

    it "レジストリ未登録で設定とも異なるアルゴリズムは拒否する(暗号文側の値だけで任意のアルゴリズムを使わせない)" do
      expect do
        described_class.pq_alg_name_for("X25519+HQC-1", configured: :ml_kem_768)
      end.to raise_error(PqcRails::CiphertextFormat::UnsupportedAlgorithmError)
    end

    it "X25519以外の古典側の曲線は拒否する" do
      expect do
        described_class.pq_alg_name_for("P-256+ML-KEM-768", configured: :ml_kem_768)
      end.to raise_error(PqcRails::CiphertextFormat::UnsupportedAlgorithmError)
    end

    it "形の崩れたIDは拒否する" do
      expect do
        described_class.pq_alg_name_for("ML-KEM-768", configured: :ml_kem_768)
      end.to raise_error(PqcRails::CiphertextFormat::UnsupportedAlgorithmError)
    end

    it "PQ側の名前が空のIDは、設定のアルゴリズム名が空文字でも拒否する" do
      expect do
        described_class.pq_alg_name_for("X25519+", configured: "")
      end.to raise_error(PqcRails::CiphertextFormat::UnsupportedAlgorithmError)
    end
  end

  describe ".canonical_pq_alg_name" do
    it "レジストリに登録されたアルゴリズムは、liboqs名で指定してもシンボルに揃える" do
      expect(described_class.canonical_pq_alg_name("ML-KEM-768")).to eq(:ml_kem_768)
      expect(described_class.canonical_pq_alg_name(:ml_kem_768)).to eq(:ml_kem_768)
    end

    it "レジストリ未登録のアルゴリズムはliboqs名のまま返す" do
      expect(described_class.canonical_pq_alg_name("HQC-1")).to eq("HQC-1")
    end
  end

  describe ".key_id" do
    it "公開鍵のSHA-1の先頭2バイトを16進4文字で返す(ActiveRecord::KeyProvider::Key#idと同じ値)" do
      public_key = "public-key-bytes"

      expect(described_class.key_id(public_key)).to eq(Digest::SHA1.hexdigest(public_key)[0, 4])
    end
  end

  describe ".associated_data" do
    it "形式バージョン・アルゴリズムID・鍵IDを1本の文字列にまとめる" do
      expect(described_class.associated_data(algorithm_id: "X25519+ML-KEM-768", key_id: "ab12", purpose: :record))
        .to eq("pqc_rails:v1:record:X25519+ML-KEM-768:ab12")
    end

    it "用途が違えば異なる値になる" do
      values = %i[record session].map do |purpose|
        described_class.associated_data(algorithm_id: "X25519+ML-KEM-768", key_id: "ab12", purpose: purpose)
      end

      expect(values.uniq.size).to eq(2)
    end

    it "未知の用途はArgumentErrorを送出する" do
      [:foo, nil, "record"].each do |purpose|
        expect { described_class.associated_data(algorithm_id: "a", key_id: "b", purpose: purpose) }
          .to raise_error(ArgumentError, /purpose/)
      end
    end
  end

  describe ".data_key" do
    let(:shared_secret) { "\x01" * 32 }
    let(:authentication_key) { "\x02" * 32 }

    it "KEMの共有鍵と認証鍵から32バイトのAES鍵を導く" do
      expect(described_class.data_key(shared_secret, authentication_key, purpose: :record).bytesize).to eq(32)
    end

    it "KEMの共有鍵そのものとは異なる(共有鍵だけではAES鍵を作れない)" do
      expect(described_class.data_key(shared_secret, authentication_key, purpose: :record)).not_to eq(shared_secret)
    end

    it "認証鍵が異なれば、同じ共有鍵からでも異なるAES鍵になる" do
      expect(described_class.data_key(shared_secret, authentication_key, purpose: :record))
        .not_to eq(described_class.data_key(shared_secret, "\x03" * 32, purpose: :record))
    end

    it "認証鍵が無い鍵ペアではPqcRails::MissingAuthenticationKeyErrorを送出する" do
      expect { described_class.data_key(shared_secret, nil, purpose: :record) }
        .to raise_error(PqcRails::MissingAuthenticationKeyError, /authentication key/)
    end

    it "用途が違えば、同じ共有鍵と認証鍵からでも異なるAES鍵になる" do
      expect(described_class.data_key(shared_secret, authentication_key, purpose: :record))
        .not_to eq(described_class.data_key(shared_secret, authentication_key, purpose: :session))
    end

    it "未知の用途はArgumentErrorを送出する" do
      [:foo, nil, "record"].each do |purpose|
        expect { described_class.data_key(shared_secret, authentication_key, purpose: purpose) }
          .to raise_error(ArgumentError, /purpose/)
      end
    end

    it "UTF-8と判定された32バイトの認証鍵でも、BINARYと同じAES鍵を導き、引数を書き換えない" do
      bytes = "\xE3\x81\x82".b * 10 + "ab".b
      utf8 = bytes.dup.force_encoding(Encoding::UTF_8)
      secret = "\xFF".b * 32

      expect(described_class.data_key(secret, utf8, purpose: :record))
        .to eq(described_class.data_key(secret, bytes, purpose: :record))
      expect(utf8.b).to eq(bytes)
      expect(secret).to eq("\xFF".b * 32)
    end

    it "鍵導出の途中のコピーをゼロで埋める" do
      wiped = []
      allow(PqcRails::SecretBuffer).to receive(:wipe).and_wrap_original do |original, *strings|
        original.call(*strings)
        wiped.concat(strings)
      end

      described_class.data_key(shared_secret, authentication_key, purpose: :record)

      expect(wiped.map(&:bytesize)).to contain_exactly(64, 32, 32)
      expect(wiped.join.bytes).to all(eq(0))
      expect(shared_secret).to eq("\x01" * 32)
      expect(authentication_key).to eq("\x02" * 32)
    end

    it "32バイトの文字列でない認証鍵はPqcRails::Errorを送出する" do
      ["", "\x02" * 31, "\x02" * 33, "\x02" * 64, 123, :key, Array.new(32, 2)].each do |bad|
        expect { described_class.data_key(shared_secret, bad, purpose: :record) }.to raise_error(PqcRails::Error) do |error|
          expect(error).not_to be_a(PqcRails::MissingAuthenticationKeyError)
        end
      end
    end
  end

  describe ".write_legacy?" do
    around do |example|
      original = PqcRails.configuration.ciphertext_format
      example.run
    ensure
      PqcRails.configuration.ciphertext_format = original
    end

    it "既定では新形式で書く" do
      expect(described_class.write_legacy?).to be(false)
    end

    it "ciphertext_format = :v0 のときは旧形式で書く" do
      PqcRails.configuration.ciphertext_format = :v0

      expect(described_class.write_legacy?).to be(true)
    end
  end

  describe ".ensure_legacy_cookie_accepted!" do
    let(:deadline) { Time.utc(2026, 12, 1) }
    let(:legacy_key) { PqcRails::HybridKem::Keypair.new("public", "secret") }
    let(:current_key) { PqcRails::HybridKem::Keypair.new("public", "secret", "a" * 32) }

    around do |example|
      original = PqcRails.configuration.accept_legacy_cookies_until
      PqcRails.configuration.accept_legacy_cookies_until = deadline
      example.run
    ensure
      PqcRails.configuration.accept_legacy_cookies_until = original
    end

    it "期限ちょうどの時刻は、まだ旧形式のCookieを受け付ける" do
      expect { described_class.ensure_legacy_cookie_accepted!(legacy_key, now: deadline) }.not_to raise_error
    end

    it "期限を1秒でも過ぎたら、旧形式のCookieを拒否する" do
      expect do
        described_class.ensure_legacy_cookie_accepted!(legacy_key, now: deadline + 1)
      end.to raise_error(PqcRails::Error, /legacy/)
    end

    it "旧形式で書く設定の間は、期限を過ぎても0.3.0の鍵では受け付ける" do
      PqcRails.configuration.ciphertext_format = :v0

      expect { described_class.ensure_legacy_cookie_accepted!(legacy_key, now: deadline + 1) }.not_to raise_error
    ensure
      PqcRails.configuration.ciphertext_format = :v1
    end

    it "認証鍵を持つ鍵は、期限内でも旧形式で書く設定でも拒否する" do
      expect { described_class.ensure_legacy_cookie_accepted!(current_key, now: deadline) }
        .to raise_error(PqcRails::Error, /authentication key/)
      PqcRails.configuration.ciphertext_format = :v0
      expect { described_class.ensure_legacy_cookie_accepted!(current_key, now: deadline) }
        .to raise_error(PqcRails::Error, /authentication key/)
    ensure
      PqcRails.configuration.ciphertext_format = :v1
    end

    context "期限が未設定のとき" do
      let(:deadline) { nil }

      it "DBと同じ鍵は、旧形式で書く設定でも拒否する" do
        PqcRails.configuration.ciphertext_format = :v0

        expect { described_class.ensure_legacy_cookie_accepted!(legacy_key, shared_with_records: true) }
          .to raise_error(PqcRails::Error, /records/)
      ensure
        PqcRails.configuration.ciphertext_format = :v1
      end

      it "新形式で書く設定では、旧形式のCookieを拒否する" do
        expect { described_class.ensure_legacy_cookie_accepted!(legacy_key) }.to raise_error(PqcRails::Error, /legacy/)
      end

      it "旧形式で書く設定(順番デプロイ中)では、旧形式のCookieを受け付ける" do
        PqcRails.configuration.ciphertext_format = :v0

        expect { described_class.ensure_legacy_cookie_accepted!(legacy_key) }.not_to raise_error
      ensure
        PqcRails.configuration.ciphertext_format = :v1
      end
    end
  end
end
