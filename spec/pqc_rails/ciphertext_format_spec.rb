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
      expect(described_class.associated_data(algorithm_id: "X25519+ML-KEM-768", key_id: "ab12"))
        .to eq("pqc_rails:v1:X25519+ML-KEM-768:ab12")
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
end
