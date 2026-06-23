# frozen_string_literal: true

RSpec.describe PqcRails::Algorithms do
  describe ".resolve_kem_name" do
    it "シンボルを渡すとliboqsのアルゴリズム名文字列に解決する" do
      expect(described_class.resolve_kem_name(:ml_kem_512)).to eq("ML-KEM-512")
    end

    it "文字列を渡すとそのまま返す(任意のliboqsアルゴリズムを許容する既存の柔軟性を保つ)" do
      expect(described_class.resolve_kem_name("Some-Future-KEM")).to eq("Some-Future-KEM")
    end

    it "未知のシンボルを渡すとUnknownAlgorithmErrorを送出する" do
      expect do
        described_class.resolve_kem_name(:not_a_real_kem)
      end.to raise_error(PqcRails::Algorithms::UnknownAlgorithmError, /unknown KEM algorithm/)
    end
  end

  describe ".resolve_sig_name" do
    it "シンボルを渡すとliboqsのアルゴリズム名文字列に解決する" do
      expect(described_class.resolve_sig_name(:ml_dsa_44)).to eq("ML-DSA-44")
    end

    it "文字列を渡すとそのまま返す" do
      expect(described_class.resolve_sig_name("Some-Future-SIG")).to eq("Some-Future-SIG")
    end

    it "未知のシンボルを渡すとUnknownAlgorithmErrorを送出する" do
      expect do
        described_class.resolve_sig_name(:not_a_real_sig)
      end.to raise_error(PqcRails::Algorithms::UnknownAlgorithmError, /unknown SIG algorithm/)
    end
  end

  describe ".find_kem" do
    it "登録済みKEMアルゴリズムのメタデータを返す" do
      algo = described_class.find_kem(:ml_kem_512)

      expect(algo.name).to eq(:ml_kem_512)
      expect(algo.liboqs_name).to eq("ML-KEM-512")
      expect(algo.family).to eq(:kem)
      expect(algo.security_level).to eq(1)
      expect(algo.status).to eq(:recommended)
    end

    it "未知のシンボルを渡すとUnknownAlgorithmErrorを送出する" do
      expect do
        described_class.find_kem(:not_a_real_kem)
      end.to raise_error(PqcRails::Algorithms::UnknownAlgorithmError, /unknown KEM algorithm/)
    end
  end

  describe ".find_sig" do
    it "登録済みSIGアルゴリズムのメタデータを返す" do
      algo = described_class.find_sig(:ml_dsa_44)

      expect(algo.name).to eq(:ml_dsa_44)
      expect(algo.liboqs_name).to eq("ML-DSA-44")
      expect(algo.family).to eq(:sig)
      expect(algo.security_level).to eq(2)
      expect(algo.status).to eq(:recommended)
    end

    it "未知のシンボルを渡すとUnknownAlgorithmErrorを送出する" do
      expect do
        described_class.find_sig(:not_a_real_sig)
      end.to raise_error(PqcRails::Algorithms::UnknownAlgorithmError, /unknown SIG algorithm/)
    end
  end

  describe "登録済みアルゴリズムの一覧" do
    it "ML-KEMの3つのセキュリティレベルを登録している" do
      expect(described_class::KEMS.keys).to contain_exactly(:ml_kem_512, :ml_kem_768, :ml_kem_1024)
    end

    it "ML-DSAの3つのセキュリティレベルを登録している" do
      expect(described_class::SIGS.keys).to contain_exactly(:ml_dsa_44, :ml_dsa_65, :ml_dsa_87)
    end
  end

  describe "UnknownAlgorithmError" do
    it "PqcRails::Errorのサブクラスである" do
      expect(described_class::UnknownAlgorithmError.ancestors).to include(PqcRails::Error)
    end
  end
end
