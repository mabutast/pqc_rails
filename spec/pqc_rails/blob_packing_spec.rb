# frozen_string_literal: true

RSpec.describe PqcRails::BlobPacking do
  describe ".pack / .unpack" do
    it "2つのバイト列を1本のバイト列にまとめ、元に戻せる" do
      blob = described_class.pack("classical", "post-quantum")

      expect(described_class.unpack(blob)).to eq(["classical", "post-quantum"])
    end

    it "空文字列を含んでもラウンドトリップできる" do
      blob = described_class.pack("", "secret_key")

      expect(described_class.unpack(blob)).to eq(["", "secret_key"])
    end

    it "バイナリ(非UTF-8)データもラウンドトリップできる" do
      first  = "\x00\x01\xFF" * 10
      second = "\xDE\xAD\xBE\xEF" * 5
      blob = described_class.pack(first, second)

      expect(described_class.unpack(blob)).to eq([first, second])
    end
  end

  describe ".pack_all / .unpack_all" do
    it "任意の個数のバイト列をラウンドトリップできる" do
      blob = described_class.pack_all("public", "secret", "authentication")

      expect(described_class.unpack_all(blob)).to eq(%w[public secret authentication])
    end

    it "2つのバイト列はpackと同じ形になる(既存の鍵を読める)" do
      expect(described_class.pack_all("a", "b")).to eq(described_class.pack("a", "b"))
      expect(described_class.unpack_all(described_class.pack("a", "b"))).to eq(%w[a b])
    end

    it "3つ目以降があっても、unpackは先頭2つだけを返す(0.3.0以前の読み方と同じ)" do
      expect(described_class.unpack(described_class.pack_all("a", "b", "c"))).to eq(%w[a b])
    end
  end
end
