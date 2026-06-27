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
end
