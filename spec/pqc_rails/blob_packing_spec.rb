# frozen_string_literal: true

require "objspace"
require "json"

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

  describe ".unpack_all の不正な入力" do
    let(:blob) { described_class.pack_all("public", "secret", "authentication") }

    it "本体が長さの欄より短い・長さの欄の途中で切れているとArgumentErrorを送出する" do
      [blob[0..-2], blob[0, 4 + 6 + 4 + 3], blob[0, 4 + 6 + 4 + 6 + 2]].each do |bad|
        expect { described_class.unpack_all(bad) }.to raise_error(ArgumentError, /truncated/)
      end
    end

    it "空のバイト列は要素0個として読む" do
      expect(described_class.unpack_all("")).to eq([])
    end
  end

  describe ".unpack の不正な入力" do
    let(:blob) { described_class.pack("classical", "post-quantum") }

    it "nilはArgumentErrorを送出する" do
      expect { described_class.unpack(nil) }.to raise_error(ArgumentError, /must be a String/)
    end

    it "長さの欄が欠けている(空・1バイト・1つ目だけ)とArgumentErrorを送出する" do
      ["", "\x00".b, blob[0, 4], blob[0, 4 + "classical".bytesize]].each do |bad|
        expect { described_class.unpack(bad) }.to raise_error(ArgumentError, /truncated/)
      end
    end

    it "長さの欄より本体が短い(末尾が切れている)とArgumentErrorを送出する" do
      expect { described_class.unpack(blob[0..-2]) }.to raise_error(ArgumentError, /truncated/)
      expect { described_class.unpack(blob[0, 6]) }.to raise_error(ArgumentError, /truncated/)
    end
  end
  # 取り出した値(秘密鍵など)をゼロ埋めした時に、元のバイト列の領域まで消せるように、
  # 元の領域を共有しない独立したコピーとして返す。共有している文字列に書き込むと、
  # 書き込んだ側だけが別の領域へコピーされ、元の領域の秘密鍵は残る。
  describe "取り出した値の独立性" do
    def shared?(string)
      JSON.parse(ObjectSpace.dump(string)).fetch("shared", false)
    end

    let(:secret) { "\xAA".b * 2400 }

    it "unpackの値は、元のバイト列と領域を共有しない" do
      described_class.unpack(described_class.pack("\x01".b * 32, secret)).each do |part|
        expect(shared?(part)).to be(false)
      end
    end

    it "unpack_allの値は、元のバイト列と領域を共有しない" do
      described_class.unpack_all(described_class.pack_all("\x01".b * 1200, secret)).each do |part|
        expect(shared?(part)).to be(false)
      end
    end
  end
end
