# frozen_string_literal: true

module PqcRails
  # 2つのバイト列を [4byte長][本体][4byte長][本体] で1本のバイト列にまとめる、その逆を行う。
  # 鍵の保存形式(公開鍵+秘密鍵+認証鍵)のように3つ以上をまとめる場合はpack_all/unpack_allを使う。
  # HybridKemの鍵/ciphertextパック(古典+PQ)と、KeyManagerの鍵シリアライズ(公開鍵+秘密鍵)で
  # 同じ処理が必要になるため共通化している。
  module BlobPacking
    module_function

    def pack(first, second)
      [first.bytesize].pack("N") + first + [second.bytesize].pack("N") + second
    end

    def unpack(blob)
      first_length = blob[0, 4].unpack1("N")
      first = blob[4, first_length]

      second_offset = 4 + first_length
      second_length = blob[second_offset, 4].unpack1("N")
      second = blob[(second_offset + 4), second_length]

      [first, second]
    end

    # 任意の個数のバイト列を [4byte長][本体] の繰り返しでまとめる。2つの場合はpackと同じ形になる。
    def pack_all(*parts)
      parts.map { |part| [part.bytesize].pack("N") + part }.join
    end

    # pack_allの逆。長さの欄が途中で足りなくなった場合は、そこまでに読めた分を返す。
    def unpack_all(blob)
      parts = []
      offset = 0
      while offset + 4 <= blob.bytesize
        length = blob[offset, 4].unpack1("N")
        parts << blob.byteslice(offset + 4, length)
        offset += 4 + length
      end
      parts
    end
  end
end
