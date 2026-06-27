# frozen_string_literal: true

module PqcRails
  # 2つのバイト列を [4byte長][本体][4byte長][本体] で1本のバイト列にまとめる、その逆を行う。
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
  end
end
