# frozen_string_literal: true

module PqcRails
  # 2つのバイト列を [4byte長][本体][4byte長][本体] で1本のバイト列にまとめる、その逆を行う。
  # 鍵の保存形式(公開鍵+秘密鍵+認証鍵)のように3つ以上をまとめる場合はpack_all/unpack_allを使う。
  # HybridKemの鍵/ciphertextパック(古典+PQ)と、KeyManagerの鍵シリアライズ(公開鍵+秘密鍵)で
  # 同じ処理が必要になるため共通化している。
  #
  # 取り出した値は、元のバイト列と領域を共有しない独立したコピーにする。秘密鍵を取り出した後に
  # SecretBuffer.wipeでゼロ埋めした時、元のバイト列の領域まで残さず消せるようにするため。
  module BlobPacking
    module_function

    def pack(first, second)
      [first.bytesize].pack("N") + first + [second.bytesize].pack("N") + second
    end

    def unpack(blob)
      first_length = blob[0, 4].unpack1("N")
      first = copy(blob, 4, first_length)

      second_offset = 4 + first_length
      second_length = blob[second_offset, 4].unpack1("N")
      second = copy(blob, second_offset + 4, second_length)

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
        parts << copy(blob, offset + 4, length)
        offset += 4 + length
      end
      parts
    end

    # blobのoffsetからlengthバイトを、新しく確保した領域にコピーして返す。offsetが範囲外ならnilを返す。
    # byteslice・blob[...]は、末尾まで切り出すとblob自身も共有の状態に変えるため、一時的にでも使わない。
    # その状態のblobに書き込むと、書き込みはblobの新しいコピーに対して行われ、元の領域は残る。
    def copy(blob, offset, length)
      return nil if offset > blob.bytesize

      blob.unpack1("@#{offset}a#{length}").force_encoding(blob.encoding)
    end
  end
end
