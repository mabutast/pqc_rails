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

    # 長さの欄が欠けている、または本体が長さの欄より短い場合はArgumentErrorを送出する。
    # 2つの長さを確かめてからコピーするため、例外の時は秘密鍵のコピーを作らない。
    # 既定では2つ目より後ろのバイト列は読まない(3要素の鍵を2要素として読む0.3.0以前と同じ読み方)。
    # exact: trueのときは、2つ目より後ろに余分なバイトがあればArgumentErrorを送出する。
    # 暗号文・公開鍵で、同じ値に別の書き方ができることと、末尾が壊れた値を黙って受け付けることを防ぐ。
    def unpack(blob, exact: false)
      raise ArgumentError, "packed blob must be a String, got #{blob.class}" unless blob.is_a?(String)

      first_length = read_length(blob, 0)
      second_offset = 4 + first_length
      second_length = read_length(blob, second_offset)
      packed_length = second_offset + 4 + second_length
      raise ArgumentError, "packed blob is truncated: expected #{second_length} bytes" if packed_length > blob.bytesize
      if exact && packed_length < blob.bytesize
        raise ArgumentError, "packed blob has #{blob.bytesize - packed_length} trailing bytes"
      end

      [copy(blob, 4, first_length), copy(blob, second_offset + 4, second_length)]
    end

    # 任意の個数のバイト列を [4byte長][本体] の繰り返しでまとめる。2つの場合はpackと同じ形になる。
    def pack_all(*parts)
      parts.map { |part| [part.bytesize].pack("N") + part }.join
    end

    # pack_allの逆。本体が長さの欄より短い、または末尾に長さの欄にも満たない余りがある場合は
    # ArgumentErrorを送出する(途中で切れた値を、要素の少ない値として読まないため)。
    def unpack_all(blob)
      raise ArgumentError, "packed blob must be a String, got #{blob.class}" unless blob.is_a?(String)

      lengths = []
      offset = 0
      while offset < blob.bytesize
        length = read_length(blob, offset)
        raise ArgumentError, "packed blob is truncated: expected #{length} bytes" if offset + 4 + length > blob.bytesize

        lengths << [offset + 4, length]
        offset += 4 + length
      end
      lengths.map { |start, length| copy(blob, start, length) }
    end

    def read_length(blob, offset)
      raise ArgumentError, "packed blob is truncated: missing length field" if offset + 4 > blob.bytesize

      blob.unpack1("@#{offset}N")
    end

    # blobのoffsetからlengthバイトを、新しく確保した領域にコピーして返す。範囲は呼び出し側が確かめる。
    # byteslice・blob[...]は、末尾まで切り出すとblob自身も共有の状態に変えるため、一時的にでも使わない。
    # その状態のblobに書き込むと、書き込みはblobの新しいコピーに対して行われ、元の領域は残る。
    def copy(blob, offset, length)
      blob.unpack1("@#{offset}a#{length}").force_encoding(blob.encoding)
    end
  end
end
