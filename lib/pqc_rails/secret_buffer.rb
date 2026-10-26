# frozen_string_literal: true

require "ffi"

module PqcRails
  # liboqsに秘密鍵・共有鍵を渡す、またはliboqsから受け取るためのCのバッファを扱う共通処理。
  #
  # FFI::MemoryPointerはGCで解放される時に中身を消さないため、解放された領域に秘密の値が残る。
  # ここではブロックを抜ける時に(例外の場合も)バッファをゼロで埋める。
  # ブロックの中で読み出したRubyのStringはこの対象外で、Rubyには確実に消す手段が無い
  # (docs/THREAT_MODEL.md「中間値の破棄」)。
  module SecretBuffer
    module_function

    # sizeバイトのバッファを確保し、bytesがあれば書き込んでからブロックに渡す。ブロックの戻り値を返す。
    def with(size, bytes = nil)
      pointer = FFI::MemoryPointer.new(:uint8, size)
      pointer.put_bytes(0, bytes) if bytes
      yield pointer
    ensure
      pointer&.clear
    end
  end
end
