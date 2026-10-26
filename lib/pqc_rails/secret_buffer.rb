# frozen_string_literal: true

require "ffi"

module PqcRails
  # liboqsに秘密鍵・共有鍵を渡す、またはliboqsから受け取るためのCのバッファを扱う共通処理。
  #
  # FFI::MemoryPointerはGCで解放される時に中身を消さないため、解放された領域に秘密の値が残る。
  # ここではブロックを抜ける時に(例外の場合も)バッファをゼロで埋める。
  # Rubyの文字列は、使い終わった途中のコピーをwipeでゼロ埋めする。プロセスが持ち続ける鍵そのものと、
  # Ruby・OpenSSLが内部で作るコピーは消せない(docs/THREAT_MODEL.md「中間値の破棄」)。
  module SecretBuffer
    module_function

    # 秘密の値を持つRubyの文字列を、同じ領域のままゼロで上書きする。nilと凍結された文字列は飛ばす。
    # 消せるのはその文字列自身の領域だけで、すでに作られたコピーや、他の文字列と共有している元の領域は残る。
    def wipe(*strings)
      strings.each do |string|
        next if string.nil? || string.frozen?

        string.bytesplice(0, string.bytesize, "\0".b * string.bytesize)
      end
      nil
    end

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
