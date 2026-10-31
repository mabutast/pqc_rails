# frozen_string_literal: true

module PqcRails
  # 鍵・暗号文・署名等のバイト列長を検証する共通処理。
  # Kem/Sig/DhKem/EnvelopeCipherで同じチェックが必要になるため切り出している。
  module LengthValidation
    private

    # 文字列でない値(nil等)もArgumentErrorにする。FFIへ渡す前に、長さの違う入力を必ず止めるため。
    def validate_length!(bytes, expected_length, name)
      validate_string!(bytes, name)
      return if bytes.bytesize == expected_length

      raise ArgumentError,
            "#{name} has wrong length: expected #{expected_length} bytes, got #{bytes.bytesize}"
    end

    def validate_string!(bytes, name)
      raise ArgumentError, "#{name} must be a String, got #{bytes.class}" unless bytes.is_a?(String)
    end
  end
end
