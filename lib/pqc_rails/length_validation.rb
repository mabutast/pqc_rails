# frozen_string_literal: true

module PqcRails
  # 鍵・暗号文・署名等のバイト列長を検証する共通処理。
  # Kem/Sig/DhKem/EnvelopeCipherで同じチェックが必要になるため切り出している。
  module LengthValidation
    private

    def validate_length!(bytes, expected_length, name)
      return if bytes.bytesize == expected_length

      raise ArgumentError,
            "#{name} has wrong length: expected #{expected_length} bytes, got #{bytes.bytesize}"
    end
  end
end
