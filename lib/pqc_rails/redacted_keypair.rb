# frozen_string_literal: true

module PqcRails
  # 鍵ペア(Sig・Kem・DhKem・HybridKemのKeypair)の表示で、秘密の値を伏せる共通処理。
  #
  # 素のStructはinspect・to_s・pp(IRBの表示もこれを使う)で全メンバーの値をそのまま出すため、
  # 鍵ペアがログ・例外の画面・コンソールに出ると秘密鍵のバイト列が漏れる。
  # 秘密の値は"[FILTERED]"(Railsのfilter_parametersと同じ表記)、公開鍵は長さだけを出す。
  # 値の取り出し(keypair.secret_key)・to_a・==はStructのまま変えない。
  module RedactedKeypair
    SECRET_MEMBERS = %i[secret_key authentication_key].freeze

    def inspect
      fields = each_pair.map { |name, value| "#{name}=#{redacted_value(name, value)}" }
      "#<struct #{self.class.name} #{fields.join(', ')}>"
    end

    def to_s = inspect

    def pretty_print(pp)
      pp.text(inspect)
    end

    private

    def redacted_value(name, value)
      return "nil" if value.nil?
      return "[FILTERED]" if SECRET_MEMBERS.include?(name)
      return "[#{value.bytesize} bytes]" if value.is_a?(String)

      value.inspect
    end
  end
end
