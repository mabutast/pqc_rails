# frozen_string_literal: true

module PqcRails
  # 鍵ペア(Sig・Kem・DhKem・HybridKemのKeypair)の表示で、秘密の値を伏せる共通処理。
  #
  # 素のStructはinspect・to_s・pp(IRBの表示もこれを使う)で全メンバーの値をそのまま出すため、
  # 鍵ペアがログ・例外の画面・コンソールに出ると秘密鍵のバイト列が漏れる。
  # 公開鍵は長さだけを出し、それ以外のメンバー(秘密鍵・認証鍵)は"[FILTERED]"
  # (Railsのfilter_parametersと同じ表記)にする。公開してよいメンバーを列挙する形なので、
  # 鍵ペアに秘密のメンバーが増えても伏せられる。
  # 公開鍵が文字列でない値(Keypair.newに直接渡した場合)は、長さを出さず"[FILTERED]"にする。
  # 表示で例外を出すと、例外の画面やログで元のエラーが見えなくなるため。
  # 値の取り出し(keypair.secret_key・to_h・to_a)と==はStructのまま変えない。
  # to_h・to_json(ActiveSupportのas_json)などで取り出した値をログに出せば、秘密鍵はそのまま出る。
  module RedactedKeypair
    PUBLIC_MEMBERS = %i[public_key].freeze

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
      return "[FILTERED]" unless PUBLIC_MEMBERS.include?(name)
      return "[FILTERED]" unless value.respond_to?(:bytesize)

      "[#{value.bytesize} bytes]"
    end
  end
end
