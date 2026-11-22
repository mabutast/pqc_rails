# frozen_string_literal: true

module PqcRails
  # 鍵ペア(Sig・Kem・DhKem・HybridKemのKeypair)とKEMの結果(Encapsulation)の表示・JSONで、
  # 秘密の値を伏せる共通処理。
  #
  # 素のStructはinspect・to_s・pp(IRBの表示もこれを使う)で全メンバーの値をそのまま出し、
  # ActiveSupportのas_json(to_json・render json:が使う)も全メンバーを取り出すため、
  # ログ・例外の画面・コンソール・JSONのレスポンスに秘密のバイト列が漏れる。
  # 公開鍵と暗号文は長さだけを出し、それ以外のメンバー(秘密鍵・認証鍵・共有秘密)は"[FILTERED]"
  # (Railsのfilter_parametersと同じ表記)にする。公開してよいメンバーを列挙する形なので、
  # 秘密のメンバーが増えても伏せられる。
  # 公開側の値が文字列でない場合(Struct.newに直接渡した場合)は、長さを出さず"[FILTERED]"にする。
  # 表示で例外を出すと、例外の画面やログで元のエラーが見えなくなるため。
  # 値の取り出し(keypair.secret_key・to_h・to_a)と==はStructのまま変えない。
  # to_h・to_aで取り出した値をログやJSONに渡せば、秘密の値はそのまま出る。
  # YAML(to_yaml、Railsのdebugヘルパー)とMarshalは保存・復元の形式で、この処理を通らず秘密の値をそのまま出す。
  module RedactedStruct
    PUBLIC_MEMBERS = %i[public_key ciphertext].freeze

    def inspect
      fields = each_pair.map { |name, value| "#{name}=#{redacted_value(name, value) || 'nil'}" }
      "#<struct #{self.class.name} #{fields.join(', ')}>"
    end

    def to_s = inspect

    def pretty_print(pp)
      pp.text(inspect)
    end

    # only・exceptなどのオプションは受け取るだけで使わない。常に全メンバーを伏せた形を返す。
    def as_json(_options = nil)
      each_pair.to_h { |name, value| [name.to_s, redacted_value(name, value)] }
    end

    private

    def redacted_value(name, value)
      return nil if value.nil?
      return "[FILTERED]" unless PUBLIC_MEMBERS.include?(name)
      return "[FILTERED]" unless value.respond_to?(:bytesize)

      "[#{value.bytesize} bytes]"
    end
  end
end
