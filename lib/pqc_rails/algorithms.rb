# frozen_string_literal: true

module PqcRails
  # NIST標準化アルゴリズムのシンボル名(:ml_kem_512等)とliboqs側のアルゴリズム名文字列
  # ("ML-KEM-512"等)を対応づけるレジストリ。
  #
  # Kem/Sigはliboqsの生の文字列を直接渡すこともできるが(liboqsが対応する任意のアルゴリズムを
  # 使える柔軟性は維持する)、このレジストリを経由してシンボルで指定すれば、
  # liboqs側の命名に依存しない安定したAPIになる。
  # 将来 ActiveRecord::Encryption と統合する際、設定ファイルやモデルにliboqsの生文字列を
  # 書かせるのではなく、このシンボルを書かせることを想定している。
  #
  # 使い方:
  #   PqcRails::Kem.new(:ml_kem_512)
  #   PqcRails::Sig.new(:ml_dsa_44)
  module Algorithms
    class UnknownAlgorithmError < PqcRails::Error; end

    Algorithm = Struct.new(:name, :liboqs_name, :family, :security_level, :status, keyword_init: true)

    KEMS = {
      ml_kem_512: Algorithm.new(
        name: :ml_kem_512, liboqs_name: "ML-KEM-512", family: :kem, security_level: 1, status: :recommended
      ),
      ml_kem_768: Algorithm.new(
        name: :ml_kem_768, liboqs_name: "ML-KEM-768", family: :kem, security_level: 3, status: :recommended
      ),
      ml_kem_1024: Algorithm.new(
        name: :ml_kem_1024, liboqs_name: "ML-KEM-1024", family: :kem, security_level: 5, status: :recommended
      )
    }.freeze

    SIGS = {
      ml_dsa_44: Algorithm.new(
        name: :ml_dsa_44, liboqs_name: "ML-DSA-44", family: :sig, security_level: 2, status: :recommended
      ),
      ml_dsa_65: Algorithm.new(
        name: :ml_dsa_65, liboqs_name: "ML-DSA-65", family: :sig, security_level: 3, status: :recommended
      ),
      ml_dsa_87: Algorithm.new(
        name: :ml_dsa_87, liboqs_name: "ML-DSA-87", family: :sig, security_level: 5, status: :recommended
      )
    }.freeze

    module_function

    def find_kem(name)
      KEMS.fetch(name.to_sym)
    rescue KeyError
      raise UnknownAlgorithmError, "unknown KEM algorithm: #{name.inspect}. Known: #{KEMS.keys.join(', ')}"
    end

    def find_sig(name)
      SIGS.fetch(name.to_sym)
    rescue KeyError
      raise UnknownAlgorithmError, "unknown SIG algorithm: #{name.inspect}. Known: #{SIGS.keys.join(', ')}"
    end

    # liboqsに渡すべきアルゴリズム名文字列を解決する。
    # Stringが渡された場合はliboqsの生の名前としてそのまま通す(後方互換・将来の未登録アルゴリズム用)。
    # Symbolが渡された場合はレジストリ経由でliboqs名に変換する。
    def resolve_kem_name(name)
      return name if name.is_a?(String)

      find_kem(name).liboqs_name
    end

    def resolve_sig_name(name)
      return name if name.is_a?(String)

      find_sig(name).liboqs_name
    end
  end
end
