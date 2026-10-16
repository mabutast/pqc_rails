# frozen_string_literal: true

require "digest"
require "openssl"
require_relative "algorithms"

module PqcRails
  # 暗号文に付けるメタデータ(形式バージョン・アルゴリズムID・鍵ID)の定義。
  # Cipher(ActiveRecordのカラム)とSession::Encryptor(セッションCookie)が共通で使う。
  #
  # メタデータが無い旧形式(v0)では、どのアルゴリズムで暗号化したかを暗号文から知る手段が無く、
  # 復号は常に設定値のアルゴリズムで行うしかない。v1では暗号文自身がアルゴリズムIDと鍵IDを持つため、
  # 設定のアルゴリズムを変えても既存の暗号文を読め、復号時に鍵IDの一致する鍵だけを試せる。
  #
  # 形式バージョン・アルゴリズムID・鍵IDはAES-256-GCMの追加認証データ(associated data)に入れる。
  # いずれかが書き換えられると認証タグの検証に失敗し、復号できない。
  #
  # アルゴリズムIDは暗号文から読む値で、DBやCookieを書き換えられる者が自由に指定できる。
  # そのため、復号に使ってよいのはレジストリ(Algorithms::KEMS)に登録されたアルゴリズムと、
  # 設定で明示したアルゴリズムだけに限る。
  #
  # HybridKemは、鍵導出(HKDF)のinfoに、指定されたアルゴリズム名をその書き方のまま含める。
  # 同じML-KEM-768でも:ml_kem_768と"ML-KEM-768"では導出される共有鍵が異なるため、
  # v1では書き方を1つに決める(canonical_pq_alg_name)。暗号化・復号の両方がこの書き方でHybridKemを開く。
  #
  # 作成元の認証: KEMは公開鍵だけで暗号化できるため、KEMの共有鍵をそのままAES鍵にすると、
  # 公開鍵を知る者が正しく復号できる暗号文を作れる。v1では、秘密鍵から導いた認証鍵をKEMの共有鍵と合わせて
  # AES鍵を導く(data_key)。認証鍵を知らない者はAES鍵を作れず、AES-GCMの認証タグの検証に必ず失敗する。
  # 暗号化と復号を同じアプリケーション(秘密鍵の持ち主)が行う前提の構成で、HPKE(RFC 9180)のPSKモードと
  # 同じく、事前共有の秘密を鍵導出に混ぜて作成元を確かめる。共有鍵と認証鍵の組み合わせは、
  # NIST SP 800-227 §4.6.2の鍵結合(KDM((S1, S2), OtherInput))の形を取る。
  # 認証鍵は秘密鍵全体(古典側とPQ側の両方)から導く。古典側(X25519)の秘密鍵は、量子計算機があれば
  # 公開鍵から求められるため、古典側だけから導くと量子計算機を持つ者に認証鍵を作られる。
  module CiphertextFormat
    class UnsupportedAlgorithmError < PqcRails::Error; end

    VERSION = 1
    CLASSICAL_CURVE = "X25519"
    SEPARATOR = "+"
    KEY_LENGTH = 32
    AUTHENTICATION_KEY_INFO = "pqc_rails:v#{VERSION}:authentication-key".freeze
    DATA_KEY_INFO = "pqc_rails:v#{VERSION}:data-key".freeze

    module_function

    # HybridKemの組み合わせを表すアルゴリズムID(例: "X25519+ML-KEM-768")を返す。
    def algorithm_id(pq_alg_name)
      "#{CLASSICAL_CURVE}#{SEPARATOR}#{Algorithms.resolve_kem_name(pq_alg_name)}"
    end

    # アルゴリズムIDを検証し、HybridKemに渡すPQ側のアルゴリズム名をv1の書き方で返す。
    # configuredは呼び出し元に設定されたアルゴリズム(レジストリ未登録の生の名前を含みうる)。
    def pq_alg_name_for(algorithm_id, configured:)
      curve, pq_name = algorithm_id.to_s.split(SEPARATOR, 2)
      unless curve == CLASSICAL_CURVE && allowed_pq_name?(pq_name, configured)
        raise UnsupportedAlgorithmError, "unsupported algorithm id: #{algorithm_id.inspect}"
      end

      canonical_pq_alg_name(pq_name)
    end

    # v1でHybridKemに渡すアルゴリズム名。レジストリに登録されたものはシンボル、それ以外はliboqs名。
    def canonical_pq_alg_name(pq_alg_name)
      liboqs_name = Algorithms.resolve_kem_name(pq_alg_name)
      registered = Algorithms::KEMS.values.find { |algorithm| algorithm.liboqs_name == liboqs_name }
      registered ? registered.name : liboqs_name
    end

    # 公開鍵から鍵IDを求める。ActiveRecord::KeyProvider::Key#idと同じ値になる。
    # 16bitしかなく衝突しうるため、一致した鍵の識別ではなく、一致しない鍵を復号の候補から外す目的に使う。
    def key_id(public_key)
      Digest::SHA1.hexdigest(public_key)[0, 4]
    end

    def associated_data(algorithm_id:, key_id:)
      "pqc_rails:v#{VERSION}:#{algorithm_id}:#{key_id}"
    end

    # KEMの共有鍵と、秘密鍵から導いた認証鍵から、AES-256-GCMの鍵(32バイト)を導く。
    # どちらもHKDF-SHA256(saltは空文字列、SP 800-56C §8.2)で、用途ごとに異なるinfoを使う。
    def data_key(shared_secret, secret_key)
      authentication_key = hkdf(secret_key, AUTHENTICATION_KEY_INFO)
      hkdf(shared_secret + authentication_key, DATA_KEY_INFO)
    end

    def write_legacy?
      PqcRails.configuration.ciphertext_format == :v0
    end

    # 旧形式(v0)の暗号文を受け付けない設定なら、PqcRails::Errorを送出する。
    def ensure_legacy_accepted!
      return if PqcRails.configuration.accept_legacy_ciphertexts

      raise PqcRails::Error, "legacy (v0) ciphertexts are not accepted (accept_legacy_ciphertexts is false)"
    end

    def hkdf(input_key_material, info)
      OpenSSL::KDF.hkdf(input_key_material, salt: "", info: info, length: KEY_LENGTH, hash: "SHA256")
    end
    private_class_method :hkdf

    def allowed_pq_name?(pq_name, configured)
      return false if pq_name.nil? || pq_name.empty?

      Algorithms::KEMS.values.any? { |algorithm| algorithm.liboqs_name == pq_name } ||
        Algorithms.resolve_kem_name(configured) == pq_name
    end
    private_class_method :allowed_pq_name?
  end
end
