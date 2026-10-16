# frozen_string_literal: true

require "digest"
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
  module CiphertextFormat
    class UnsupportedAlgorithmError < PqcRails::Error; end

    VERSION = 1
    CLASSICAL_CURVE = "X25519"
    SEPARATOR = "+"

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

    def write_legacy?
      PqcRails.configuration.ciphertext_format == :v0
    end

    def allowed_pq_name?(pq_name, configured)
      return false if pq_name.nil? || pq_name.empty?

      Algorithms::KEMS.values.any? { |algorithm| algorithm.liboqs_name == pq_name } ||
        Algorithms.resolve_kem_name(configured) == pq_name
    end
    private_class_method :allowed_pq_name?
  end
end
