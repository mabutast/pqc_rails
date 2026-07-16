# frozen_string_literal: true

require "openssl"
require_relative "blob_packing"
require_relative "dh_kem"
require_relative "kem"

module PqcRails
  # 古典ECDH(DhKem)とPQ KEM(liboqs経由のKem)を組み合わせたハイブリッドKEM。
  #
  # 量子コンピュータがPQ側を破ったとしても古典側が安全なら(あるいはその逆でも)
  # 全体の共有鍵は安全、という「移行期間中の保険」を提供するのが目的。
  # NIST標準化されたML-KEMはまだ実運用歴が浅いため、実績のあるX25519と組み合わせることで
  # 「PQアルゴリズム自体に未知の脆弱性が見つかった場合」のリスクを下げる。
  #
  # コンバイナの方式: 古典側の共有鍵とPQ側の共有鍵を連結し、両者のciphertext
  # (encapsulateの出力)をHKDFのinfoにバインドした上でHKDF-SHA256にかけて
  # 32バイトの最終共有鍵を導出する。ciphertextをバインドするのは、
  # 通常のTLSハンドシェイクのようなトランスクリプトハッシュによる結合が無い
  # スタンドアロン用途のため、コンバイナ自体に結合の安全性を持たせる必要があるため。
  #
  # この「連結してからHKDFにかける」方式は自己流ではなく、RFC 9954(TLS 1.3ハイブリッド鍵共有、
  # 旧draft-ietf-tls-hybrid-design)が採用する"concatenation approach"と同じ構成であり、
  # NIST SP 800-56Cが承認済みアルゴリズムと非承認アルゴリズムのハイブリッド共有鍵生成における
  # 承認済み手法として単純連結を挙げている。RFC 9954はこの構成が「dual-PRFコンバイナ」に対応し、
  # ハッシュ関数がdual-PRFであるという仮定の下で安全性が証明されているとしている([BINDEL]論文)。
  # なお、RFC 9370(IKEv2の複数鍵交換)はSKEYSEED(n) = prf(SK_d(n-1), SK(n) | Ni | Nr)という
  # 逐次的なPRF連鎖(cascade)を採るため、本実装とは別のコンバイナ方式である点に注意
  # (2026-07-16、一次資料読解セッションでRFC本文を確認して検証済み)。
  #
  # 使い方:
  #   PqcRails::HybridKem.open(:ml_kem_512) do |hybrid|
  #     keypair = hybrid.generate_keypair
  #     encap   = hybrid.encapsulate(keypair.public_key)
  #     shared  = hybrid.decapsulate(encap.ciphertext, keypair.secret_key)
  #     shared == encap.shared_secret # => true
  #   end
  class HybridKem
    Keypair = Struct.new(:public_key, :secret_key)
    Encapsulation = Struct.new(:ciphertext, :shared_secret)

    COMBINER_LABEL = "pqc_rails-hybrid-kem-v1"
    SHARED_SECRET_LENGTH = 32

    attr_reader :pq_alg_name, :classical_curve

    def initialize(pq_alg_name, classical_curve = "X25519")
      @pq_alg_name = pq_alg_name
      @classical_curve = classical_curve
      @classical = DhKem.new(classical_curve)
      @pq = Kem.new(pq_alg_name)
      @freed = false
    end

    def generate_keypair
      ensure_not_freed!

      classical_keypair = @classical.generate_keypair
      pq_keypair = @pq.generate_keypair

      Keypair.new(
        BlobPacking.pack(classical_keypair.public_key, pq_keypair.public_key),
        BlobPacking.pack(classical_keypair.secret_key, pq_keypair.secret_key)
      )
    end

    def encapsulate(public_key)
      ensure_not_freed!

      classical_public_key, pq_public_key = BlobPacking.unpack(public_key)
      classical_encap = @classical.encapsulate(classical_public_key)
      pq_encap = @pq.encapsulate(pq_public_key)

      Encapsulation.new(
        BlobPacking.pack(classical_encap.ciphertext, pq_encap.ciphertext),
        combine(classical_encap.shared_secret, pq_encap.shared_secret,
                classical_encap.ciphertext, pq_encap.ciphertext)
      )
    end

    def decapsulate(ciphertext, secret_key)
      ensure_not_freed!

      classical_ciphertext, pq_ciphertext = BlobPacking.unpack(ciphertext)
      classical_secret_key, pq_secret_key = BlobPacking.unpack(secret_key)

      classical_shared = @classical.decapsulate(classical_ciphertext, classical_secret_key)
      pq_shared = @pq.decapsulate(pq_ciphertext, pq_secret_key)

      combine(classical_shared, pq_shared, classical_ciphertext, pq_ciphertext)
    end

    def free
      return if @freed

      @pq.free
      @freed = true
    end

    def self.open(pq_alg_name, classical_curve = "X25519")
      hybrid = new(pq_alg_name, classical_curve)
      yield hybrid
    ensure
      hybrid&.free
    end

    private

    # 古典側とPQ側の共有鍵を連結し、両者のciphertextとアルゴリズム名をinfoに
    # バインドした上でHKDF-SHA256にかけ、最終的な共有鍵を導出する。
    def combine(classical_secret, pq_secret, classical_ciphertext, pq_ciphertext)
      ikm = classical_secret + pq_secret
      info = [
        COMBINER_LABEL,
        @classical.curve,
        @pq.alg_name.to_s,
        classical_ciphertext,
        pq_ciphertext
      ].join("\x00")

      OpenSSL::KDF.hkdf(ikm, salt: "", info: info, length: SHARED_SECRET_LENGTH, hash: "SHA256")
    end

    def ensure_not_freed!
      raise PqcRails::Error, "this PqcRails::HybridKem instance has already been freed" if @freed
    end
  end
end
