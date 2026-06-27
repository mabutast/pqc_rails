# frozen_string_literal: true

require "openssl"
require_relative "length_validation"

module PqcRails
  # 古典的なECDH(X25519)を「KEM」のAPI形状(generate_keypair/encapsulate/decapsulate)で
  # 包んだクラス。RFC 9180(HPKE)のDHKEMと同じ考え方:
  #
  #   encapsulate: 一時鍵ペアを生成し、一時秘密鍵と相手の公開鍵からECDHで共有鍵を導出する。
  #                ciphertextは一時鍵の公開鍵そのもの。
  #   decapsulate: 自分の秘密鍵とciphertext(相手の一時公開鍵)からECDHで同じ共有鍵を導出する。
  #
  # これにより PqcRails::Kem (liboqs) と同じインターフェースで古典鍵を扱えるようになり、
  # HybridKem側で両者を対称に組み合わせられる。
  #
  # 使い方:
  #   dh_kem = PqcRails::DhKem.new
  #   keypair = dh_kem.generate_keypair
  #   encap   = dh_kem.encapsulate(keypair.public_key)
  #   shared  = dh_kem.decapsulate(encap.ciphertext, keypair.secret_key)
  #   shared == encap.shared_secret # => true
  class DhKem
    include LengthValidation

    Keypair = Struct.new(:public_key, :secret_key)
    Encapsulation = Struct.new(:ciphertext, :shared_secret)

    KEY_LENGTH = 32

    attr_reader :curve

    def initialize(curve = "X25519")
      @curve = curve
    end

    def length_public_key    = KEY_LENGTH
    def length_secret_key    = KEY_LENGTH
    def length_ciphertext    = KEY_LENGTH
    def length_shared_secret = KEY_LENGTH

    def generate_keypair
      key = OpenSSL::PKey.generate_key(@curve)
      Keypair.new(key.raw_public_key, key.raw_private_key)
    end

    def encapsulate(public_key)
      validate_length!(public_key, length_public_key, "public_key")

      peer_key  = OpenSSL::PKey.new_raw_public_key(@curve, public_key)
      ephemeral = OpenSSL::PKey.generate_key(@curve)

      Encapsulation.new(ephemeral.raw_public_key, ephemeral.derive(peer_key))
    end

    def decapsulate(ciphertext, secret_key)
      validate_length!(ciphertext, length_ciphertext, "ciphertext")
      validate_length!(secret_key, length_secret_key, "secret_key")

      own_key       = OpenSSL::PKey.new_raw_private_key(@curve, secret_key)
      ephemeral_pub = OpenSSL::PKey.new_raw_public_key(@curve, ciphertext)

      own_key.derive(ephemeral_pub)
    end
  end
end
