# frozen_string_literal: true

require_relative "algorithms"
require_relative "length_validation"
require_relative "ffi/kem"

module PqcRails
  # liboqsのGeneric KEM APIをRubyらしく包んだクラス。
  #
  # 使い方:
  #   kem = PqcRails::Kem.new(:ml_kem_512) # またはliboqsの生の名前 "ML-KEM-512"
  #   keypair = kem.generate_keypair
  #   encap   = kem.encapsulate(keypair.public_key)
  #   shared  = kem.decapsulate(encap.ciphertext, keypair.secret_key)
  #   shared == encap.shared_secret # => true
  #
  # kem.free を呼ぶか、ブロック形式(PqcRails::Kem.open)を使うことで
  # Cレベルのメモリを確実に解放できる。
  class Kem
    include LengthValidation

    Keypair = Struct.new(:public_key, :secret_key)
    Encapsulation = Struct.new(:ciphertext, :shared_secret)

    attr_reader :alg_name

    def initialize(alg_name)
      @alg_name = alg_name
      liboqs_alg_name = Algorithms.resolve_kem_name(alg_name)
      @kem_ptr = Ffi::Kem.OQS_KEM_new(liboqs_alg_name)
      if @kem_ptr.null?
        raise PqcRails::Error,
              "OQS_KEM_new failed for '#{liboqs_alg_name}'. " \
              "liboqsがこのアルゴリズムを有効にしてビルドされているか確認してください。"
      end

      @kem = Ffi::Kem::Struct.new(@kem_ptr)
      @freed = false
    end

    def length_public_key    = @kem[:length_public_key]
    def length_secret_key    = @kem[:length_secret_key]
    def length_ciphertext    = @kem[:length_ciphertext]
    def length_shared_secret = @kem[:length_shared_secret]

    def generate_keypair
      ensure_not_freed!

      public_key = FFI::MemoryPointer.new(:uint8, length_public_key)
      secret_key = FFI::MemoryPointer.new(:uint8, length_secret_key)

      status = Ffi::Kem.OQS_KEM_keypair(@kem_ptr, public_key, secret_key)
      raise PqcRails::Error, "OQS_KEM_keypair failed (status=#{status})" unless status.zero?

      Keypair.new(
        public_key.read_bytes(length_public_key),
        secret_key.read_bytes(length_secret_key)
      )
    end

    def encapsulate(public_key)
      ensure_not_freed!
      validate_length!(public_key, length_public_key, "public_key")

      ciphertext    = FFI::MemoryPointer.new(:uint8, length_ciphertext)
      shared_secret = FFI::MemoryPointer.new(:uint8, length_shared_secret)
      pk_ptr        = FFI::MemoryPointer.new(:uint8, public_key.bytesize)
      pk_ptr.put_bytes(0, public_key)

      status = Ffi::Kem.OQS_KEM_encaps(@kem_ptr, ciphertext, shared_secret, pk_ptr)
      raise PqcRails::Error, "OQS_KEM_encaps failed (status=#{status})" unless status.zero?

      Encapsulation.new(
        ciphertext.read_bytes(length_ciphertext),
        shared_secret.read_bytes(length_shared_secret)
      )
    end

    def decapsulate(ciphertext, secret_key)
      ensure_not_freed!
      validate_length!(ciphertext, length_ciphertext, "ciphertext")
      validate_length!(secret_key, length_secret_key, "secret_key")

      shared_secret = FFI::MemoryPointer.new(:uint8, length_shared_secret)
      ct_ptr        = FFI::MemoryPointer.new(:uint8, ciphertext.bytesize)
      ct_ptr.put_bytes(0, ciphertext)
      sk_ptr        = FFI::MemoryPointer.new(:uint8, secret_key.bytesize)
      sk_ptr.put_bytes(0, secret_key)

      status = Ffi::Kem.OQS_KEM_decaps(@kem_ptr, shared_secret, ct_ptr, sk_ptr)
      raise PqcRails::Error, "OQS_KEM_decaps failed (status=#{status})" unless status.zero?

      shared_secret.read_bytes(length_shared_secret)
    end

    def free
      return if @freed

      Ffi::Kem.OQS_KEM_free(@kem_ptr)
      @freed = true
    end

    def self.open(alg_name)
      kem = new(alg_name)
      yield kem
    ensure
      kem&.free
    end

    private

    def ensure_not_freed!
      raise PqcRails::Error, "this PqcRails::Kem instance has already been freed" if @freed
    end
  end
end