# frozen_string_literal: true

require_relative "algorithms"
require_relative "length_validation"
require_relative "ffi/sig"

module PqcRails
  # liboqsのGeneric SIG(署名)APIをRubyらしく包んだクラス。
  #
  # 使い方:
  #   sig = PqcRails::Sig.new(:ml_dsa_44) # またはliboqsの生の名前 "ML-DSA-44"
  #   keypair   = sig.generate_keypair
  #   signature = sig.sign("hello world", keypair.secret_key)
  #   sig.verify("hello world", signature, keypair.public_key) # => true
  #
  # PqcRails::Kem と同じパターン(open/free によるリソース管理)を踏襲している。
  class Sig
    include LengthValidation

    Keypair = Struct.new(:public_key, :secret_key)

    attr_reader :alg_name

    def initialize(alg_name)
      @alg_name = alg_name
      liboqs_alg_name = Algorithms.resolve_sig_name(alg_name)
      @sig_ptr = Ffi::Sig.OQS_SIG_new(liboqs_alg_name)
      if @sig_ptr.null?
        raise PqcRails::Error,
              "OQS_SIG_new failed for '#{liboqs_alg_name}'. " \
              "liboqsがこのアルゴリズムを有効にしてビルドされているか確認してください。"
      end

      @sig = Ffi::Sig::Struct.new(@sig_ptr)
      @freed = false
    end

    def length_public_key = @sig[:length_public_key]
    def length_secret_key = @sig[:length_secret_key]

    # (最大の)署名長。ML-DSAのような一部のアルゴリズムは固定長だが、
    # アルゴリズムによっては実際の署名長がこれより短くなることがある。
    def length_signature = @sig[:length_signature]

    # 鍵ペアを生成する
    # @return [Keypair]
    def generate_keypair
      ensure_not_freed!

      public_key = FFI::MemoryPointer.new(:uint8, length_public_key)
      secret_key = FFI::MemoryPointer.new(:uint8, length_secret_key)

      status = Ffi::Sig.OQS_SIG_keypair(@sig_ptr, public_key, secret_key)
      raise PqcRails::Error, "OQS_SIG_keypair failed (status=#{status})" unless status.zero?

      Keypair.new(
        public_key.read_bytes(length_public_key),
        secret_key.read_bytes(length_secret_key)
      )
    end

    # メッセージに署名する
    # @param message [String] 署名対象のバイト列
    # @param secret_key [String] バイト列
    # @return [String] 署名のバイト列(実際の長さは length_signature 以下のことがある)
    def sign(message, secret_key)
      ensure_not_freed!
      validate_length!(secret_key, length_secret_key, "secret_key")

      message_ptr = FFI::MemoryPointer.new(:uint8, message.bytesize)
      message_ptr.put_bytes(0, message)

      secret_key_ptr = FFI::MemoryPointer.new(:uint8, secret_key.bytesize)
      secret_key_ptr.put_bytes(0, secret_key)

      # signatureバッファは「最大長」で確保しておく。
      # 実際に書き込まれた長さは signature_len_ptr 経由で後から読み取る。
      signature_ptr = FFI::MemoryPointer.new(:uint8, length_signature)

      # OQS_SIG_signの第3引数(signature_len)は size_t* の出力引数。
      # FFI::MemoryPointer.new(:size_t, 1) で size_t 1個分の領域を確保し、
      # 関数呼び出し後に read_uint64 (64bit環境でのsize_t) で読み出す。
      signature_len_ptr = FFI::MemoryPointer.new(:size_t, 1)

      status = Ffi::Sig.OQS_SIG_sign(
        @sig_ptr,
        signature_ptr,
        signature_len_ptr,
        message_ptr,
        message.bytesize,
        secret_key_ptr
      )
      raise PqcRails::Error, "OQS_SIG_sign failed (status=#{status})" unless status.zero?

      actual_signature_len = signature_len_ptr.read(:size_t)
      signature_ptr.read_bytes(actual_signature_len)
    end

    # 署名を検証する
    # @param message [String] 元のメッセージのバイト列
    # @param signature [String] 検証する署名のバイト列
    # @param public_key [String] バイト列
    # @return [Boolean] 署名が正当であれば true
    def verify(message, signature, public_key)
      ensure_not_freed!
      validate_length!(public_key, length_public_key, "public_key")

      message_ptr = FFI::MemoryPointer.new(:uint8, message.bytesize)
      message_ptr.put_bytes(0, message)

      signature_ptr = FFI::MemoryPointer.new(:uint8, signature.bytesize)
      signature_ptr.put_bytes(0, signature)

      public_key_ptr = FFI::MemoryPointer.new(:uint8, public_key.bytesize)
      public_key_ptr.put_bytes(0, public_key)

      status = Ffi::Sig.OQS_SIG_verify(
        @sig_ptr,
        message_ptr,
        message.bytesize,
        signature_ptr,
        signature.bytesize,
        public_key_ptr
      )

      # OQS_SIG_verifyは「検証失敗」も含めてOQS_ERRORを返す設計。
      # つまりここでのstatusはエラー(例外送出)ではなく、検証結果そのものとして扱う。
      status.zero?
    end

    def free
      return if @freed

      Ffi::Sig.OQS_SIG_free(@sig_ptr)
      @freed = true
    end

    def self.open(alg_name)
      sig = new(alg_name)
      yield sig
    ensure
      sig&.free
    end

    private

    def ensure_not_freed!
      raise PqcRails::Error, "this PqcRails::Sig instance has already been freed" if @freed
    end
  end
end
