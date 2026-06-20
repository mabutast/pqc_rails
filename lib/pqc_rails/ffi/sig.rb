# frozen_string_literal: true

require "ffi"

module PqcRails
  module Ffi
    # liboqsのGeneric SIG(署名)APIへの低レベルFFIバインディング。
    # PqcRails::Ffi::Kem と対になる、署名アルゴリズム版。
    module Sig
      extend FFI::Library

      ffi_lib PqcRails.configuration.liboqs_path

      # liboqs/include/oqs/sig.h の OQS_SIG 構造体に対応。
      # liboqs 0.15.0の実物ヘッダ(/usr/local/include/oqs/sig.h)で確認済みのフィールド順序。
      #
      # KEMのOQS_KEM構造体との違い:
      #   - euf_cma / suf_cma / sig_with_ctx_support という3つのbool値が追加されている
      #   - length_ciphertext / length_shared_secret は無く、代わりに length_signature がある
      #   - keypair_derand に相当するderandomized版は無い(2026-06-20時点のヘッダには存在しない)
      #   - sign / verify に加えて、コンテキスト文字列付きの
      #     sign_with_ctx_str / verify_with_ctx_str が追加で存在する
      class Struct < FFI::Struct
        layout(
          :method_name,            :pointer,
          :alg_version,            :pointer,
          :claimed_nist_level,     :uint8,
          :euf_cma,                 :bool,
          :suf_cma,                 :bool,
          :sig_with_ctx_support,   :bool,
          :length_public_key,      :size_t,
          :length_secret_key,      :size_t,
          :length_signature,       :size_t,
          :keypair,                 :pointer,
          :sign,                    :pointer,
          :sign_with_ctx_str,      :pointer,
          :verify,                  :pointer,
          :verify_with_ctx_str,    :pointer
        )
      end

      # OQS_SIG *OQS_SIG_new(const char *method_name);
      attach_function :OQS_SIG_new, [:string], :pointer

      # void OQS_SIG_free(OQS_SIG *sig);
      attach_function :OQS_SIG_free, [:pointer], :void

      # OQS_STATUS OQS_SIG_keypair(const OQS_SIG *sig, uint8_t *public_key, uint8_t *secret_key);
      attach_function :OQS_SIG_keypair, [:pointer, :pointer, :pointer], :int

      # OQS_STATUS OQS_SIG_sign(const OQS_SIG *sig, uint8_t *signature, size_t *signature_len,
      #                          const uint8_t *message, size_t message_len, const uint8_t *secret_key);
      # 引数は6個: sig, signature, signature_len(出力, size_t*), message, message_len, secret_key
      # signature_len は size_t* (出力引数)。FFIでは :pointer として渡し、
      # 呼び出し側で FFI::MemoryPointer#read_ulong 等で読み出す必要がある。
      attach_function :OQS_SIG_sign,
                       [:pointer, :pointer, :pointer, :pointer, :size_t, :pointer],
                       :int

      # OQS_STATUS OQS_SIG_verify(const OQS_SIG *sig, const uint8_t *message, size_t message_len,
      #                            const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
      # 引数は6個: sig, message, message_len, signature, signature_len, public_key
      attach_function :OQS_SIG_verify,
                       [:pointer, :pointer, :size_t, :pointer, :size_t, :pointer],
                       :int
    end
  end
end
