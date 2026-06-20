# frozen_string_literal: true

require "ffi"

module PqcRails
  module Ffi
    # liboqsのGeneric KEM APIへの低レベルFFIバインディング。
    module Kem
      extend FFI::Library

      ffi_lib PqcRails.configuration.liboqs_path

      class Struct < FFI::Struct
        layout(
          :method_name,          :pointer,
          :alg_version,          :pointer,
          :claimed_nist_level,   :uint8,
          :ind_cca,               :bool,
          :length_public_key,    :size_t,
          :length_secret_key,    :size_t,
          :length_ciphertext,    :size_t,
          :length_shared_secret, :size_t,
          :length_keypair_seed,  :size_t,
          :length_encaps_seed,   :size_t,
          :keypair_derand,       :pointer,
          :keypair,               :pointer,
          :encaps_derand,        :pointer,
          :encaps,                :pointer,
          :decaps,                :pointer
        )
      end

      attach_function :OQS_KEM_new, [:string], :pointer
      attach_function :OQS_KEM_free, [:pointer], :void
      attach_function :OQS_KEM_keypair, [:pointer, :pointer, :pointer], :int
      attach_function :OQS_KEM_encaps, [:pointer, :pointer, :pointer, :pointer], :int
      attach_function :OQS_KEM_decaps, [:pointer, :pointer, :pointer, :pointer], :int
    end
  end
end