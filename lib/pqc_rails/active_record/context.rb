# frozen_string_literal: true

require "active_record"
require_relative "../cipher"
require_relative "key_provider"

module PqcRails
  module ActiveRecord
    # ActiveRecord::Encryptionのデフォルトcontextに、PqcRails::Cipherと
    # PqcRails::ActiveRecord::KeyProviderを設定する。
    #
    # 注意: ActiveRecord::Encryption.config.custom_contexts はwith_encryption_context用の
    # スレッドローカルな一時上書きスタックで、永続的な差し替えには使えない。
    # 永続的な差し替えの正しい入口は ActiveRecord::Encryption.configure(...)。
    module Context
      module_function

      def install!(pq_alg_name: PqcRails::Cipher::DEFAULT_PQ_ALG_NAME,
                   primary_key: existing_config_value(:primary_key),
                   deterministic_key: existing_config_value(:deterministic_key),
                   key_derivation_salt: existing_config_value(:key_derivation_salt))
        ::ActiveRecord::Encryption.configure(
          key_provider: PqcRails::ActiveRecord::KeyProvider.new,
          cipher: PqcRails::Cipher.new(pq_alg_name: pq_alg_name),
          primary_key: primary_key,
          deterministic_key: deterministic_key,
          key_derivation_salt: key_derivation_salt
        )
      end

      # ActiveRecord::Encryption.configure(...)は呼ぶたびにprimary_key/deterministic_key/
      # key_derivation_saltを常に上書きする(未指定ならnilで巻き戻す)ため、install!を呼ぶ前に
      # bin/rails db:encryption:init等で既に設定されていた値を、明示的な指定が無い限り
      # 引き継ぐ。config側の値は未設定だとErrors::Configurationを送出しうるので握りつぶす。
      def existing_config_value(name)
        ::ActiveRecord::Encryption.config.public_send(name)
      rescue ::ActiveRecord::Encryption::Errors::Configuration
        nil
      end
    end
  end
end
