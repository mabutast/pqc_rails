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

      def install!(pq_alg_name: PqcRails::Cipher::DEFAULT_PQ_ALG_NAME)
        ::ActiveRecord::Encryption.configure(
          key_provider: PqcRails::ActiveRecord::KeyProvider.new,
          cipher: PqcRails::Cipher.new(pq_alg_name: pq_alg_name)
        )
      end
    end
  end
end
