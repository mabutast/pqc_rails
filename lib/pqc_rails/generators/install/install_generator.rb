# frozen_string_literal: true

require "yaml"
require "rails/generators"
require_relative "../../hybrid_kem"
require_relative "../../key_source"
require_relative "../../session/encryptor"

module PqcRails
  module Generators
    # `rails generate pqc_rails:install` で実行される。
    # config/initializers/pqc_rails.rbを生成し、セッション用とDB用のHybridKemキーペアを
    # 別々に生成してRails credentialsに保存する。
    # 設定済みの鍵は上書きしない。鍵を置き換えると、その鍵で暗号化したデータを復号できなくなるため。
    class InstallGenerator < Rails::Generators::Base
      # credentialsのキーと、同じ鍵を渡す環境変数の組。
      KEY_NAMES = {
        "pqc_session_key" => "PQC_SESSION_KEY",
        "pqc_record_key" => "PQC_RECORD_KEY"
      }.freeze

      source_root File.expand_path("templates", __dir__)

      desc "Generates the pqc_rails initializer and any missing PQC session and record keys in Rails credentials."

      def create_initializer
        copy_file "initializer.rb", "config/initializers/pqc_rails.rb", skip: true
      end

      def add_missing_keys_to_credentials
        stored = parse_credentials(credentials.read)
        configured, missing = KEY_NAMES.keys.partition { |key| configured?(key, stored) }
        configured.each { |key| say_status :skip, "#{key} is already set", :yellow }
        return if missing.empty?

        write_keys(missing)
        missing.each { |key| say_status :credentials, "Added #{key} to Rails credentials" }
      end

      private

      def configured?(key, stored)
        !ENV.fetch(KEY_NAMES.fetch(key), nil).to_s.empty? || !(stored[key] || stored[key.to_sym]).to_s.empty?
      end

      def parse_credentials(content)
        YAML.safe_load(content, permitted_classes: [Symbol], aliases: true) || {}
      end

      def write_keys(keys)
        credentials.change do |tmp_path|
          data = parse_credentials(tmp_path.read)
          keys.each do |key|
            data.delete(key.to_sym)
            data[key] = PqcRails::KeySource.encode(generate_keypair)
          end
          tmp_path.write(data.to_yaml)
        end
      end

      def generate_keypair
        PqcRails::HybridKem.open(PqcRails::Session::Encryptor::DEFAULT_PQ_ALG_NAME, &:generate_keypair)
      end

      def credentials
        Rails.application.credentials
      end
    end
  end
end
