# frozen_string_literal: true

require "yaml"
require "rails/generators"
require_relative "../../hybrid_kem"
require_relative "../../session/encryptor"
require_relative "../../session/key_manager"

module PqcRails
  module Generators
    # `rails generate pqc_rails:install` で実行される。
    # config/initializers/pqc_rails.rbを生成し、セッション暗号化用のHybridKemキーペアを
    # 生成してRails credentialsに保存する。
    class InstallGenerator < Rails::Generators::Base
      source_root File.expand_path("templates", __dir__)

      desc "Generates the pqc_rails initializer and a PQC session key in Rails credentials."

      def create_initializer
        copy_file "initializer.rb", "config/initializers/pqc_rails.rb"
      end

      def add_session_key_to_credentials
        encoded_key = PqcRails::Session::KeyManager.encode(generated_keypair)

        credentials.change do |tmp_path|
          data = YAML.safe_load(tmp_path.read, permitted_classes: [Symbol], aliases: true) || {}
          data["pqc_session_key"] = encoded_key
          tmp_path.write(data.to_yaml)
        end

        say_status :credentials, "Added pqc_session_key to Rails credentials"
      end

      private

      def generated_keypair
        @generated_keypair ||= PqcRails::HybridKem.open(PqcRails::Session::Encryptor::DEFAULT_PQ_ALG_NAME) do |hybrid|
          hybrid.generate_keypair
        end
      end

      def credentials
        Rails.application.credentials
      end
    end
  end
end
