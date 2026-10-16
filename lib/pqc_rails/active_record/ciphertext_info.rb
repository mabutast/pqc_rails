# frozen_string_literal: true

require "active_record"
require_relative "../ciphertext_format"

module PqcRails
  module ActiveRecord
    # ActiveRecord::Encryptionの暗号化カラムに保存された値(record.ciphertext_for(:attr)が返す文字列)を、
    # 復号せずに調べる。鍵ローテーションやアルゴリズム変更の後に、どのレコードが旧い鍵・旧い形式のまま
    # 残っているかを判断する材料に使う。
    #
    # format_version: 1以上は形式バージョン、0は0.3.0以前の形式(メタデータを持たない)、
    #                 nilはpqc_rails以外の暗号文(Rails標準のAES-256-GCM等)
    # algorithm_id / key_id: 形式バージョン1以上の暗号文だけが持つ。それ以外はnil
    class CiphertextInfo
      attr_reader :format_version, :algorithm_id, :key_id

      # 暗号文として読めない値(nil、平文のまま残っている値など)はnilを返す。
      def self.parse(serialized)
        return nil if serialized.nil?

        new(::ActiveRecord::Encryption::MessageSerializer.new.load(serialized))
      rescue ::ActiveRecord::Encryption::Errors::Base, ArgumentError, TypeError, JSON::ParserError
        nil
      end

      def initialize(message)
        headers = message.headers
        version = headers[:pv] || headers["pv"]
        kem_ciphertext = headers[:kem_ct] || headers["kem_ct"]

        @format_version = version || (kem_ciphertext ? 0 : nil)
        @algorithm_id = headers[:alg] || headers["alg"]
        @key_id = headers[:kid] || headers["kid"]
      end

      # pqc_rails(HybridKem)で暗号化された値ならtrue。
      def pqc?
        !format_version.nil?
      end

      # 0.3.0以前の形式(作成元の認証・アルゴリズムID・鍵IDを持たない)ならtrue。
      def legacy?
        format_version&.zero? || false
      end
    end
  end
end
