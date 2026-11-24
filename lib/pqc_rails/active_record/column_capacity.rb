# frozen_string_literal: true

module PqcRails
  module ActiveRecord
    # 暗号化する属性の列に、暗号文が入る長さがあるかを確かめる。
    #
    # MySQLのstring列は255文字までで、KEMの暗号文を含む値は短い平文でも入らない。strictモードでは保存が
    # エラーになり、strictモードでなければ値が切れて保存され、元の値を復元できなくなる。
    # 属性ごとの設定(key_provider等)を反映するため、属性の型で短い値を実際に暗号化して長さを測る。
    # 暗号文は平文より長くなるので、測った長さは必要な長さの下限になる。
    module ColumnCapacity
      Column = Struct.new(:attribute, :limit, :required, keyword_init: true)
      SAMPLE = "x"

      module_function

      # 暗号文が入らない列をColumnの配列で返す。長さの上限が無い列とテーブルが無いモデルは対象外。
      def too_short(model)
        return [] unless model.table_exists?

        model.encrypted_attributes.filter_map do |attribute|
          name = attribute.to_s
          limit = model.columns_hash[name]&.limit
          next unless limit

          required = model.type_for_attribute(name).serialize(SAMPLE).to_s.bytesize
          Column.new(attribute: name, limit: limit, required: required) if required > limit
        end
      end

      # 短い値の暗号文は入るが、長い値では超えうるstring列をColumnの配列で返す。
      def may_overflow(model)
        return [] unless model.table_exists?

        short = too_short(model).map(&:attribute)
        model.encrypted_attributes.filter_map do |attribute|
          name = attribute.to_s
          column = model.columns_hash[name]
          next if short.include?(name) || column&.type != :string || column.limit.nil?

          required = model.type_for_attribute(name).serialize(SAMPLE).to_s.bytesize
          Column.new(attribute: name, limit: column.limit, required: required)
        end
      end

      # このレコードの今の値を暗号化すると列に入らない属性をColumnの配列で返す。
      # 暗号文の長さは平文の内容と長さで決まるので、書く前に測った長さは書く時の長さと一致する。
      def too_long(record)
        model = record.class
        model.encrypted_attributes.filter_map do |attribute|
          name = attribute.to_s
          limit = model.columns_hash[name]&.limit
          next unless limit

          value = record.read_attribute(name)
          next if value.nil?

          required = model.type_for_attribute(name).serialize(value).to_s.bytesize
          Column.new(attribute: name, limit: limit, required: required) if required > limit
        end
      end
    end
  end
end
