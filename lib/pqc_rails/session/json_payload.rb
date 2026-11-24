# frozen_string_literal: true

require "json"

module PqcRails
  module Session
    # セッションの中身をJSONで読み書きする(形式v2)。
    #
    # JSONで同じ形に戻る値だけを受け付ける: String・Integer・有限のFloat・true・false・nil・Array・
    # キーが文字列のHash。シンボルの値は文字列にする(Railsのセッション・フラッシュで使われやすく、
    # 文字列になっても意味が変わりにくいため)。TimeやシンボルのキーのHash、独自のオブジェクトは、
    # 黙って文字列にすると読み戻した時に型が変わるので、書き込みの時にPqcRails::Errorにする。
    # エラーのメッセージには、最上位のキーの名前とクラス名だけを出し、値は出さない。
    module JsonPayload
      module_function

      def dump(data)
        raise PqcRails::Error, "the session must be a Hash with string keys, got #{data.class}" unless data.is_a?(Hash)

        normalized = data.to_h do |key, value|
          raise PqcRails::Error, "session keys must be strings, got #{key.class}" unless key.is_a?(String)

          [key, normalize(value, key)]
        end
        JSON.generate(normalized)
      end

      def load(json)
        data = JSON.parse(json)
        raise PqcRails::Error, "the session cookie does not hold a JSON object" unless data.is_a?(Hash)

        data
      rescue JSON::ParserError
        raise PqcRails::Error, "the session cookie does not hold valid JSON"
      end

      # JSONで同じ形に戻らない値を持つ最上位のキー。Marshalで書く間に、:jsonへ切り替えられるかを知らせるために使う。
      def unsafe_keys(data)
        return [] unless data.is_a?(Hash)

        data.filter_map do |key, value|
          next key.to_s unless key.is_a?(String)

          begin
            key unless normalize(value, key) == value
          rescue PqcRails::Error
            key
          end
        end
      end

      def normalize(value, top_key)
        case value
        when String, Integer, true, false, nil then value
        when Symbol then value.to_s
        when Float
          raise PqcRails::Error, "the session value under #{top_key.inspect} is not a finite number" unless value.finite?

          value
        when Array then value.map { |item| normalize(item, top_key) }
        when Hash
          value.to_h do |key, item|
            unless key.is_a?(String)
              raise PqcRails::Error, "the session value under #{top_key.inspect} has a #{key.class} key; use strings"
            end

            [key, normalize(item, top_key)]
          end
        else
          raise PqcRails::Error,
                "the session value under #{top_key.inspect} is a #{value.class}, which JSON cannot hold; " \
                "store a string or number instead (session_serializer is :json)"
        end
      end
      private_class_method :normalize
    end
  end
end
