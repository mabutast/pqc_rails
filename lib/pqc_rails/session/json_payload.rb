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
      # 入れ子の深さの上限。自分自身を含む配列・ハッシュで再帰が終わらないことを防ぎ、
      # JSONの既定の上限(100段)より先にPqcRails::Errorにする。
      MAX_DEPTH = 64

      # unsafe_keysでUTF-8にできないキーを知らせる時の名前。キーのバイト列そのものは出さない。
      INVALID_KEY_NAME = "(a key that is not a valid UTF-8 string)"

      module_function

      def dump(data)
        raise PqcRails::Error, "the session must be a Hash with string keys, got #{data.class}" unless data.is_a?(Hash)

        normalized = data.to_h do |key, value|
          raise PqcRails::Error, "session keys must be strings, got #{key.class}" unless key.is_a?(String)

          key = utf8_key(key)
          [key, normalize(value, key)]
        end
        JSON.generate(normalized)
      end

      def load(json)
        data = JSON.parse(json)
        raise PqcRails::Error, "the session cookie does not hold a JSON object" unless data.is_a?(Hash)

        data
      rescue JSON::ParserError
        # JSON::ParserErrorのメッセージは入力の一部(復号したCookieの中身)を含むので、原因として残さない。
        raise PqcRails::Error, "the session cookie does not hold valid JSON", cause: nil
      end

      # JSONで同じ形に戻らない値を持つ最上位のキー。Marshalで書く間に、:jsonへ切り替えられるかを知らせるために使う。
      def unsafe_keys(data)
        return [] unless data.is_a?(Hash)

        data.filter_map do |key, value|
          next key.to_s unless key.is_a?(String)

          begin
            next key unless utf8_key(key).equal?(key)
          rescue PqcRails::Error
            next INVALID_KEY_NAME
          end

          begin
            key unless normalize(value, key) == value
          rescue PqcRails::Error
            key
          end
        end
      end

      def normalize(value, top_key, depth = 1)
        if depth > MAX_DEPTH
          raise PqcRails::Error, "the session value under #{top_key.inspect} is nested more than #{MAX_DEPTH} levels"
        end

        case value
        when String then utf8(value, top_key)
        when Integer, true, false, nil then value
        when Symbol then value.to_s
        when Float
          raise PqcRails::Error, "the session value under #{top_key.inspect} is not a finite number" unless value.finite?

          value
        when Array then value.map { |item| normalize(item, top_key, depth + 1) }
        when Hash
          value.to_h do |key, item|
            unless key.is_a?(String)
              raise PqcRails::Error, "the session value under #{top_key.inspect} has a #{key.class} key; use strings"
            end

            [utf8_key(key, top_key), normalize(item, top_key, depth + 1)]
          end
        else
          raise PqcRails::Error,
                "the session value under #{top_key.inspect} is a #{value.class}, which JSON cannot hold; " \
                "store a string or number instead (session_serializer is :json)"
        end
      end
      private_class_method :normalize

      def utf8(value, top_key)
        to_utf8(value) { "the session value under #{top_key.inspect} is not a valid UTF-8 string" }
      end
      private_class_method :utf8

      # キーも値と同じくUTF-8にそろえる。UTF-8にできないキーは、メッセージにキーを出さない。
      # top_keyは、入れ子のハッシュのキーの時に、それを含む最上位のキー(UTF-8であることを確かめ済み)。
      def utf8_key(key, top_key = nil)
        to_utf8(key) do
          if top_key
            "the session value under #{top_key.inspect} has a key that is not a valid UTF-8 string"
          else
            "a session key is not a valid UTF-8 string"
          end
        end
      end
      private_class_method :utf8_key

      # JSONはUTF-8の文字列だけを書ける。UTF-8に変換できない文字列(バイナリ、UTF-8と名乗る不正なバイト列)は、
      # 文字列を出さずにエラーにする。UTF-8と名乗る文字列は、同じ文字コードへのencodeが検査をしないので、変換の後にも確かめる。
      # EncodingError・JSONのエラーは変換できなかったバイト(セッションの値・キーの一部)を含むので、原因として残さない。
      def to_utf8(string)
        return string if string.valid_encoding? && (string.encoding == Encoding::UTF_8 || string.ascii_only?)

        converted = string.encode(Encoding::UTF_8)
        return converted if converted.valid_encoding?

        raise PqcRails::Error, yield, cause: nil
      rescue EncodingError
        raise PqcRails::Error, yield, cause: nil
      end
      private_class_method :to_utf8
    end
  end
end
