# frozen_string_literal: true

require "action_dispatch"
require_relative "encryptor"
require_relative "key_manager"

module PqcRails
  module Session
    # ActionDispatch::Session::CookieStoreを継承し、Railsのsecret_key_baseによる
    # AES暗号化(signed_or_encryptedクッキージャー)を使わず、HybridKem(PQC)で
    # セッション内容そのものを暗号化する。
    #
    # set_cookie/get_cookieはCookieStoreがRailsの暗号化クッキージャーへの委譲点として
    # 用意しているprivateな拡張点(Rails 7.1〜8.1で同一シグネチャ)。ここを上書きして
    # 生のcookie_jar(署名・暗号化なし)に対してEncryptorで暗号化した文字列を直接書き込む。
    # AEAD(AES-256-GCM)が改竄検知も兼ねるため、Railsの署名は不要。
    #
    # 鍵ローテーション対応: 書き込みは常に現行鍵(@encryptor)のみを使う。読み込みは
    # 現行鍵で失敗した場合、previous_keypairs(鍵ローテーション前の旧鍵)で順に再試行する。
    # previous_keypairsはDB側のようにprevious:機構で永続する必要はなく、ローテーション後
    # 発行済みの旧セッションCookieが自然に失効するまでの一時的な設定という位置づけ。
    class PqcCookieStore < ActionDispatch::Session::CookieStore
      def initialize(app, options = {})
        keypair = options.delete(:keypair) || KeyManager.keypair
        previous_keypairs = options.delete(:previous_keypairs) || KeyManager.previous_keypairs
        pq_alg_name = options.delete(:pq_alg_name) || Encryptor::DEFAULT_PQ_ALG_NAME
        @encryptor = Encryptor.new(keypair, pq_alg_name: pq_alg_name)
        @previous_encryptors = previous_keypairs.map { |kp| Encryptor.new(kp, pq_alg_name: pq_alg_name) }
        super(app, options)
      end

      private

      def set_cookie(request, _session_id, cookie)
        cookie[:value] = @encryptor.encrypt(cookie[:value])
        request.cookie_jar[@key] = cookie
      end

      # 現行鍵→旧鍵世代の順に復号を試す(鍵ローテーション対応)。全て失敗、または
      # そもそもCookieが無い場合はnilを返し、改竄・不正なCookieと同様に空セッションとして扱う。
      # Railsの署名/暗号化クッキージャーが復号失敗時にnilを返す挙動に揃えている。
      def get_cookie(request)
        raw = request.cookie_jar[@key]
        return nil if raw.nil?

        [@encryptor, *@previous_encryptors].each do |encryptor|
          return encryptor.decrypt(raw)
        rescue StandardError
          next
        end

        nil
      end
    end
  end
end
