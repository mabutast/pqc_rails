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
    class PqcCookieStore < ActionDispatch::Session::CookieStore
      def initialize(app, options = {})
        keypair = options.delete(:keypair) || KeyManager.keypair
        pq_alg_name = options.delete(:pq_alg_name) || Encryptor::DEFAULT_PQ_ALG_NAME
        @encryptor = Encryptor.new(keypair, pq_alg_name: pq_alg_name)
        super(app, options)
      end

      private

      def set_cookie(request, _session_id, cookie)
        cookie[:value] = @encryptor.encrypt(cookie[:value])
        request.cookie_jar[@key] = cookie
      end

      def get_cookie(request)
        raw = request.cookie_jar[@key]
        return nil if raw.nil?

        @encryptor.decrypt(raw)
      rescue StandardError
        # 改竄・不正なCookieはクラッシュさせず空セッションとして扱う。
        # Railsの署名/暗号化クッキージャーが復号失敗時にnilを返す挙動に揃えている。
        nil
      end
    end
  end
end
