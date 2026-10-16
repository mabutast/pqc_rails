# frozen_string_literal: true

require "active_support/notifications"

module PqcRails
  class Error < StandardError; end

  # 復号に失敗したことを、ActiveSupport::Notificationsのdecryption_failed.pqc_railsイベントで通知する。
  # payloadはtarget(:record=DBカラム、:session=セッションCookie)とerror(例外のクラス名)。
  # 鍵の設定の誤りや、改ざんされた値の検知に使える。値・鍵・例外のメッセージは含めない。
  def self.instrument_decryption_failure(target:, error:)
    ActiveSupport::Notifications.instrument("decryption_failed.pqc_rails", target: target, error: error&.class&.name)
  end
end

require_relative "pqc_rails/version"
require_relative "pqc_rails/configuration"
require_relative "pqc_rails/algorithms"
require_relative "pqc_rails/ciphertext_format"
require_relative "pqc_rails/length_validation"
require_relative "pqc_rails/blob_packing"
require_relative "pqc_rails/key_source"
require_relative "pqc_rails/kem"
require_relative "pqc_rails/sig"
require_relative "pqc_rails/dh_kem"
require_relative "pqc_rails/envelope_cipher"
require_relative "pqc_rails/hybrid_kem"
require_relative "pqc_rails/session/encryptor"
require_relative "pqc_rails/session/key_manager"
require_relative "pqc_rails/session/pqc_cookie_store"
require_relative "pqc_rails/generators/install/install_generator"
require_relative "pqc_rails/cipher"
require_relative "pqc_rails/active_record/key_provider"
require_relative "pqc_rails/active_record/context"
require_relative "pqc_rails/active_record/ciphertext_info"
require_relative "pqc_rails/status_check"
require_relative "pqc_rails/railtie"

ActionDispatch::Session::PqcCookieStore = PqcRails::Session::PqcCookieStore
