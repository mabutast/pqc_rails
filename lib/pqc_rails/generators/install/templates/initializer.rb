# frozen_string_literal: true

# config/application.rb (または config/initializers/session_store.rb) で
# 以下を設定すると、セッションがPQC(ML-KEM + X25519のハイブリッド)で暗号化されます。
#
#   config.session_store :pqc_cookie_store
#
PqcRails.configure do |config|
  # config.liboqs_path = "/usr/local/lib/liboqs.dylib"
end
