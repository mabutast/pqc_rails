# frozen_string_literal: true

require "active_record"
require "active_support/notifications"
require "rack/mock"

RSpec.describe "復号の失敗の通知(decryption_failed.pqc_rails)" do
  let(:keypair) { PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair } }
  let(:other_keypair) { PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair } }

  def capture_events
    events = []
    subscriber = ActiveSupport::Notifications.subscribe("decryption_failed.pqc_rails") do |*args|
      events << ActiveSupport::Notifications::Event.new(*args)
    end
    yield
    events
  ensure
    ActiveSupport::Notifications.unsubscribe(subscriber)
  end

  it "DBカラムの復号に失敗すると、target: :recordとエラーのクラス名を通知する" do
    cipher = PqcRails::Cipher.new(pq_alg_name: :ml_kem_512)
    message = cipher.encrypt("hello", key: keypair)

    events = capture_events do
      expect { cipher.decrypt(message, key: other_keypair) }.to raise_error(ActiveRecord::Encryption::Errors::Decryption)
    end

    expect(events.size).to eq(1)
    expect(events.first.payload).to include(target: :record, error: "PqcRails::Error")
  end

  it "pqc_railsの暗号文でない値(Rails標準の暗号文)や、pqc_railsの鍵が渡されない呼び出しでは通知しない" do
    cipher = PqcRails::Cipher.new(pq_alg_name: :ml_kem_512)
    rails_message = ActiveRecord::Encryption::Message.new(payload: "x").tap { |m| m.headers[:iv] = "y" }
    pqc_message = cipher.encrypt("hello", key: keypair)

    events = capture_events do
      expect { cipher.decrypt(rails_message, key: keypair) }.to raise_error(ActiveRecord::Encryption::Errors::Decryption)
      expect { cipher.decrypt(pqc_message, key: ["derived-secret"]) }
        .to raise_error(ActiveRecord::Encryption::Errors::Decryption)
    end

    expect(events).to be_empty
  end

  it "セッションCookieをどの鍵でも復号できないと、target: :sessionを通知する" do
    writer = PqcRails::Session::Encryptor.new(other_keypair, pq_alg_name: :ml_kem_512)
    app = ->(env) { [200, {}, [env["rack.session"]["user_id"].inspect]] }
    store = PqcRails::Session::PqcCookieStore.new(app, key: "_s", keypair: keypair, previous_keypairs: [],
                                                       pq_alg_name: :ml_kem_512)
    cookie = Rack::Utils.escape(writer.encrypt({ "user_id" => 1 }))

    events = capture_events do
      Rack::MockRequest.new(store).get("/", "HTTP_COOKIE" => "_s=#{cookie}")
    end

    expect(events.map { |event| event.payload[:target] }).to eq([:session])
  end

  it "Cookieが無いだけでは通知しない" do
    store = PqcRails::Session::PqcCookieStore.new(->(_env) { [200, {}, [""]] }, key: "_s", keypair: keypair,
                                                                             previous_keypairs: [])

    expect(capture_events { Rack::MockRequest.new(store).get("/") }).to be_empty
  end
end
