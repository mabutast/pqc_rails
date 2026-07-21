# frozen_string_literal: true

require "rack"
require "action_dispatch"

RSpec.describe PqcRails::Session::PqcCookieStore do
  let(:keypair) { PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair } }
  let(:session_key) { "_pqc_test_session" }

  def build_app(keypair, session_key, previous_keypairs: [])
    inner = lambda do |env|
      session = env["rack.session"]
      request = Rack::Request.new(env)

      session["user_id"] = 42 if request.path == "/write"

      [200, {}, [(session["user_id"] || "none").to_s]]
    end

    Rack::Builder.new do
      use ActionDispatch::Cookies
      use PqcRails::Session::PqcCookieStore, key: session_key, keypair: keypair,
                                              previous_keypairs: previous_keypairs, pq_alg_name: :ml_kem_512
      run inner
    end.to_app
  end

  describe "Cookieへの書き込み" do
    it "セッション値がPQC暗号化された不透明な値としてSet-Cookieに書き込まれる" do
      app = build_app(keypair, session_key)

      response = Rack::MockRequest.new(app).get("/write")

      set_cookie = response.headers["Set-Cookie"]
      expect(set_cookie).to be_a(String)
      expect(set_cookie).not_to include("user_id")
    end
  end

  describe "Cookieからの復号" do
    it "書き込まれたCookieを次のリクエストで送ると元のセッション値が復元される" do
      app = build_app(keypair, session_key)

      first_response = Rack::MockRequest.new(app).get("/write")
      cookie_header = first_response.headers["Set-Cookie"].split(";").first

      second_response = Rack::MockRequest.new(app).get("/read", "HTTP_COOKIE" => cookie_header)

      expect(second_response.body).to eq("42")
    end
  end

  describe "不正なCookie" do
    it "改竄・不正な値が送られてもクラッシュせず空セッションとして扱う" do
      app = build_app(keypair, session_key)

      response = Rack::MockRequest.new(app).get("/read", "HTTP_COOKIE" => "#{session_key}=not-a-valid-blob")

      expect(response.status).to eq(200)
      expect(response.body).to eq("none")
    end
  end

  describe "鍵ローテーション(previous_keypairs)" do
    it "旧鍵で書かれたCookieもprevious_keypairsに旧鍵を渡せば復号できる" do
      old_keypair = keypair
      new_keypair = PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair }

      old_app = build_app(old_keypair, session_key)
      write_response = Rack::MockRequest.new(old_app).get("/write")
      cookie_header = write_response.headers["Set-Cookie"].split(";").first

      rotated_app = build_app(new_keypair, session_key, previous_keypairs: [old_keypair])
      read_response = Rack::MockRequest.new(rotated_app).get("/read", "HTTP_COOKIE" => cookie_header)

      expect(read_response.body).to eq("42")
    end

    it "previous_keypairsから旧鍵を外すと、その鍵で書かれたCookieはもう復号できない(自然失効後の想定)" do
      old_keypair = keypair
      new_keypair = PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair }

      old_app = build_app(old_keypair, session_key)
      write_response = Rack::MockRequest.new(old_app).get("/write")
      cookie_header = write_response.headers["Set-Cookie"].split(";").first

      rotated_app = build_app(new_keypair, session_key, previous_keypairs: [])
      read_response = Rack::MockRequest.new(rotated_app).get("/read", "HTTP_COOKIE" => cookie_header)

      expect(read_response.body).to eq("none")
    end

    it "previous_keypairsを渡さない場合、KeyManager.previous_keypairsから読み込む" do
      old_keypair = keypair
      new_keypair = PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair }

      old_app = build_app(old_keypair, session_key)
      write_response = Rack::MockRequest.new(old_app).get("/write")
      cookie_header = write_response.headers["Set-Cookie"].split(";").first

      allow(PqcRails::Session::KeyManager).to receive(:previous_keypairs).and_return([old_keypair])
      inner = ->(env) { [200, {}, [(env["rack.session"]["user_id"] || "none").to_s]] }
      key = session_key
      app = Rack::Builder.new do
        use ActionDispatch::Cookies
        use PqcRails::Session::PqcCookieStore, key: key, keypair: new_keypair, pq_alg_name: :ml_kem_512
        run inner
      end.to_app

      read_response = Rack::MockRequest.new(app).get("/read", "HTTP_COOKIE" => cookie_header)

      expect(read_response.body).to eq("42")
    end
  end

  describe "鍵が見つからない場合" do
    it "ENVにもRails.application.credentialsにも鍵が無い場合、初期化時にMissingKeyErrorを送出する" do
      ENV.delete(PqcRails::Session::KeyManager::ENV_VAR)
      allow(Rails).to receive(:application).and_return(nil)

      expect do
        described_class.new(->(env) { [200, {}, [""]] })
      end.to raise_error(PqcRails::MissingKeyError)
    end
  end
end
