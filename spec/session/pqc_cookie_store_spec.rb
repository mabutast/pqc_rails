# frozen_string_literal: true

require "rack"
require "action_dispatch"
require "action_dispatch/middleware/flash"

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

  describe "継承とメソッド解決" do
    it "ActionDispatch::Session::CookieStoreを継承している" do
      expect(described_class.ancestors).to include(ActionDispatch::Session::CookieStore)
    end

    it "set_cookie/get_cookieはRailsのCookieStoreではなく自身の実装が使われる" do
      expect(described_class.instance_method(:set_cookie).owner).to eq(described_class)
      expect(described_class.instance_method(:get_cookie).owner).to eq(described_class)
    end
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

    it "session_serializerが:jsonでも、セッションIDとフラッシュを含めて次のリクエストで復元される" do
      inner = lambda do |env|
        request = ActionDispatch::Request.new(env)
        if request.path == "/write"
          request.session[:user_id] = 42
          request.flash[:notice] = "saved"
        end
        body = "#{request.session[:user_id]}:#{request.flash[:notice]}"
        request.commit_flash
        [200, {}, [body]]
      end
      store_keypair = keypair
      app = Rack::Builder.new do
        use ActionDispatch::Cookies
        use PqcRails::Session::PqcCookieStore, key: "_json_session", keypair: store_keypair, pq_alg_name: :ml_kem_512
        run inner
      end.to_app
      PqcRails.configuration.session_serializer = :json

      first = Rack::MockRequest.new(app).get("/write")
      cookie = first.headers["Set-Cookie"].split(";").first
      second = Rack::MockRequest.new(app).get("/read", "HTTP_COOKIE" => cookie)

      expect(Base64.strict_decode64(Rack::Utils.unescape(cookie.split("=", 2).last)).getbyte(0)).to eq(2)
      expect(second.body).to eq("42:saved")
    ensure
      PqcRails.configuration.session_serializer = :marshal
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

  describe "旧形式(v0)のCookie" do
    let(:old_keypair) { PqcRails::HybridKem::Keypair.new(keypair.public_key, keypair.secret_key) }
    let(:new_keypair) { PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair } }

    around do |example|
      original = [PqcRails.configuration.ciphertext_format, PqcRails.configuration.accept_legacy_cookies_until]
      example.run
    ensure
      PqcRails.configuration.ciphertext_format, PqcRails.configuration.accept_legacy_cookies_until = original
    end

    def legacy_cookie(old_keypair, session_key)
      PqcRails.configuration.ciphertext_format = :v0
      response = Rack::MockRequest.new(build_app(old_keypair, session_key)).get("/write")
      PqcRails.configuration.ciphertext_format = :v1
      response.headers["Set-Cookie"].split(";").first
    end

    def read_body(app, cookie)
      response = Rack::MockRequest.new(app).get("/read", "HTTP_COOKIE" => cookie)
      expect(response.status).to eq(200)
      response.body
    end

    it "鍵ローテーション中、旧鍵宛の旧形式のCookieは期限内なら読め、期限後と未設定では空セッションになる" do
      cookie = legacy_cookie(old_keypair, session_key)
      app = build_app(new_keypair, session_key, previous_keypairs: [old_keypair])

      PqcRails.configuration.accept_legacy_cookies_until = Time.now + 60
      expect(read_body(app, cookie)).to eq("42")
      [Time.now - 60, nil].each do |deadline|
        PqcRails.configuration.accept_legacy_cookies_until = deadline
        expect(read_body(app, cookie)).to eq("none")
      end
    end

    it "認証鍵を持つ鍵宛の旧形式のCookieは、期限内でも例外にならず空セッションになる" do
      cookie = legacy_cookie(old_keypair, session_key)
      PqcRails.configuration.accept_legacy_cookies_until = Time.now + 60

      expect(read_body(build_app(keypair, session_key), cookie)).to eq("none")
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

    it "複数世代の旧鍵をprevious_keypairsに渡せば、最も古い世代で書かれたCookieも復号できる" do
      gen_a = keypair
      gen_b = PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair }
      gen_c = PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair }

      gen_a_app = build_app(gen_a, session_key)
      write_response = Rack::MockRequest.new(gen_a_app).get("/write")
      cookie_header = write_response.headers["Set-Cookie"].split(";").first

      current_app = build_app(gen_c, session_key, previous_keypairs: [gen_b, gen_a])
      read_response = Rack::MockRequest.new(current_app).get("/read", "HTTP_COOKIE" => cookie_header)

      expect(read_response.body).to eq("42")
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
