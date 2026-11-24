# frozen_string_literal: true

require "spec_helper"
require "pqc_rails/session/encryptor"

RSpec.describe PqcRails::Session::Encryptor, "session_serializer" do
  let(:keypair) { PqcRails::HybridKem.open(:ml_kem_512, &:generate_keypair) }
  let(:encryptor) { described_class.new(keypair, pq_alg_name: :ml_kem_512) }
  let(:config) { PqcRails.configuration }

  around do |example|
    saved = %i[session_serializer accept_marshal_cookies_until ciphertext_format accept_legacy_cookies_until]
            .to_h { |name| [name, config.public_send(name)] }
    example.run
  ensure
    saved.each { |name, value| config.public_send("#{name}=", value) }
  end

  def bytes_of(blob) = Base64.strict_decode64(blob)

  def with_json
    config.session_serializer = :json
    yield
  ensure
    config.session_serializer = :marshal
  end

  def events_during(&)
    events = []
    callback = ->(*args) { events << ActiveSupport::Notifications::Event.new(*args).payload }
    ActiveSupport::Notifications.subscribed(callback, "session_not_json_safe.pqc_rails", &)
    events
  end

  describe "設定" do
    it "既定は:marshalで、:jsonも受け付ける" do
      expect(PqcRails::Configuration.new.session_serializer).to eq(:marshal)
      expect(PqcRails::Configuration.new.accept_marshal_cookies_until).to be_nil
      config.session_serializer = :json
      expect(config.session_serializer).to eq(:json)
    end

    it "それ以外の値はArgumentErrorを送出する" do
      [:yaml, "json", nil].each do |value|
        expect { config.session_serializer = value }.to raise_error(ArgumentError, /session_serializer/)
      end
      ["2027-01-01", Date.new(2027, 1, 1), 0].each do |value|
        expect { config.accept_marshal_cookies_until = value }.to raise_error(ArgumentError, /accept_marshal/)
      end
    end
  end

  describe ":marshalで書く時" do
    it "形式v1で書き、Timeも往復する" do
      time = Time.at(1_700_000_000)
      blob = encryptor.encrypt({ "at" => time })

      expect(bytes_of(blob).getbyte(0)).to eq(1)
      expect(encryptor.decrypt(blob)).to eq({ "at" => time })
    end

    it "JSONに入る値だけならイベントを出さない" do
      events = events_during { encryptor.encrypt({ "user_id" => 1, "flash" => { "notice" => ["ok"] } }) }

      expect(events).to be_empty
    end

    it "JSONで同じ形に戻らない値は、最上位のキーの名前だけをイベントで知らせ、書き込みは成功する" do
      session = { "ok" => 1, "at" => Time.at(0), "nested" => { "role" => :admin }, :sym_key => 1,
                  "list" => [1, Object.new] }
      blob = nil
      events = events_during { blob = encryptor.encrypt(session) }

      expect(events).to eq([{ keys: %w[at nested sym_key list] }])
      expect(encryptor.decrypt(blob).keys).to eq(session.keys)
    end

    it "UTF-8にできない文字列・自分自身を含む値も、落ちずにキーの名前を知らせる" do
      cyclic = []
      cyclic << cyclic
      session = { "bin" => "\xFF".b, "cyclic" => cyclic, "ok" => "fine" }
      events = events_during { encryptor.encrypt(session) }

      expect(events).to eq([{ keys: %w[bin cyclic] }])
    end
  end

  describe ":jsonで書く時" do
    it "形式v2で書き、v1と同じヘッダーの並びを持つ" do
      bytes = with_json { bytes_of(encryptor.encrypt({ "user_id" => 1 })) }
      algorithm_id = "X25519+ML-KEM-512"

      expect(bytes.getbyte(0)).to eq(2)
      expect(bytes.getbyte(1)).to eq(algorithm_id.bytesize)
      expect(bytes[2, algorithm_id.bytesize]).to eq(algorithm_id)
      expect(bytes[2 + algorithm_id.bytesize, 2].unpack1("H4")).to eq(PqcRails::CiphertextFormat.key_id(keypair.public_key))
    end

    it "JSONに入る値は同じ形で往復し、シンボルの値は文字列になる" do
      session = { "s" => "x", "i" => 2**70, "f" => 1.5, "t" => true, "n" => nil, "empty" => {},
                  "list" => [1, [nil, :a]], "h" => { "role" => :admin } }
      expected = session.merge("list" => [1, [nil, "a"]], "h" => { "role" => "admin" })

      with_json do
        expect(encryptor.decrypt(encryptor.encrypt(session))).to eq(expected)
        expect(encryptor.decrypt(encryptor.encrypt({}))).to eq({})
      end
    end

    it "JSONに入らない値はPqcRails::Errorにし、メッセージに値を出さない" do
      marker = "value-that-must-not-appear"
      custom = Struct.new(:token).new(marker)
      [
        { "at" => Time.at(0) }, { "deep" => { "list" => [Time.at(0)] } }, { sym: 1 }, { "h" => { sym: 1 } },
        { "h" => { 1 => marker } }, { "nan" => Float::NAN }, { "inf" => -Float::INFINITY },
        { "obj" => custom }, { "d" => Date.new(2026, 1, 1) }
      ].each do |session|
        with_json do
          expect { encryptor.encrypt(session) }.to raise_error(PqcRails::Error) { |e| expect(e.message).not_to include(marker) }
        end
      end
    end

    it "UTF-8にできない文字列・深すぎる入れ子・自分自身を含む値は、値を出さずにPqcRails::Errorにする" do
      marker = "value\xFFthat-must-not-appear".b
      cyclic = []
      cyclic << cyclic
      deep = 70.times.reduce("x") { |inner, _| [inner] }
      [{ "bin" => marker }, { "deep" => deep }, { "cyclic" => cyclic }].each do |session|
        with_json do
          expect { encryptor.encrypt(session) }
            .to raise_error(PqcRails::Error) { |e| expect(e.message.b).not_to include("must-not-appear") }
        end
      end
    end

    it "UTF-8以外の文字コードでも、UTF-8にできる文字列はUTF-8で保存する" do
      sjis = "日本語".encode(Encoding::Shift_JIS)

      with_json { expect(encryptor.decrypt(encryptor.encrypt({ "s" => sjis, "ascii" => "abc".b }))).to eq({ "s" => "日本語", "ascii" => "abc" }) }
    end

    it "最上位がHashでなければPqcRails::Errorにする" do
      with_json { expect { encryptor.encrypt([1]) }.to raise_error(PqcRails::Error, /Hash/) }
    end

    it "ciphertext_formatが:v0の間は書けない" do
      config.ciphertext_format = :v0
      legacy = described_class.new(PqcRails::HybridKem::Keypair.new(keypair.public_key, keypair.secret_key),
                                   pq_alg_name: :ml_kem_512)

      with_json { expect { legacy.encrypt({ "a" => 1 }) }.to raise_error(PqcRails::Error, /:v0/) }
    end
  end

  describe "読み込み" do
    let(:v1_blob) { encryptor.encrypt({ "user_id" => 1 }) }
    let(:v2_blob) { with_json { encryptor.encrypt({ "user_id" => 2 }) } }

    it "v2はどちらの設定でも読む" do
      blob = v2_blob
      expect(encryptor.decrypt(blob)).to eq({ "user_id" => 2 })
      with_json { expect(encryptor.decrypt(blob)).to eq({ "user_id" => 2 }) }
    end

    it ":jsonの間も、未知の形式バージョンは形式のエラーにする" do
      bytes = bytes_of(v1_blob).tap { |b| b.setbyte(0, 3) }

      with_json { expect { encryptor.decrypt(Base64.strict_encode64(bytes)) }.to raise_error(PqcRails::Error, /format version/) }
    end

    it "v2はMarshal.loadを通らない" do
      blob = v2_blob
      expect(Marshal).not_to receive(:load)

      encryptor.decrypt(blob)
    end

    it ":jsonの間、Marshalで書いたv1は期限内(期限ちょうどを含む)だけ読む" do
      blob = v1_blob
      now = Time.now
      allow(Time).to receive(:now).and_return(now)

      with_json do
        expect { encryptor.decrypt(blob) }.to raise_error(PqcRails::Error, /accept_marshal_cookies_until/)
        config.accept_marshal_cookies_until = now - 1
        expect { encryptor.decrypt(blob) }.to raise_error(PqcRails::Error, /accept_marshal_cookies_until/)
        config.accept_marshal_cookies_until = now
        expect(encryptor.decrypt(blob)).to eq({ "user_id" => 1 })
      end
    end

    it ":jsonの間、Marshalを読まない時はMarshal.loadに届かない" do
      blob = v1_blob
      expect(Marshal).not_to receive(:load)

      with_json { expect { encryptor.decrypt(blob) }.to raise_error(PqcRails::Error) }
    end

    it ":jsonの間、v0はMarshalの期限と旧形式の条件の両方が要る" do
      legacy_keypair = PqcRails::HybridKem::Keypair.new(keypair.public_key, keypair.secret_key)
      legacy = described_class.new(legacy_keypair, pq_alg_name: :ml_kem_512)
      config.ciphertext_format = :v0
      blob = legacy.encrypt({ "user_id" => 0 })
      config.ciphertext_format = :v1

      with_json do
        config.accept_legacy_cookies_until = Time.now + 3600
        expect { legacy.decrypt(blob) }.to raise_error(PqcRails::Error, /accept_marshal_cookies_until/)
        config.accept_marshal_cookies_until = Time.now + 3600
        expect(legacy.decrypt(blob)).to eq({ "user_id" => 0 })
        config.accept_legacy_cookies_until = nil
        expect { legacy.decrypt(blob) }.to raise_error(PqcRails::Error, /legacy/)
      end
    end

    it "版の1バイトを書き換えたv1・v2は復号できない" do
      v1 = bytes_of(v1_blob).tap { |bytes| bytes.setbyte(0, 2) }
      v2 = bytes_of(v2_blob).tap { |bytes| bytes.setbyte(0, 1) }

      expect(Marshal).not_to receive(:load)
      expect { encryptor.decrypt(Base64.strict_encode64(v1)) }.to raise_error(PqcRails::Error)
      expect { encryptor.decrypt(Base64.strict_encode64(v2)) }.to raise_error(PqcRails::Error)
    end

    it "v2の中身が壊れたJSON・Hashでない値ならPqcRails::Errorにする" do
      expect { PqcRails::Session::JsonPayload.load("{not json") }.to raise_error(PqcRails::Error, /valid JSON/)
      ["[1]", "\"s\"", "null", "1"].each do |json|
        expect { PqcRails::Session::JsonPayload.load(json) }.to raise_error(PqcRails::Error, /JSON object/)
      end
    end
  end
end
