# frozen_string_literal: true

require "json"
require "active_record"
require "sqlite3"

# 以前の版が書いた暗号文(spec/fixtures/compat/)を、今のコードで元の平文に戻せることを確かめる。
# 同じテストの中で書いて読むテストは、書く側と読む側の両方が同じように変わると通ってしまう
# (HKDFのinfoやヘッダーの並びを誤って変えた場合など)。固定の検査データは書いた時点の形のまま残るので、
# 利用者のDBやブラウザに残っている古いデータが読めなくなる変更をここで検出する。
# 検査データの作り方は script/generate-compat-fixtures を参照。検査データは作り直さない。
RSpec.describe "以前の版が書いた暗号文の読み込み(固定の検査データ)" do
  FIXTURE_DIR = File.expand_path("../fixtures/compat", __dir__)

  def self.load_fixture(name)
    JSON.parse(File.read(File.join(FIXTURE_DIR, name)))
  end

  before(:all) do
    ::ActiveRecord::Base.establish_connection(adapter: "sqlite3", database: ":memory:")
    ::ActiveRecord::Migration.verbose = false
    ::ActiveRecord::Schema.define do
      create_table(:compat_records, force: true) { |t| t.text :secret }
    end
  end

  let(:record_class) do
    Class.new(::ActiveRecord::Base) do
      self.table_name = "compat_records"
      encrypts :secret
    end
  end

  around do |example|
    original_key = ENV.fetch("PQC_RECORD_KEY", nil)
    original_previous = ENV.fetch("PQC_RECORD_PREVIOUS_KEYS", nil)
    example.run
  ensure
    ENV["PQC_RECORD_KEY"] = original_key
    ENV["PQC_RECORD_PREVIOUS_KEYS"] = original_previous
  end

  # 暗号化された値をそのままカラムに入れ、モデル経由で読む(利用者のDBに残っている値を読むのと同じ道筋)。
  def read_stored_value(record_fixture)
    ENV["PQC_RECORD_KEY"] = record_fixture.fetch("key")
    ENV["PQC_RECORD_PREVIOUS_KEYS"] = nil
    PqcRails::ActiveRecord::Context.install!

    connection = record_class.connection
    connection.execute("INSERT INTO compat_records (secret) VALUES (#{connection.quote(record_fixture.fetch('stored_value'))})")
    record_class.find(connection.select_value("SELECT MAX(id) FROM compat_records"))
  end

  def open_cookie(session_fixture)
    keypair = PqcRails::KeySource.decode(session_fixture.fetch("key"))
    PqcRails::Session::Encryptor.new(keypair).decrypt(session_fixture.fetch("cookie_value"))
  end

  [
    ["pqc_rails-0.3.0.json", 0],
    ["format-v1.json", 1]
  ].each do |file_name, format_version|
    context "#{file_name}(形式バージョン #{format_version})" do
      let(:fixture) { self.class.load_fixture(file_name) }

      it "検査データが想定した形式で書かれている" do
        info = PqcRails::ActiveRecord::CiphertextInfo.parse(fixture.dig("record", "stored_value"))
        cookie_first_byte = Base64.strict_decode64(fixture.dig("session", "cookie_value")).getbyte(0)

        expect(info.format_version).to eq(format_version)
        expect(cookie_first_byte).to eq(format_version)
      end

      it "DBカラムの暗号文を、今のコードで元の平文に戻せる" do
        record = read_stored_value(fixture.fetch("record"))

        expect(record.secret).to eq(fixture.dig("record", "plaintext"))
      end

      it "セッションCookieの暗号文を、今のコードで元のデータに戻せる" do
        expect(open_cookie(fixture.fetch("session"))).to eq(fixture.dig("session", "data"))
      end
    end
  end

  it "0.3.0の検査データの鍵は、認証鍵を持たない0.3.0の形式のまま残っている" do
    keypair = PqcRails::KeySource.decode(self.class.load_fixture("pqc_rails-0.3.0.json").dig("record", "key"))

    expect(keypair.authentication_key).to be_nil
  end
end
