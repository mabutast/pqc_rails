# frozen_string_literal: true

require "json"
require "active_record"
require "sqlite3"

# 以前の版が書いた暗号文(spec/fixtures/compat/)を、今のコードで元の平文に戻せることを確かめる。
# 同じテストの中で書いて読むテストは、書く側と読む側の両方が同じように変わると通ってしまう
# (HKDFのinfoやヘッダーの並びを誤って変えた場合など)。固定の検査データは書いた時点の形のまま残るので、
# 利用者のDBやブラウザに残っている古いデータが読めなくなる変更をここで検出する。
# 検査データの作り方は script/generate-compat-fixtures を参照。
RSpec.describe "以前の版が書いた暗号文の読み込み(固定の検査データ)" do
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

  # 旧形式の受け付けは既定(受け付ける)に固定する。ほかのspecの設定が残っていても結果が変わらないように。
  around do |example|
    configuration = PqcRails.configuration
    original = [ENV.fetch("PQC_RECORD_KEY", nil), ENV.fetch("PQC_RECORD_PREVIOUS_KEYS", nil),
                configuration.accept_legacy_records, configuration.accept_legacy_cookies_until]
    configuration.accept_legacy_records = true
    configuration.accept_legacy_cookies_until = nil
    example.run
  ensure
    ENV["PQC_RECORD_KEY"], ENV["PQC_RECORD_PREVIOUS_KEYS"] = original[0], original[1]
    configuration.accept_legacy_records = original[2]
    configuration.accept_legacy_cookies_until = original[3]
  end

  def new_key_value(pq_alg_name)
    PqcRails::KeySource.encode(PqcRails::HybridKem.open(pq_alg_name, &:generate_keypair))
  end

  # 暗号化された値をそのままカラムに入れ、モデル経由で読む(利用者のDBに残っている値を読むのと同じ道筋)。
  def read_stored_value(stored_value, current_key:, previous_keys: nil, pq_alg_name:)
    ENV["PQC_RECORD_KEY"] = current_key
    ENV["PQC_RECORD_PREVIOUS_KEYS"] = previous_keys
    PqcRails::ActiveRecord::Context.install!(pq_alg_name: pq_alg_name)

    connection = record_class.connection
    id = connection.insert("INSERT INTO compat_records (secret) VALUES (#{connection.quote(stored_value)})")
    record_class.find(id).secret
  end

  {
    "pqc_rails-0.3.0.json" => 0,
    "format-v1.json" => 1
  }.each do |file_name, format_version|
    context "#{file_name}(形式バージョン #{format_version})" do
      let(:fixture) { JSON.parse(File.read(File.expand_path("../fixtures/compat/#{file_name}", __dir__))) }
      let(:pq_alg_name) { fixture.fetch("pq_alg_name").to_sym }
      let(:record_values) { fixture.dig("record", "values") }

      # 検査データを作り直して形が変わった時に、ここで気付けるようにする。
      it "検査データが想定した形式で書かれている(圧縮した値を含む)" do
        infos = record_values.map { |value| PqcRails::ActiveRecord::CiphertextInfo.parse(value.fetch("stored_value")) }
        compressed = record_values.map { |value| JSON.parse(value.fetch("stored_value")).dig("h", "c") }
        cookie_first_byte = Base64.strict_decode64(fixture.dig("session", "cookie_value")).getbyte(0)
        keypair = PqcRails::KeySource.decode(fixture.dig("record", "key"))

        expect(infos.map(&:format_version)).to all(eq(format_version))
        expect(compressed).to include(true)
        expect(cookie_first_byte).to eq(format_version)
        expect(keypair.authentication_key.nil?).to eq(format_version.zero?)
      end

      it "DBカラムの暗号文を、今のコードで元の平文に戻せる" do
        record_values.each do |value|
          decrypted = read_stored_value(value.fetch("stored_value"), current_key: fixture.dig("record", "key"),
                                                                     pq_alg_name: pq_alg_name)

          expect(decrypted).to eq(value.fetch("plaintext"))
        end
      end

      # 鍵をローテーションした後(新しい鍵が現在、検査データの鍵が旧鍵)に、古いレコードを読む道筋。
      # 0.3.0からの更新手順(docs/MIGRATION.md)は、この状態を通る。
      it "検査データの鍵を旧鍵にしても、DBカラムの暗号文を元の平文に戻せる" do
        record_values.each do |value|
          decrypted = read_stored_value(value.fetch("stored_value"), current_key: new_key_value(pq_alg_name),
                                                                     previous_keys: fixture.dig("record", "key"),
                                                                     pq_alg_name: pq_alg_name)

          expect(decrypted).to eq(value.fetch("plaintext"))
        end
      end

      it "セッションCookieの暗号文を、今のコードで元のデータに戻せる" do
        session = fixture.fetch("session")
        encryptor = PqcRails::Session::Encryptor.new(PqcRails::KeySource.decode(session.fetch("key")),
                                                     pq_alg_name: pq_alg_name)

        expect(encryptor.decrypt(session.fetch("cookie_value"))).to eq(session.fetch("data"))
      end
    end
  end
end
