# frozen_string_literal: true

require "active_record"
require "sqlite3"

RSpec.describe PqcRails::ActiveRecord::Context do
  before(:all) do
    ::ActiveRecord::Base.establish_connection(adapter: "sqlite3", database: ":memory:")
    ::ActiveRecord::Migration.verbose = false
    ::ActiveRecord::Schema.define do
      create_table :widgets do |t|
        t.string :secret
      end
    end
  end

  let(:keypair) { PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair } }
  let(:widget_class) do
    Class.new(::ActiveRecord::Base) do
      self.table_name = "widgets"
      encrypts :secret
    end
  end

  around do |example|
    original = ENV.fetch("PQC_RECORD_KEY", nil)
    ENV["PQC_RECORD_KEY"] = PqcRails::Session::KeyManager.encode(keypair)
    described_class.install!(pq_alg_name: :ml_kem_512)
    example.run
  ensure
    ENV["PQC_RECORD_KEY"] = original
  end

  it "encryptsで宣言した属性がPQCで暗号化されてDBに保存される(平文を含まない)" do
    widget = widget_class.create!(secret: "hello pqc")

    raw = widget_class.connection.select_value("SELECT secret FROM widgets WHERE id = #{widget.id}")

    expect(raw).not_to include("hello pqc")
  end

  it "読み出すと平文に戻る" do
    widget = widget_class.create!(secret: "hello pqc")

    expect(widget_class.find(widget.id).secret).to eq("hello pqc")
  end

  it "別のインストール(別の鍵ペア)で暗号化されたものは復号に失敗する" do
    widget = widget_class.create!(secret: "hello pqc")

    other_keypair = PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair }
    ENV["PQC_RECORD_KEY"] = PqcRails::Session::KeyManager.encode(other_keypair)
    described_class.install!(pq_alg_name: :ml_kem_512)

    expect { widget_class.find(widget.id).secret }.to raise_error(ActiveRecord::Encryption::Errors::Decryption)
  end

  it "DB内の値が壊れている場合はActiveRecord::Encryption::Errorsを送出する(クラッシュしない)" do
    widget = widget_class.create!(secret: "hello pqc")
    widget_class.connection.execute("UPDATE widgets SET secret = 'not-a-valid-message' WHERE id = #{widget.id}")

    expect { widget_class.find(widget.id).secret }.to raise_error(ActiveRecord::Encryption::Errors::Base)
  end
end
