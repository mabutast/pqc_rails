# frozen_string_literal: true

require "active_record"
require "sqlite3"

RSpec.describe PqcRails::ActiveRecord::CiphertextInfo do
  before(:all) do
    ::ActiveRecord::Base.establish_connection(adapter: "sqlite3", database: ":memory:")
    ::ActiveRecord::Migration.verbose = false
    ::ActiveRecord::Schema.define do
      create_table :info_widgets do |t|
        t.string :secret
      end
    end
  end

  let(:keypair) { PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair } }
  let(:widget_class) do
    Class.new(::ActiveRecord::Base) do
      self.table_name = "info_widgets"
      encrypts :secret
    end
  end

  around do |example|
    original_key = ENV.fetch("PQC_RECORD_KEY", nil)
    original_format = PqcRails.configuration.ciphertext_format
    ENV["PQC_RECORD_KEY"] = PqcRails::KeySource.encode(keypair)
    PqcRails::ActiveRecord::Context.install!(pq_alg_name: :ml_kem_512)
    example.run
  ensure
    ENV["PQC_RECORD_KEY"] = original_key
    PqcRails.configuration.ciphertext_format = original_format
  end

  describe ".parse" do
    it "新しい形式の暗号文から、形式バージョン・アルゴリズムID・鍵IDを復号せずに読む" do
      widget = widget_class.create!(secret: "hello") # pragma: allowlist secret

      info = described_class.parse(widget.ciphertext_for(:secret))

      expect(info.format_version).to eq(1)
      expect(info.algorithm_id).to eq("X25519+ML-KEM-512")
      expect(info.key_id).to eq(PqcRails::CiphertextFormat.key_id(keypair.public_key))
      expect(info).to be_pqc
      expect(info).not_to be_legacy
    end

    it "0.3.0以前の形式の暗号文は、形式バージョン0(legacy)として読む" do
      PqcRails.configuration.ciphertext_format = :v0
      widget = widget_class.create!(secret: "hello") # pragma: allowlist secret

      info = described_class.parse(widget.ciphertext_for(:secret))

      expect(info.format_version).to eq(0)
      expect(info.algorithm_id).to be_nil
      expect(info.key_id).to be_nil
      expect(info).to be_legacy
    end

    it "pqc_rails以外(Rails標準のAES-256-GCM等)の暗号文は、pqc?がfalseになる" do
      message = ActiveRecord::Encryption::Message.new(payload: "x").tap { |m| m.headers[:iv] = "y" }
      serialized = ActiveRecord::Encryption::MessageSerializer.new.dump(message)

      info = described_class.parse(serialized)

      expect(info).not_to be_pqc
      expect(info.format_version).to be_nil
    end

    it "暗号文として読めない値(平文のまま残っている値など)はnilを返す" do
      expect(described_class.parse("plain text")).to be_nil
      expect(described_class.parse(nil)).to be_nil
    end
  end
end
