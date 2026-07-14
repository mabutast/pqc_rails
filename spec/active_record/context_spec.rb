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

  describe "既存データの移行(dual-stack, docs/MIGRATION.md)" do
    let(:old_primary_key) { "s" * 32 }
    let(:legacy_widget_class) do
      Class.new(::ActiveRecord::Base) do
        self.table_name = "widgets"
        encrypts :secret
      end
    end
    let(:dual_stack_widget_class) do
      old_primary_key = self.old_primary_key
      Class.new(::ActiveRecord::Base) do
        self.table_name = "widgets"
        encrypts :secret, previous: [
          {
            cipher: ::ActiveRecord::Encryption::Cipher.new,
            key_provider: ::ActiveRecord::Encryption::DerivedSecretKeyProvider.new(old_primary_key)
          }
        ]
      end
    end

    it "pqc_rails導入前のAES-256-GCMデータをprevious:経由で読み出せ、新規書き込みはpqc_railsで暗号化される" do
      ::ActiveRecord::Encryption.configure(
        primary_key: old_primary_key,
        deterministic_key: "d" * 32,
        key_derivation_salt: "s" * 32
      )
      legacy = legacy_widget_class.create!(secret: "legacy plaintext") # pragma: allowlist secret

      ENV["PQC_RECORD_KEY"] = PqcRails::Session::KeyManager.encode(keypair)
      described_class.install!(pq_alg_name: :ml_kem_512)

      expect(dual_stack_widget_class.find(legacy.id).secret).to eq("legacy plaintext")

      fresh = dual_stack_widget_class.create!(secret: "new pqc plaintext") # pragma: allowlist secret
      raw = dual_stack_widget_class.connection.select_value("SELECT secret FROM widgets WHERE id = #{fresh.id}")

      expect(raw).not_to include("new pqc plaintext")
      expect(dual_stack_widget_class.find(fresh.id).secret).to eq("new pqc plaintext")
    end
  end

  describe ".install!" do
    after do
      ::ActiveRecord::Encryption.configure(primary_key: nil, deterministic_key: nil, key_derivation_salt: nil)
    end

    it "install!を呼ぶ前から設定されていたprimary_key等を保持する(黙ってnilに巻き戻さない)" do
      ::ActiveRecord::Encryption.configure(
        primary_key: "existing-primary-key",
        deterministic_key: "existing-deterministic-key",
        key_derivation_salt: "existing-salt"
      )

      described_class.install!(pq_alg_name: :ml_kem_512)

      expect(::ActiveRecord::Encryption.config.primary_key).to eq("existing-primary-key")
      expect(::ActiveRecord::Encryption.config.deterministic_key).to eq("existing-deterministic-key")
      expect(::ActiveRecord::Encryption.config.key_derivation_salt).to eq("existing-salt")
    end
  end
end
