# frozen_string_literal: true

require_relative "../support/test_database"

RSpec.describe PqcRails::ActiveRecord::Context do
  before(:all) do
    TestDatabase.connect
    ::ActiveRecord::Migration.verbose = false
    ::ActiveRecord::Schema.define do
      create_table :widgets, force: true do |t|
        t.text :secret
        t.binary :payload
      end
    end
  end

  let(:keypair) { PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair } }
  let(:widget_class) do
    Class.new(::ActiveRecord::Base) do
      self.table_name = "widgets"
      encrypts :secret
      encrypts :payload
    end
  end

  around do |example|
    original = ENV.fetch("PQC_RECORD_KEY", nil)
    ENV["PQC_RECORD_KEY"] = PqcRails::KeySource.encode(keypair)
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

  it "install!に渡したkey_providerを使う" do
    provider = PqcRails::ActiveRecord::KeyProvider.new
    described_class.install!(pq_alg_name: :ml_kem_512, key_provider: provider)

    expect(::ActiveRecord::Encryption.key_provider).to equal(provider)
    expect(PqcRails::ActiveRecord::KeyProvider.installed).to equal(provider)
  end

  it "読み出すと平文に戻る" do
    widget = widget_class.create!(secret: "hello pqc")

    expect(widget_class.find(widget.id).secret).to eq("hello pqc")
  end

  it "binary型の属性は、UTF-8として不正なバイト列もそのまま読み出す" do
    bytes = "\xFF\x00\xE6\x97".b * 100
    widget = widget_class.create!(payload: bytes)

    payload = widget_class.find(widget.id).payload

    expect(payload.encoding).to eq(Encoding::BINARY)
    expect(payload).to eq(bytes)
  end

  it "別のインストール(別の鍵ペア)で暗号化されたものは復号に失敗する" do
    widget = widget_class.create!(secret: "hello pqc")

    other_keypair = PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair }
    ENV["PQC_RECORD_KEY"] = PqcRails::KeySource.encode(other_keypair)
    described_class.install!(pq_alg_name: :ml_kem_512)

    expect { widget_class.find(widget.id).secret }.to raise_error(ActiveRecord::Encryption::Errors::Decryption)
  end

  it "DB内の値が壊れている場合はActiveRecord::Encryption::Errorsを送出する(クラッシュしない)" do
    widget = widget_class.create!(secret: "hello pqc")
    widget_class.connection.execute("UPDATE widgets SET secret = 'not-a-valid-message' WHERE id = #{widget.id}")

    expect { widget_class.find(widget.id).secret }.to raise_error(ActiveRecord::Encryption::Errors::Base)
  end

  describe "レコードのMarshal(Rails.cache)" do
    # 6.1の形式は属性の型(暗号化のスキームとkey_provider)までたどり、7.1の形式は属性の値だけを書く。
    around do |example|
      original = ::ActiveRecord::Marshalling.format_version
      example.run
    ensure
      ::ActiveRecord::Marshalling.format_version = original
    end

    def expect_marshal_without_keys(klass)
      stub_const("MarshalWidget", klass)
      widget = MarshalWidget.find(MarshalWidget.create!(secret: "hello pqc").id)
      widget.secret

      dumped = Marshal.dump(widget)

      [keypair.secret_key, keypair.authentication_key].each { |secret| expect(dumped.b).not_to include(secret.b) }
      loaded = Marshal.load(dumped)
      expect(loaded.secret).to eq("hello pqc")
      loaded.update!(secret: "after reload") # pragma: allowlist secret
      expect(MarshalWidget.find(loaded.id).secret).to eq("after reload")
    end

    # 鍵を読み終えたKeyProviderを、属性ごとのkey_providerに指定したモデル。
    def class_with_own_key_provider
      provider = PqcRails::ActiveRecord::KeyProvider.new
      provider.encryption_key
      Class.new(::ActiveRecord::Base) do
        self.table_name = "widgets"
        encrypts :secret, key_provider: provider
      end
    end

    it "暗号化属性を持つレコードは6.1の形式でMarshal.dumpでき、鍵を含まない" do
      ::ActiveRecord::Marshalling.format_version = 6.1

      expect_marshal_without_keys(widget_class)
    end

    it "暗号化属性を持つレコードは7.1の形式でMarshal.dumpでき、鍵を含まない" do
      ::ActiveRecord::Marshalling.format_version = 7.1

      expect_marshal_without_keys(widget_class)
    end

    it "属性ごとにKeyProvider.newを指定したレコードも6.1の形式でMarshal.dumpでき、鍵を含まない" do
      ::ActiveRecord::Marshalling.format_version = 6.1

      expect_marshal_without_keys(class_with_own_key_provider)
    end

    it "属性ごとにKeyProvider.newを指定したレコードも7.1の形式でMarshal.dumpでき、鍵を含まない" do
      ::ActiveRecord::Marshalling.format_version = 7.1

      expect_marshal_without_keys(class_with_own_key_provider)
    end

    it "旧鍵を読んだ後のKeyProviderも、旧鍵を含めずにMarshalできる" do
      previous = PqcRails::HybridKem.open(:ml_kem_512, &:generate_keypair)
      original = ENV.fetch("PQC_RECORD_PREVIOUS_KEYS", nil)
      ENV["PQC_RECORD_PREVIOUS_KEYS"] = PqcRails::KeySource.encode(previous)
      provider = PqcRails::ActiveRecord::KeyProvider.new
      expect(provider.decryption_keys(nil).size).to eq(2)

      dumped = Marshal.dump(provider)

      [previous.secret_key, previous.authentication_key].each { |secret| expect(dumped.b).not_to include(secret.b) }
      expect(Marshal.load(dumped).decryption_keys(nil).last.secret.public_key).to eq(previous.public_key)
    ensure
      ENV["PQC_RECORD_PREVIOUS_KEYS"] = original
    end

    it "KeyProviderは鍵を読んだ後でも、鍵を含めずにMarshalでき、読み戻すと同じ鍵を読む" do
      provider = PqcRails::ActiveRecord::KeyProvider.new
      provider.encryption_key

      dumped = Marshal.dump(provider)

      [keypair.secret_key, keypair.authentication_key].each { |secret| expect(dumped.b).not_to include(secret.b) }
      expect(Marshal.load(dumped).encryption_key.secret.public_key).to eq(keypair.public_key)
    end
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

      ENV["PQC_RECORD_KEY"] = PqcRails::KeySource.encode(keypair)
      described_class.install!(pq_alg_name: :ml_kem_512)

      expect(dual_stack_widget_class.find(legacy.id).secret).to eq("legacy plaintext")

      fresh = dual_stack_widget_class.create!(secret: "new pqc plaintext") # pragma: allowlist secret
      raw = dual_stack_widget_class.connection.select_value("SELECT secret FROM widgets WHERE id = #{fresh.id}")

      expect(raw).not_to include("new pqc plaintext")
      expect(dual_stack_widget_class.find(fresh.id).secret).to eq("new pqc plaintext")
    ensure
      # primary_keyを設定したままにすると、Context.install!は明示指定が無い限り既存設定を
      # 引き継ぐ(Phase3の意図的な仕様)ため、後続の他テストのinstall!呼び出しにまで
      # このprimary_keyが漏れ、支援用のsupport_sha1_for_non_deterministic_encryption経由で
      # config.previous_schemes(グローバル)にゴミエントリが溜まり続ける。明示的にリセットする。
      ::ActiveRecord::Encryption.configure(primary_key: nil, deterministic_key: nil, key_derivation_salt: nil)
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
