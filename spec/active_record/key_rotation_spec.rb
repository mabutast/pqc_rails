# frozen_string_literal: true

require "active_record"
require "sqlite3"

# docs/MIGRATION.md「鍵ローテーション（pqc_rails鍵世代間）」に書かれた運用手順
# (ローテーション→複数世代の併用→一括再暗号化→鍵失効、およびpqc_rails導入前へのロールバック)を
# 実際のActiveRecord::Encryption経由でE2Eに検証する。ユニットレベルの挙動は
# spec/active_record/key_provider_spec.rbで既にカバーしているため、ここでは
# KeyProvider単体の戻り値ではなく、実際のDB書き込み・読み出しを通した結果を確認する。
RSpec.describe "PqcRails鍵ローテーション(DB, E2E)" do
  before(:all) do
    ::ActiveRecord::Base.establish_connection(adapter: "sqlite3", database: ":memory:")
    ::ActiveRecord::Migration.verbose = false
    ::ActiveRecord::Schema.define do
      create_table :rotation_widgets do |t|
        t.string :secret
      end
    end
  end

  let(:key_a) { PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair } }
  let(:key_b) { PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair } }
  let(:key_c) { PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair } }
  let(:widget_class) do
    Class.new(::ActiveRecord::Base) do
      self.table_name = "rotation_widgets"
      encrypts :secret
    end
  end

  around do |example|
    original_current = ENV.fetch("PQC_RECORD_KEY", nil)
    original_previous = ENV.fetch("PQC_RECORD_PREVIOUS_KEYS", nil)
    example.run
  ensure
    ENV["PQC_RECORD_KEY"] = original_current
    ENV["PQC_RECORD_PREVIOUS_KEYS"] = original_previous
  end

  # docs/MIGRATION.mdのローテーション手順(1〜4)をそのままENV設定として再現する。
  def rotate!(current:, previous: [])
    ENV["PQC_RECORD_KEY"] = PqcRails::KeySource.encode(current)
    ENV["PQC_RECORD_PREVIOUS_KEYS"] =
      previous.empty? ? nil : previous.map { |kp| PqcRails::KeySource.encode(kp) }.join(",")
    PqcRails::ActiveRecord::Context.install!(pq_alg_name: :ml_kem_512)
  end

  it "ローテーション後も旧鍵で暗号化された既存レコードを復号でき、新規レコードは新鍵で暗号化される" do
    rotate!(current: key_a)
    old_record = widget_class.create!(secret: "generation A") # pragma: allowlist secret

    rotate!(current: key_b, previous: [key_a])

    expect(widget_class.find(old_record.id).secret).to eq("generation A")

    new_record = widget_class.create!(secret: "generation B") # pragma: allowlist secret
    expect(widget_class.find(new_record.id).secret).to eq("generation B")
  end

  it "3世代(現行+旧鍵2世代)を併用しても、最も古い世代の鍵で暗号化されたレコードまで復号できる" do
    rotate!(current: key_a)
    gen_a_record = widget_class.create!(secret: "generation A") # pragma: allowlist secret

    rotate!(current: key_b, previous: [key_a])
    gen_b_record = widget_class.create!(secret: "generation B") # pragma: allowlist secret

    rotate!(current: key_c, previous: [key_b, key_a])

    expect(widget_class.find(gen_a_record.id).secret).to eq("generation A")
    expect(widget_class.find(gen_b_record.id).secret).to eq("generation B")

    gen_c_record = widget_class.create!(secret: "generation C") # pragma: allowlist secret
    expect(widget_class.find(gen_c_record.id).secret).to eq("generation C")
  end

  it "旧鍵をPQC_RECORD_PREVIOUS_KEYSから外す(鍵失効)と、その鍵でしか復号できないレコードは読めなくなる" do
    rotate!(current: key_a)
    old_record = widget_class.create!(secret: "generation A") # pragma: allowlist secret

    rotate!(current: key_b, previous: [key_a])
    new_record = widget_class.create!(secret: "generation B") # pragma: allowlist secret

    rotate!(current: key_b, previous: []) # 鍵Aを失効

    expect { widget_class.find(old_record.id).secret }.to raise_error(ActiveRecord::Encryption::Errors::Decryption)
    expect(widget_class.find(new_record.id).secret).to eq("generation B") # 現行鍵のレコードは影響を受けない
  end

  it "save!だけでは再暗号化されない(dirty-trackingにより復号後の値が変わらないとUPDATEされない)" do
    rotate!(current: key_a)
    record = widget_class.create!(secret: "generation A") # pragma: allowlist secret
    raw_before = widget_class.connection.select_value("SELECT secret FROM rotation_widgets WHERE id = #{record.id}")

    rotate!(current: key_b, previous: [key_a])
    widget_class.find(record.id).save! # 値を変更せずsave!するだけでは何も起きない

    raw_after = widget_class.connection.select_value("SELECT secret FROM rotation_widgets WHERE id = #{record.id}")
    expect(raw_after).to eq(raw_before) # 依然として鍵Aの暗号文のまま(再暗号化されていない)
  end

  it "一括再暗号化(MIGRATION.mdの手順)後は、旧鍵を失効させても新しい鍵で復号できる" do
    rotate!(current: key_a)
    record = widget_class.create!(secret: "generation A") # pragma: allowlist secret

    rotate!(current: key_b, previous: [key_a])
    widget_class.find(record.id).encrypt # 一括再暗号化スイープを1レコード分だけ再現(読み出し→encrypt)

    rotate!(current: key_b, previous: []) # 再暗号化済みなので鍵Aを失効させてよい

    expect(widget_class.find(record.id).secret).to eq("generation A")
  end

  it "previous:経由でpqc_rails導入前(Rails標準AES)へロールバックできる(docs/MIGRATION.md「ロールバック手順」)" do
    rotate!(current: key_a)
    pqc_record = widget_class.create!(secret: "pqc plaintext") # pragma: allowlist secret

    old_primary_key = "r" * 32
    rolled_back_widget_class = Class.new(::ActiveRecord::Base) do
      self.table_name = "rotation_widgets"
      encrypts :secret, previous: [
        {
          cipher: PqcRails::Cipher.new(pq_alg_name: :ml_kem_512), # Context.install!に渡したpq_alg_nameと一致させる必要がある
          key_provider: PqcRails::ActiveRecord::KeyProvider.new
        }
      ]
    end

    ::ActiveRecord::Encryption.configure(
      primary_key: old_primary_key,
      deterministic_key: "d" * 32,
      key_derivation_salt: "s" * 32
    )

    expect(rolled_back_widget_class.find(pqc_record.id).secret).to eq("pqc plaintext")

    fresh = rolled_back_widget_class.create!(secret: "rails standard plaintext") # pragma: allowlist secret
    raw = rolled_back_widget_class.connection.select_value("SELECT secret FROM rotation_widgets WHERE id = #{fresh.id}")

    expect(raw).not_to include("rails standard plaintext")
    expect(rolled_back_widget_class.find(fresh.id).secret).to eq("rails standard plaintext")
  ensure
    ::ActiveRecord::Encryption.configure(primary_key: nil, deterministic_key: nil, key_derivation_salt: nil)
  end
end
