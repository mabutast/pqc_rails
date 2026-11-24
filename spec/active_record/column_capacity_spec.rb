# frozen_string_literal: true

require_relative "../support/test_database"

RSpec.describe PqcRails::ActiveRecord::ColumnCapacity do
  before(:all) do
    TestDatabase.connect
    ::ActiveRecord::Migration.verbose = false
    ::ActiveRecord::Schema.define do
      create_table :capacity_widgets, force: true do |t|
        t.string :short_secret, limit: 64
        t.string :medium_secret, limit: 3000
        t.text :long_secret
        t.string :plain, limit: 8
      end
    end
  end

  let(:keypair) { PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair } }
  let(:widget_class) do
    Class.new(::ActiveRecord::Base) do
      self.table_name = "capacity_widgets"
      encrypts :short_secret, :medium_secret, :long_secret
    end
  end

  around do |example|
    original = ENV.fetch("PQC_RECORD_KEY", nil)
    ENV["PQC_RECORD_KEY"] = PqcRails::KeySource.encode(keypair)
    PqcRails::ActiveRecord::Context.install!(pq_alg_name: :ml_kem_512)
    example.run
  ensure
    ENV["PQC_RECORD_KEY"] = original
  end

  describe ".too_short" do
    it "暗号文が入らない長さの列を、属性名・列の上限・暗号文の長さで返す" do
      column = described_class.too_short(widget_class).fetch(0)

      expect(column.attribute).to eq("short_secret")
      expect(column.limit).to eq(64)
      expect(column.required).to be > 64
    end

    it "暗号文が入る列と、暗号化していない短い列は返さない" do
      expect(described_class.too_short(widget_class).map(&:attribute)).to eq(["short_secret"])
    end

    it "暗号文の長さが列の上限と等しければ入るものとして扱い、1文字でも超えれば返す" do
      type = double("encrypted type")
      allow(widget_class).to receive(:type_for_attribute).and_return(type)

      allow(type).to receive(:serialize).and_return("a" * 64)
      expect(described_class.too_short(widget_class)).to be_empty

      allow(type).to receive(:serialize).and_return("a" * 65)
      expect(described_class.too_short(widget_class).map(&:required)).to eq([65])
    end

    it "テーブルが無いモデルでは何も返さない" do
      missing = Class.new(::ActiveRecord::Base) do
        self.table_name = "capacity_missing"
        encrypts :secret
      end

      expect(described_class.too_short(missing)).to eq([])
    end
  end

  describe "長い値で上限を超える列" do
    it ".may_overflowは、短い値は入るが上限のあるstring列を返し、text列と入らない列は返さない" do
      expect(described_class.may_overflow(widget_class).map(&:attribute)).to eq(["medium_secret"])
    end

    it ".too_longは、列に入る値では何も返さない" do
      expect(described_class.too_long(widget_class.new(medium_secret: "short"))).to eq([]) # pragma: allowlist secret
    end

    it ".too_longは、暗号文が列の上限を超える値の属性を返す" do
      found = described_class.too_long(widget_class.new(medium_secret: SecureRandom.hex(2000))).fetch(0)

      expect(found.attribute).to eq("medium_secret")
      expect(found.limit).to eq(3000)
      expect(found.required).to be > 3000
    end

    it ".too_longは、値がnilの属性を測らない" do
      expect(described_class.too_long(widget_class.new(medium_secret: nil))).to eq([])
    end
  end

  context "MySQLのstring列(255文字)", if: ENV.fetch("PQC_TEST_DATABASE_URL", "").start_with?("mysql") do
    before(:all) do
      ::ActiveRecord::Schema.define do
        create_table(:capacity_mysql_rows, force: true) { |t| t.string :secret }
      end
    end

    let(:row_class) do
      Class.new(::ActiveRecord::Base) do
        self.table_name = "capacity_mysql_rows"
        encrypts :secret
      end
    end

    it "暗号文が入らないと判定する" do
      expect(described_class.too_short(row_class).map(&:limit)).to eq([255])
    end

    it "strictモードでは保存がValueTooLongになる" do
      expect { row_class.create!(secret: "a@example.com") }.to raise_error(::ActiveRecord::ValueTooLong) # pragma: allowlist secret
    end
  end
end
