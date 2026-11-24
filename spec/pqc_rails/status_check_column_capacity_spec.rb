# frozen_string_literal: true

require_relative "../support/test_database"

RSpec.describe PqcRails::StatusCheck, "暗号文が入る列" do
  let(:keypair) { PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair } }
  let(:model) do
    Class.new(::ActiveRecord::Base) do
      self.table_name = "status_capacity_rows"
      encrypts :secret
    end
  end
  let(:check) { described_class.new }

  before(:all) do
    TestDatabase.connect
    ::ActiveRecord::Migration.verbose = false
    ::ActiveRecord::Schema.define do
      create_table(:status_capacity_rows, force: true) { |t| t.string :secret, limit: 64 }
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

  # 名前は例の中だけで付ける。名前の残ったクラスは、ほかのspecの属性の一覧に現れるため。
  before do
    allow(model).to receive(:name).and_return("StatusCapacityRow")
    allow(check).to receive(:encrypted_models).and_return([model])
  end

  def result = check.send(:column_capacity_result)

  it "暗号文が入らない列をモデル名・属性名・長さで報告し、失敗にする" do
    expect(result.ok).to be false
    expect(result.detail).to include("StatusCapacityRow#secret", "列の上限64", "text列")
  end

  it "すべての列に入る場合は成功にする" do
    allow(PqcRails::ActiveRecord::ColumnCapacity).to receive(:too_short).and_return([])

    expect(result.ok).to be true
  end

  it "確かめられない場合は失敗にし、例外のメッセージを出さない" do
    allow(PqcRails::ActiveRecord::ColumnCapacity).to receive(:too_short).and_raise(StandardError, "password=hunter2") # pragma: allowlist secret

    expect(result.ok).to be false
    expect(result.detail).to include("StandardError")
    expect(result.detail).not_to include("hunter2")
  end

  it "PqcRails::Cipherを使っていない場合は確かめない" do
    allow(::ActiveRecord::Encryption.context).to receive(:cipher).and_return(::ActiveRecord::Encryption::Cipher.new)

    expect(result.ok).to be true
    expect(result.detail).to include("確かめていません")
  end
end
