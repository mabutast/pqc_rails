# frozen_string_literal: true

require "active_record"

RSpec.describe PqcRails::StatusCheck do
  let(:keypair) { PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair } }

  around do |example|
    original_session_key = ENV.fetch("PQC_SESSION_KEY", nil)
    original_session_previous = ENV.fetch("PQC_SESSION_PREVIOUS_KEYS", nil)
    original_record_key = ENV.fetch("PQC_RECORD_KEY", nil)
    original_record_previous = ENV.fetch("PQC_RECORD_PREVIOUS_KEYS", nil)
    ENV.delete("PQC_SESSION_KEY")
    ENV.delete("PQC_SESSION_PREVIOUS_KEYS")
    ENV.delete("PQC_RECORD_KEY")
    ENV.delete("PQC_RECORD_PREVIOUS_KEYS")
    example.run
  ensure
    ENV["PQC_SESSION_KEY"] = original_session_key
    ENV["PQC_SESSION_PREVIOUS_KEYS"] = original_session_previous
    ENV["PQC_RECORD_KEY"] = original_record_key
    ENV["PQC_RECORD_PREVIOUS_KEYS"] = original_record_previous
  end

  before do
    allow(Rails).to receive(:application).and_return(nil)
  end

  def result_for(results, name)
    results.find { |r| r.name == name }
  end

  describe "#run" do
    it "liboqsの解決済みパスを常に報告する(app boot自体が成功していれば読み込みは既に成功している)" do
      results = described_class.run

      liboqs = result_for(results, "liboqs")
      expect(liboqs.ok).to be true
      expect(liboqs.detail).to include(PqcRails.configuration.liboqs_path)
    end

    it "セッション鍵が未設定の場合、その旨を報告する" do
      results = described_class.run

      session_key = result_for(results, "セッション鍵 (PQC_SESSION_KEY)")
      expect(session_key.ok).to be false
      expect(session_key.detail).to include("未設定")
    end

    it "セッション鍵が設定されている場合、設定済みと報告する" do
      ENV["PQC_SESSION_KEY"] = PqcRails::KeySource.encode(keypair)

      results = described_class.run

      session_key = result_for(results, "セッション鍵 (PQC_SESSION_KEY)")
      expect(session_key.ok).to be true
      expect(session_key.detail).to include("設定済み")
    end

    it "DBレコード鍵が未設定の場合、その旨を報告する" do
      results = described_class.run

      record_key = result_for(results, "DBレコード鍵 (PQC_RECORD_KEY)")
      expect(record_key.ok).to be false
    end

    it "旧鍵が未設定の場合、ローテーション中ではないと報告する" do
      results = described_class.run

      previous = result_for(results, "セッション旧鍵 (PQC_SESSION_PREVIOUS_KEYS)")
      expect(previous.ok).to be true
      expect(previous.detail).to include("ローテーション中ではありません")
    end

    it "旧鍵が複数設定されている場合、世代数を報告する(鍵ローテーション中)" do
      other_keypair = PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair }
      ENV["PQC_RECORD_PREVIOUS_KEYS"] =
        [keypair, other_keypair].map { |kp| PqcRails::KeySource.encode(kp) }.join(",")

      results = described_class.run

      previous = result_for(results, "DBレコード旧鍵 (PQC_RECORD_PREVIOUS_KEYS)")
      expect(previous.ok).to be true
      expect(previous.detail).to include("2世代")
    end

    it "Rails.applicationが無い場合、セッションストアは確認不可と報告する" do
      results = described_class.run

      session_store = result_for(results, "セッションストア")
      expect(session_store.ok).to be false
    end

    it ":pqc_cookie_storeがmiddlewareに含まれていれば有効と報告する" do
      middleware_item = double("middleware_item", klass: PqcRails::Session::PqcCookieStore)
      fake_app = double("Rails.application", middleware: [middleware_item], credentials: {})
      allow(Rails).to receive(:application).and_return(fake_app)

      results = described_class.run

      session_store = result_for(results, "セッションストア")
      expect(session_store.ok).to be true
    end

    it ":pqc_cookie_storeがmiddlewareに含まれていなければ未設定と報告する" do
      fake_app = double("Rails.application", middleware: [], credentials: {})
      allow(Rails).to receive(:application).and_return(fake_app)

      results = described_class.run

      session_store = result_for(results, "セッションストア")
      expect(session_store.ok).to be false
    end

    it "ActiveRecord::Encryptionのcipherが未設定(Rails標準のまま)の場合、未設定と報告する" do
      ::ActiveRecord::Encryption.configure(primary_key: nil, deterministic_key: nil, key_derivation_salt: nil)

      results = described_class.run

      ar = result_for(results, "ActiveRecord::Encryption")
      expect(ar.ok).to be false
    end

    it "PqcRails::ActiveRecord::Context.install!済みの場合、設定済みと報告する" do
      ENV["PQC_RECORD_KEY"] = PqcRails::KeySource.encode(keypair)
      PqcRails::ActiveRecord::Context.install!(pq_alg_name: :ml_kem_512)

      results = described_class.run

      ar = result_for(results, "ActiveRecord::Encryption")
      expect(ar.ok).to be true
    ensure
      ::ActiveRecord::Encryption.configure(primary_key: nil, deterministic_key: nil, key_derivation_salt: nil)
    end
  end
end
