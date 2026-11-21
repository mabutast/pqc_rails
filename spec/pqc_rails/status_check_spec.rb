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

    it "セッション鍵が認証鍵を持たない(0.3.0以前の形式)場合、鍵の再生成が必要と報告する" do
      legacy = Base64.strict_encode64(PqcRails::BlobPacking.pack(keypair.public_key, keypair.secret_key))
      ENV["PQC_SESSION_KEY"] = legacy

      results = described_class.run

      session_key = result_for(results, "セッション鍵 (PQC_SESSION_KEY)")
      expect(session_key.ok).to be false
      expect(session_key.detail).to include("認証鍵")
    end

    it "セッション鍵の値が途中で切れている場合、止まらずに鍵を貼り直すよう報告する" do
      ENV["PQC_SESSION_KEY"] = Base64.strict_encode64(Base64.strict_decode64(PqcRails::KeySource.encode(keypair))[0..-4])

      results = described_class.run

      session_key = result_for(results, "セッション鍵 (PQC_SESSION_KEY)")
      expect(session_key.ok).to be false
      expect(session_key.detail).to include("途中で切れて")
      expect(result_for(results, "liboqs")).not_to be_nil
    end

    it "セッション鍵の値がシードだけの秘密鍵(64バイト)の場合、pqc_railsの鍵を設定するよう報告する" do
      ENV["PQC_SESSION_KEY"] = Base64.strict_encode64("\x01".b + SecureRandom.random_bytes(63))

      session_key = result_for(described_class.run, "セッション鍵 (PQC_SESSION_KEY)")
      expect(session_key.ok).to be false
      expect(session_key.detail).to include("シードだけの秘密鍵")
      expect(session_key.detail).to include("rails generate pqc_rails:install")
      expect(session_key.detail).not_to include("途中で切れて")
    end

    it "旧鍵の値がシードだけの秘密鍵(32バイト)の場合、何世代目かを報告する" do
      good = PqcRails::KeySource.encode(keypair)
      seed = Base64.strict_encode64("\x01".b + SecureRandom.random_bytes(31))
      ENV["PQC_SESSION_PREVIOUS_KEYS"] = [good, seed].join(",")

      previous = result_for(described_class.run, "セッション旧鍵 (PQC_SESSION_PREVIOUS_KEYS)")
      expect(previous.ok).to be false
      expect(previous.detail).to include("2世代目")
      expect(previous.detail).to include("シードだけの秘密鍵")
    end

    it "旧鍵に途中で切れた値とシードだけの値が両方ある場合、途中で切れた方を報告する" do
      good = PqcRails::KeySource.encode(keypair)
      seed = Base64.strict_encode64("\x01".b + SecureRandom.random_bytes(31))
      cut = Base64.strict_encode64(Base64.strict_decode64(good)[0..-4])
      ENV["PQC_SESSION_PREVIOUS_KEYS"] = [seed, cut].join(",")

      previous = result_for(described_class.run, "セッション旧鍵 (PQC_SESSION_PREVIOUS_KEYS)")
      expect(previous.ok).to be false
      expect(previous.detail).to include("2世代目の旧鍵の値が途中で切れています")
    end

    it "旧鍵の値が途中で切れている場合、何世代目かを報告する" do
      good = PqcRails::KeySource.encode(keypair)
      cut = Base64.strict_encode64(Base64.strict_decode64(good)[0..-4])
      ENV["PQC_SESSION_PREVIOUS_KEYS"] = [good, cut].join(",")

      previous = result_for(described_class.run, "セッション旧鍵 (PQC_SESSION_PREVIOUS_KEYS)")
      expect(previous.ok).to be false
      expect(previous.detail).to include("2世代目")
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

    describe "暗号化している属性" do
      let!(:model) do
        Class.new(::ActiveRecord::Base) do
          self.table_name = "status_check_people"
          def self.name = "StatusCheckPerson"
          encrypts :email
          encrypts :phone
        end
      end

      it "encryptsで暗号化している属性を、モデル名と属性名で一覧にする" do
        attributes = result_for(described_class.run, "暗号化している属性")

        expect(attributes.ok).to be true
        expect(attributes.detail).to include("StatusCheckPerson(email, phone)")
      end

      it "抽象クラスと名前の無いクラスは一覧に入れない" do
        Class.new(::ActiveRecord::Base) do
          self.abstract_class = true
          encrypts :secret
        end

        attributes = result_for(described_class.run, "暗号化している属性")

        expect(attributes.detail).not_to include("secret")
      end

      it "暗号化している属性が無い場合、モデルが読み込まれているかを確かめるよう案内する" do
        allow(::ActiveRecord::Base).to receive(:descendants).and_return([])

        attributes = result_for(described_class.run, "暗号化している属性")

        expect(attributes.ok).to be true
        expect(attributes.detail).to include("見つかりません")
      end

      it "Rails.applicationがあれば、一覧を作る前にモデルを読み込む(eager_load!)" do
        fake_app = double("Rails.application", middleware: [], credentials: {})
        allow(fake_app).to receive(:eager_load!)
        allow(Rails).to receive(:application).and_return(fake_app)

        described_class.run

        expect(fake_app).to have_received(:eager_load!)
      end
    end

    describe "使うアルゴリズム" do
      it "DBとセッションが新しく暗号化する時のアルゴリズムIDを報告する" do
        ENV["PQC_RECORD_KEY"] = PqcRails::KeySource.encode(keypair)
        PqcRails::ActiveRecord::Context.install!(pq_alg_name: :ml_kem_512)
        middleware_item = double("middleware_item", klass: PqcRails::Session::PqcCookieStore,
                                                    args: [{ pq_alg_name: :ml_kem_1024 }])
        allow(Rails).to receive(:application)
          .and_return(double("Rails.application", middleware: [middleware_item], credentials: {}))

        algorithms = result_for(described_class.run, "使うアルゴリズム")

        expect(algorithms.ok).to be true
        expect(algorithms.detail).to include("DB: X25519+ML-KEM-512")
        expect(algorithms.detail).to include("セッション: X25519+ML-KEM-1024")
      ensure
        ::ActiveRecord::Encryption.configure(primary_key: nil, deterministic_key: nil, key_derivation_salt: nil)
      end

      it "セッションでpq_alg_nameを指定していなければ既定のアルゴリズムを報告する" do
        middleware_item = double("middleware_item", klass: PqcRails::Session::PqcCookieStore, args: [{}])
        allow(Rails).to receive(:application)
          .and_return(double("Rails.application", middleware: [middleware_item], credentials: {}))

        algorithms = result_for(described_class.run, "使うアルゴリズム")

        expect(algorithms.detail).to include("セッション: X25519+ML-KEM-768")
      end

      it "pqc_railsを使っていない側は、使っていないと報告する" do
        ::ActiveRecord::Encryption.configure(primary_key: nil, deterministic_key: nil, key_derivation_salt: nil)

        algorithms = result_for(described_class.run, "使うアルゴリズム")

        expect(algorithms.detail).to include("DB: pqc_railsを使っていません")
        expect(algorithms.detail).to include("セッション: pqc_railsを使っていません")
      end
    end
  end
end
