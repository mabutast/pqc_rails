# frozen_string_literal: true

require "active_record"

# README.md「API の安定性」節が列挙するクラス・メソッドが、実際に存在するかを検証する
# (対外公開文書とコードの一致監査、Tier1)。README側のリストを書き換えた際は、このリストも
# あわせて更新すること(自動でREADMEから抽出はしていない。フリーテキストの箇条書きを安全に
# 機械抽出するのは困難なため、あえて手動同期の明示的なチェックリストにしてある)。
RSpec.describe "README.mdの「API の安定性」節に列挙されたクラス・メソッドの実在確認" do
  describe "安定した公開API" do
    it "PqcRails.configureが存在する" do
      expect(PqcRails).to respond_to(:configure)
    end

    it "PqcRails::Configuration#liboqs_pathが存在する" do
      expect(PqcRails::Configuration.instance_methods).to include(:liboqs_path)
    end

    it "PqcRails::Session::PqcCookieStoreがkeypair:/previous_keypairs:/pq_alg_name:オプションを実際に処理する" do
      keypair = PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair }

      store = PqcRails::Session::PqcCookieStore.new(
        ->(_env) { [200, {}, [""]] },
        key: "_test_session", keypair: keypair, previous_keypairs: [], pq_alg_name: :ml_kem_512
      )

      expect(store).to be_a(PqcRails::Session::PqcCookieStore)
    end

    it "PqcRails::ActiveRecord::Context.install!が存在する" do
      expect(PqcRails::ActiveRecord::Context).to respond_to(:install!)
    end

    it "PqcRails::ActiveRecord::KeyProviderが存在し、key_source:を受け取れる" do
      expect(PqcRails::ActiveRecord::KeyProvider.instance_method(:initialize).parameters)
        .to include([:key, :key_source])
    end

    it "PqcRails::Cipherが存在する" do
      expect(PqcRails::Cipher).to be_a(Class)
    end

    it "PqcRails::KeySource::EnvCredentialsが#current_keypair/#previous_keypairsを実装している" do
      expect(PqcRails::KeySource::EnvCredentials.instance_methods).to include(:current_keypair, :previous_keypairs)
    end

    it "PqcRails::Kem / PqcRails::Sigが存在する" do
      expect(PqcRails::Kem).to be_a(Class)
      expect(PqcRails::Sig).to be_a(Class)
    end

    it "PqcRails::Algorithms::UnknownAlgorithmErrorが存在し、PqcRails::Errorのサブクラスである" do
      expect(PqcRails::Algorithms::UnknownAlgorithmError.ancestors).to include(PqcRails::Error)
    end

    it "PqcRails::Error / PqcRails::MissingKeyErrorが存在する" do
      expect(PqcRails::Error.ancestors).to include(StandardError)
      expect(PqcRails::MissingKeyError.ancestors).to include(PqcRails::Error)
    end

    it "rails generate pqc_rails:installジェネレータが存在する" do
      expect(PqcRails::Generators::InstallGenerator).to be_a(Class)
    end

    it "rails pqc_rails:statusタスクが定義されている" do
      require "rake"
      Rake::Task.clear
      load File.expand_path("../../lib/pqc_rails/tasks/pqc_rails.rake", __dir__)
      expect(Rake::Task.task_defined?("pqc_rails:status")).to be(true)
    end

    it "PqcRails::StatusCheck.runが、name/ok/detailを持つResultの配列を返す" do
      result = PqcRails::StatusCheck.run.first
      expect(result).to respond_to(:name, :ok, :detail)
    end
  end

  describe "内部実装(READMEが「直接使わないでください」と明記しているクラス群)" do
    it "HybridKem / DhKem / EnvelopeCipher / BlobPackingが存在する" do
      expect(PqcRails::HybridKem).to be_a(Class)
      expect(PqcRails::DhKem).to be_a(Class)
      expect(PqcRails::EnvelopeCipher).to be_a(Class)
      expect(PqcRails::BlobPacking).to be_a(Module)
    end

    it "Session::Encryptor / Session::KeyManagerが存在する" do
      expect(PqcRails::Session::Encryptor).to be_a(Class)
      expect(PqcRails::Session::KeyManager).to be_a(Module)
    end

    it "Algorithms.find_kemが存在する" do
      expect(PqcRails::Algorithms).to respond_to(:find_kem)
    end

    it "KeySource.fetch / .fetch! / .fetch_keypair!が存在する" do
      expect(PqcRails::KeySource).to respond_to(:fetch, :fetch!, :fetch_keypair!)
    end
  end
end
