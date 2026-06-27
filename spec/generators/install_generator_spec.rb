# frozen_string_literal: true

require "tmpdir"
require "active_support/encrypted_file"
require "active_support/encrypted_configuration"
require "pqc_rails/generators/install/install_generator"

RSpec.describe PqcRails::Generators::InstallGenerator do
  around do |example|
    Dir.mktmpdir do |dir|
      @destination_root = dir
      example.run
    end
  end

  def build_credentials(dir)
    key_path = File.join(dir, "master.key")
    File.write(key_path, ActiveSupport::EncryptedFile.generate_key)

    ActiveSupport::EncryptedConfiguration.new(
      config_path: File.join(dir, "credentials.yml.enc"),
      key_path: key_path,
      env_key: "RAILS_MASTER_KEY",
      raise_if_missing_key: true
    )
  end

  def run_generator(credentials)
    fake_app = double("Rails.application", credentials: credentials)
    allow(Rails).to receive(:application).and_return(fake_app)

    original_stdout = $stdout
    $stdout = StringIO.new
    described_class.start([], destination_root: @destination_root)
  ensure
    $stdout = original_stdout
  end

  describe "initializerの生成" do
    it "config/initializers/pqc_rails.rbを生成する" do
      run_generator(build_credentials(@destination_root))

      path = File.join(@destination_root, "config/initializers/pqc_rails.rb")
      expect(File).to exist(path)
      expect(File.read(path)).to include("PqcRails.configure")
    end
  end

  describe "credentialsへの鍵の保存" do
    it "pqc_session_keyをcredentialsに書き込む" do
      credentials = build_credentials(@destination_root)

      run_generator(credentials)

      encoded = credentials.config[:pqc_session_key]
      expect(encoded).to be_a(String)
    end

    it "書き込まれた鍵はKeyManager.decodeで有効なHybridKemキーペアに戻る" do
      credentials = build_credentials(@destination_root)

      run_generator(credentials)

      keypair = PqcRails::Session::KeyManager.decode(credentials.config[:pqc_session_key])
      expect(keypair.public_key).to be_a(String)
      expect(keypair.secret_key).to be_a(String)
    end

    it "既存のcredentialsの内容を消さずに鍵を追加する" do
      credentials = build_credentials(@destination_root)
      credentials.change { |tmp_path| tmp_path.write({ "existing_secret" => "keep-me" }.to_yaml) }

      run_generator(credentials)

      expect(credentials.config[:existing_secret]).to eq("keep-me")
      expect(credentials.config[:pqc_session_key]).to be_a(String)
    end
  end
end
