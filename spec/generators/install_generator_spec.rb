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

    it "書き込まれた鍵はKeySource.decodeで有効なHybridKemキーペアに戻る" do
      credentials = build_credentials(@destination_root)

      run_generator(credentials)

      keypair = PqcRails::KeySource.decode(credentials.config[:pqc_session_key])
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

    it "pqc_record_keyに認証鍵を持つ有効なキーペアを書き込む" do
      credentials = build_credentials(@destination_root)

      run_generator(credentials)

      keypair = PqcRails::KeySource.decode(credentials.config[:pqc_record_key])
      expect(keypair.public_key).to be_a(String)
      expect(keypair.authentication_key).to be_a(String)
    end

    it "セッションとDBに別の鍵を書き込む" do
      credentials = build_credentials(@destination_root)

      run_generator(credentials)

      expect(credentials.config[:pqc_record_key]).not_to eq(credentials.config[:pqc_session_key])
    end

    it "再実行しても両方の鍵を上書きしない" do
      credentials = build_credentials(@destination_root)
      run_generator(credentials)
      session_key = credentials.config[:pqc_session_key]
      record_key = credentials.config[:pqc_record_key]

      run_generator(reloaded(credentials))

      expect(reloaded(credentials).config[:pqc_session_key]).to eq(session_key)
      expect(reloaded(credentials).config[:pqc_record_key]).to eq(record_key)
    end

    it "セッションの鍵だけがある時は、それを保ってDBの鍵を足す" do
      credentials = build_credentials(@destination_root)
      credentials.change { |tmp_path| tmp_path.write({ "pqc_session_key" => "existing-session-key" }.to_yaml) }

      run_generator(reloaded(credentials))

      expect(reloaded(credentials).config[:pqc_session_key]).to eq("existing-session-key")
      expect(reloaded(credentials).config[:pqc_record_key]).to be_a(String)
    end

    it "DBの鍵だけがある時は、それを保ってセッションの鍵を足す" do
      credentials = build_credentials(@destination_root)
      credentials.change { |tmp_path| tmp_path.write({ "pqc_record_key" => "existing-record-key" }.to_yaml) }

      run_generator(reloaded(credentials))

      expect(reloaded(credentials).config[:pqc_record_key]).to eq("existing-record-key")
      expect(reloaded(credentials).config[:pqc_session_key]).to be_a(String)
    end

    it "環境変数で設定済みの鍵はcredentialsに書き込まない" do
      credentials = build_credentials(@destination_root)
      allow(ENV).to receive(:fetch).and_call_original
      allow(ENV).to receive(:fetch).with("PQC_RECORD_KEY", nil).and_return("key-from-env")

      run_generator(credentials)

      expect(credentials.config).not_to have_key(:pqc_record_key)
      expect(credentials.config[:pqc_session_key]).to be_a(String)
    end

    it "全ての鍵が設定済みならcredentialsを書き換えない" do
      credentials = build_credentials(@destination_root)
      credentials.change do |tmp_path|
        tmp_path.write({ "pqc_session_key" => "session", "pqc_record_key" => "record" }.to_yaml)
      end
      path = File.join(@destination_root, "credentials.yml.enc")
      before = File.binread(path)

      run_generator(reloaded(credentials))

      expect(File.binread(path)).to eq(before)
    end
  end

  describe "既存のcredentialsの扱い" do
    def write_credentials(credentials, content)
      credentials.change { |tmp_path| tmp_path.write(content) }
      reloaded(credentials)
    end

    it "日付の値があっても鍵を足せる" do
      credentials = write_credentials(build_credentials(@destination_root), "expires: 2027-01-01\n")

      run_generator(credentials)

      expect(reloaded(credentials).config[:pqc_record_key]).to be_a(String)
      expect(reloaded(credentials).config[:expires]).to eq(Date.new(2027, 1, 1))
    end

    it "コメントを消さない" do
      credentials = write_credentials(build_credentials(@destination_root), "# aws:\n#   id: 123\nsecret_key_base: abc")

      run_generator(credentials)

      content = reloaded(credentials).read
      expect(content).to include("# aws:\n#   id: 123\nsecret_key_base: abc\n")
      expect(reloaded(credentials).config[:secret_key_base]).to eq("abc")
    end

    it "シンボルのキーで設定済みの鍵を上書きしない" do
      credentials = write_credentials(build_credentials(@destination_root), ":pqc_session_key: symbol-key\n")

      run_generator(credentials)

      expect(reloaded(credentials).config[:pqc_session_key]).to eq("symbol-key")
    end

    it "値が空のキーがある時は書き換えない" do
      content = "pqc_record_key:\n"
      credentials = write_credentials(build_credentials(@destination_root), content)

      run_generator(credentials)

      expect(reloaded(credentials).read).not_to match(/pqc_record_key: \S/)
      expect(reloaded(credentials).read.scan("pqc_record_key").size).to eq(1)
    end

    it "空の環境変数は設定済みとして扱い、credentialsに書き込まない" do
      credentials = build_credentials(@destination_root)
      allow(ENV).to receive(:fetch).and_call_original
      allow(ENV).to receive(:fetch).with("PQC_RECORD_KEY", nil).and_return("")

      run_generator(credentials)

      expect(reloaded(credentials).config).not_to have_key(:pqc_record_key)
    end

    it "--pretendではcredentialsを書き換えない" do
      credentials = build_credentials(@destination_root)
      fake_app = double("Rails.application", credentials: credentials)
      allow(Rails).to receive(:application).and_return(fake_app)

      capture_stdout { described_class.start(["--pretend"], destination_root: @destination_root) }

      expect(File).not_to exist(File.join(@destination_root, "credentials.yml.enc"))
    end

    it "rails destroyではcredentialsを書き換えない" do
      credentials = build_credentials(@destination_root)
      fake_app = double("Rails.application", credentials: credentials)
      allow(Rails).to receive(:application).and_return(fake_app)

      capture_stdout { described_class.start([], destination_root: @destination_root, behavior: :revoke) }

      expect(File).not_to exist(File.join(@destination_root, "credentials.yml.enc"))
    end

    it "鍵を足した時に、対象のアルゴリズムを出力で知らせる" do
      credentials = build_credentials(@destination_root)
      fake_app = double("Rails.application", credentials: credentials)
      allow(Rails).to receive(:application).and_return(fake_app)

      output = capture_stdout { described_class.start([], destination_root: @destination_root) }

      expect(output).to include("ML-KEM-768")
    end

    it "認証鍵の無い0.3.0形式の鍵は残し、入れ替えを案内する" do
      legacy = PqcRails::HybridKem.open(:ml_kem_768, &:generate_keypair)
      encoded = PqcRails::KeySource.encode(PqcRails::HybridKem::Keypair.new(legacy.public_key, legacy.secret_key))
      credentials = write_credentials(build_credentials(@destination_root), { "pqc_session_key" => encoded }.to_yaml)
      allow(Rails).to receive(:application).and_return(double("Rails.application", credentials: credentials))

      output = capture_stdout { described_class.start([], destination_root: @destination_root) }

      expect(output).to include("pqc_session_key was generated by pqc_rails 0.3.0")
      expect(reloaded(credentials).config[:pqc_session_key]).to eq(encoded)
    end

    it "不正な鍵は残し、値を出力しない" do
      credentials = write_credentials(build_credentials(@destination_root), "pqc_record_key: not-a-valid-secret\n")
      allow(Rails).to receive(:application).and_return(double("Rails.application", credentials: credentials))

      output = capture_stdout { described_class.start([], destination_root: @destination_root) }

      expect(output).to include("pqc_record_key is not a valid pqc_rails key")
      expect(output).not_to include("not-a-valid-secret")
      expect(reloaded(credentials).config[:pqc_record_key]).to eq("not-a-valid-secret")
    end

    def capture_stdout
      original = $stdout
      $stdout = StringIO.new
      yield
      $stdout.string
    ensure
      $stdout = original
    end
  end

  describe "再実行時のinitializer" do
    it "編集済みのinitializerを上書きしない" do
      credentials = build_credentials(@destination_root)
      run_generator(credentials)
      path = File.join(@destination_root, "config/initializers/pqc_rails.rb")
      File.write(path, "# edited\n")

      run_generator(reloaded(credentials))

      expect(File.read(path)).to eq("# edited\n")
    end
  end

  def reloaded(credentials)
    ActiveSupport::EncryptedConfiguration.new(
      config_path: credentials.content_path.to_s,
      key_path: credentials.key_path.to_s,
      env_key: "RAILS_MASTER_KEY",
      raise_if_missing_key: true
    )
  end
end
