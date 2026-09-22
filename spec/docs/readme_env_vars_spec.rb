# frozen_string_literal: true

# README.mdに書かれた環境変数名・credentialsキー名が、実際のソースコードの定数と一致しているかを
# 機械的に検証する(対外公開文書とコードの一致監査、Tier1)。バックティックで囲まれた
# PQC_*/pqc_*_key(s) 表記をREADMEから抽出し、実際の定数と突き合わせる。
RSpec.describe "README.mdの環境変数名・credentialsキー名" do
  let(:readme) { File.read(File.expand_path("../../README.md", __dir__)) }

  let(:actual_env_vars) do
    [
      PqcRails::Session::KeyManager::ENV_VAR,
      PqcRails::Session::KeyManager::PREVIOUS_ENV_VAR,
      PqcRails::ActiveRecord::KeyProvider::ENV_VAR,
      PqcRails::ActiveRecord::KeyProvider::PREVIOUS_ENV_VAR
    ].sort
  end

  let(:actual_credentials_keys) do
    [
      PqcRails::Session::KeyManager::CREDENTIALS_KEY,
      PqcRails::Session::KeyManager::PREVIOUS_CREDENTIALS_KEY,
      PqcRails::ActiveRecord::KeyProvider::CREDENTIALS_KEY,
      PqcRails::ActiveRecord::KeyProvider::PREVIOUS_CREDENTIALS_KEY
    ].map(&:to_s).sort
  end

  it "READMEがバックティックで言及する環境変数名は、すべて実在の定数のいずれかと一致する" do
    mentioned = readme.scan(/`(PQC_[A-Z_]+)`/).flatten.uniq

    expect(mentioned).not_to be_empty # 抽出パターン自体が壊れていないことの素朴な確認
    expect(mentioned - actual_env_vars).to eq([])
  end

  it "READMEがバックティックで言及するcredentialsキー名は、すべて実在の定数のいずれかと一致する" do
    mentioned = readme.scan(/`(pqc_(?:session|record)(?:_previous)?_keys?)`/).flatten.uniq

    expect(mentioned).not_to be_empty
    expect(mentioned - actual_credentials_keys).to eq([])
  end
end
