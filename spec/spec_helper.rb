# frozen_string_literal: true

require_relative "../lib/pqc_rails"

RSpec.configure do |config|
  # rspec-expectationsの構文を厳密化(should記法を禁止し、expect記法のみ許可)
  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end

  # mocks使用時の警告を厳格化
  config.mock_with :rspec do |mocks|
    mocks.verify_partial_doubles = true
  end

  # 1テストファイルにつき1つのトップレベルdescribe/contextを強制しない(柔軟性のため)
  config.shared_context_metadata_behavior = :apply_to_host_groups

  # ランダム順序でテストを実行し、テスト間の隠れた依存を検出しやすくする
  config.order = :random
  Kernel.srand config.seed
end