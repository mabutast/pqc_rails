# frozen_string_literal: true

require "yaml"

# README.mdの「動作確認済み環境」節が主張するRuby/Rails/liboqsの組み合わせが、実際にCIで
# 検証されている組み合わせと一致しているかを検証する(対外公開文書とコードの一致監査、Tier1)。
# 「CIで継続的に検証しています」という文言自体が対外公開文書上の主張であり、その主張の裏付けである
# .github/workflows/test.ymlのマトリクス定義と食い違えば、README側の記述が古いか、CI側の
# マトリクスを変更した際にREADMEの更新を忘れたことを意味する。
RSpec.describe "README.mdの「動作確認済み環境」とCIマトリクスの一致" do
  let(:readme) { File.read(File.expand_path("../../README.md", __dir__)) }
  let(:workflow) { YAML.load_file(File.expand_path("../../.github/workflows/test.yml", __dir__)) }
  let(:matrix) { workflow["jobs"]["rspec-matrix"]["strategy"]["matrix"] }

  def environment_section(readme)
    body = readme[/^## 動作確認済み環境\n(.*?)(?=\n## )/m, 1]
    raise "README.mdに「## 動作確認済み環境」セクションが見つからない(抽出パターン自体が壊れている可能性)" unless body

    body
  end

  def readme_versions_after(label, readme)
    line = environment_section(readme).lines.find { |l| l.start_with?("- #{label} ") }
    raise "「- #{label} 」で始まる行が「動作確認済み環境」節に見つからない(抽出パターン自体が壊れている可能性)" unless line

    line.delete_prefix("- #{label} ").strip.split(" / ")
  end

  it "READMEに書かれたRubyバージョンの一覧がCIマトリクスと一致する" do
    expect(readme_versions_after("Ruby", readme)).to eq(matrix["ruby"])
  end

  it "READMEに書かれたRailsバージョンの一覧がCIマトリクスと一致する" do
    expect(readme_versions_after("Rails", readme)).to eq(matrix["rails"])
  end

  it "READMEに書かれたliboqsバージョンの一覧がCIマトリクス(基本+include)と一致する" do
    ci_liboqs_versions = (matrix["liboqs"] + matrix["include"].map { |entry| entry["liboqs"] }).uniq

    expect(readme_versions_after("liboqs", readme)).to eq(ci_liboqs_versions)
  end

  it "gemspecのrequired_ruby_versionの下限が、READMEの最小Rubyバージョンと矛盾しない" do
    lowest_readme_ruby = readme_versions_after("Ruby", readme).first
    gemspec = Gem::Specification.load(File.expand_path("../../pqc_rails.gemspec", __dir__))

    expect(gemspec.required_ruby_version.satisfied_by?(Gem::Version.new("#{lowest_readme_ruby}.0"))).to be(true)
  end
end
