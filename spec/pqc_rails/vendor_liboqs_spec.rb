# frozen_string_literal: true

require "spec_helper"
require "tmpdir"
require "fileutils"
require_relative "../../ext/pqc_rails/vendor_liboqs"

RSpec.describe PqcRails::VendorLiboqs do
  around do |example|
    Dir.mktmpdir("vendor_liboqs") do |dir|
      @dir = dir
      example.run
    end
  end

  def write(root, path, content)
    full = File.join(root, path)
    FileUtils.mkdir_p(File.dirname(full))
    File.write(full, content)
  end

  describe ".tree_differences" do
    let(:upstream) { File.join(@dir, "upstream") }
    let(:vendored) { File.join(@dir, "vendored") }

    before do
      write(upstream, "CMakeLists.txt", "cmake")
      write(upstream, "src/kem/ml_kem/kem.c", "int x;")
      write(upstream, ".clang-format", "style")
      write(upstream, "tests/test_kem.c", "test")
      write(upstream, ".git/HEAD", "ref")
      FileUtils.cp_r(upstream, vendored)
      FileUtils.rm_rf([File.join(vendored, "tests"), File.join(vendored, ".git")])
      write(vendored, described_class::MARKER_FILE, "0.16.0\n")
    end

    it "同梱から除いたディレクトリと同梱の目印のファイルを除けば一致する時は、空を返す" do
      expect(described_class.tree_differences(upstream, vendored)).to be_empty
    end

    it "内容が書き換えられたファイルを報告する" do
      write(vendored, "src/kem/ml_kem/kem.c", "int y;")

      expect(described_class.tree_differences(upstream, vendored)).to eq(["changed: src/kem/ml_kem/kem.c"])
    end

    it "上流にあって同梱に無いファイルと、同梱にだけあるファイルを報告する" do
      FileUtils.rm(File.join(vendored, "CMakeLists.txt"))
      write(vendored, "src/kem/ml_kem/backdoor.c", "evil")

      expect(described_class.tree_differences(upstream, vendored))
        .to contain_exactly("missing: CMakeLists.txt", "extra: src/kem/ml_kem/backdoor.c")
    end
  end

  describe ".verify_commit!" do
    let(:repo) { File.join(@dir, "repo") }
    let(:head) do
      FileUtils.mkdir_p(repo)
      git = ["git", "-C", repo, "-c", "user.name=t", "-c", "user.email=t@example.com"]
      system(*git, "init", "-q", exception: true)
      write(repo, "README.md", "x")
      system(*git, "add", ".", exception: true)
      system(*git, "commit", "-q", "-m", "init", exception: true)
      IO.popen(["git", "-C", repo, "rev-parse", "HEAD"], &:read).strip
    end

    it "取得したソースのコミットが固定した値と一致すれば、何もしない" do
      expect { described_class.verify_commit!(repo, expected: head) }.not_to raise_error
    end

    it "一致しなければビルドを止める(タグが付け替えられた場合など)" do
      head
      expect do
        described_class.verify_commit!(repo, expected: "0" * 40)
      end.to raise_error(SystemExit).and output(/does not match the pinned commit/).to_stderr
    end
  end

  it "固定したコミットは40桁の16進数で、TAGと一緒に更新する" do
    expect(described_class::COMMIT).to match(/\A\h{40}\z/)
  end
end
