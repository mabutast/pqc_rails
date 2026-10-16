# frozen_string_literal: true

require "spec_helper"
require "tmpdir"
require_relative "../../ext/pqc_rails/build_shell"

RSpec.describe PqcRails::BuildShell do
  describe ".sh!" do
    around do |example|
      Dir.mktmpdir("pqc rails build") do |dir|
        @dir = dir
        example.run
      end
    end

    before { allow($stdout).to receive(:puts) }

    context "引数にシェルのメタ文字が含まれる場合" do
      it "シェルを経由せず、引数をそのまま1つの値として渡す" do
        Dir.chdir(@dir) { described_class.sh!("touch", "x; touch injected") }

        expect(Dir.children(@dir)).to contain_exactly("x; touch injected")
      end
    end

    context "パスにスペースが含まれる場合" do
      it "スペースで分割せずに1つのパスとして扱う" do
        described_class.sh!("mkdir", File.join(@dir, "with space"))

        expect(File).to be_directory(File.join(@dir, "with space"))
      end
    end

    context "コマンドが失敗した場合" do
      it "abortで処理を止める" do
        expect { described_class.sh!("false") }.to raise_error(SystemExit)
      end
    end
  end

  describe ".capture" do
    it "シェルを経由せずにコマンドを実行し、標準出力を返す" do
      expect(described_class.capture("printf", "%s", "a; echo b")).to eq("a; echo b")
    end
  end
end
