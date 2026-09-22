# frozen_string_literal: true

# README.md「使い方」節に載っている実行可能なRubyコード例(```ruby フェンス)を実際に実行し、
# 各行末尾の `# => 値` というコメントが本当にその通りの値になるかを検証する、いわゆる
# doctest(対外公開文書とコードの一致監査、Tier2)。
#
# フェンスの抽出は行番号ではなく「コードの先頭が何で始まるか」で行う。README中のプロース(周辺の
# 説明文)が増減しても、コード自体の中身が変わらない限り抽出が壊れないようにするため。
#
# READMEの例の中には、直前のコード例が定義した変数(sig・keypair・signature等)を参照する
# 「地の文としては続きだが、実際にはRubyのブロックスコープの外」という書き方をしている箇所が
# 1つある(署名の改竄検知の例)。これは自動検出せず、該当ペアだけ明示的に「直前の例のendの前に
# 差し込む」と手動で指定してある(README全体を対象にした汎用的な自動結合は、結合すべきでない
# 独立した例まで誤って結合してしまう危険があるため、あえて自動化していない)。
RSpec.describe "READMEの「使い方」節に記載されたコード例(doctest)" do
  readme = File.read(File.expand_path("../../README.md", __dir__))
  RUBY_BLOCKS = readme.scan(/```ruby\n(.*?)```/m).map(&:first).freeze

  def find_block(prefix)
    block = RUBY_BLOCKS.find { |code| code.start_with?(prefix) }
    raise "README.md中に「#{prefix}」で始まるrubyコードブロックが見つからない(README側の変更で抽出パターンが壊れた可能性)" unless block

    block
  end

  # `expr # => 値` という行を、実行時に値を検証しつつ元の値をそのまま返す形へ書き換える。
  # 値の表記のうしろに日本語の補足(「（約255KBの略）」等)が続いていても、先頭のRubyリテラル
  # 部分だけを期待値として取り出す。
  ASSERTION_LINE = /\A(?<indent>\s*)(?<expr>.+?)\s*#\s*=>\s*(?<expected>true|false|nil|-?\d+|"[^"]*"|:\w+)/

  def instrument(source)
    source.lines.map do |line|
      match = ASSERTION_LINE.match(line)
      next line unless match

      "#{match[:indent]}__assert__.call((#{match[:expr]}), (#{match[:expected]}), #{line.strip.dump})\n"
    end.join
  end

  def run_example(source)
    failures = []
    assert = lambda do |actual, expected, source_line|
      failures << "#{source_line} => actual #{actual.inspect}, expected #{expected.inspect}" unless actual == expected
      actual
    end

    doctest_binding = binding
    doctest_binding.local_variable_set(:__assert__, assert)
    eval(instrument(source), doctest_binding, "README.md(doctest)") # rubocop:disable Security/Eval

    failures
  end

  it "アルゴリズムのシンボル指定の例が構文エラーなく実行できる" do
    source = find_block('PqcRails::Kem.new(:ml_kem_512)')

    expect { eval(source, binding) }.not_to raise_error # rubocop:disable Security/Eval
  end

  it "Classic McEliece-348864の公開鍵サイズが、書かれている値と一致する" do
    source = find_block('PqcRails::Kem.open("Classic-McEliece-348864")')

    expect(run_example(source)).to eq([])
  end

  it "HQC-1の公開鍵サイズが、書かれている値と一致する(liboqsがHQCを有効化してビルドされている場合のみ)" do
    # HQCはliboqs 0.16.0以降でデフォルト有効(0.15.0はデフォルト無効、OQS_ENABLE_KEM_HQC=OFF)。
    # pqc_rails自身がbundle installで自動ビルドする既定のliboqsは0.15.0のため、この例は
    # デフォルト設定では動かない(README側にもその旨の注記がある)。CI環境によってHQCの有無が
    # 変わりうるので、無効な場合はテスト自体をスキップし、有効な場合のみ値を検証する。
    source = find_block('PqcRails::Kem.open("HQC-1")')

    begin
      PqcRails::Kem.new("HQC-1").free
    rescue PqcRails::Error
      skip "このliboqsビルドではHQCが無効化されている(liboqs 0.15.0のデフォルト、既知の制約)"
    end

    expect(run_example(source)).to eq([])
  end

  it "KEMの基本フローの例が、書かれている通りに動く" do
    source = find_block('PqcRails::Kem.open("ML-KEM-512") do |kem|')

    expect(run_example(source)).to eq([])
  end

  it "KEMの手動リソース管理の例(new/free)が構文エラーなく実行できる" do
    source = find_block('kem = PqcRails::Kem.new("ML-KEM-512")')

    expect { eval(source, binding) }.not_to raise_error # rubocop:disable Security/Eval
  end

  it "KEMの鍵長参照の例が、書かれている値と一致する" do
    source = find_block('kem = PqcRails::Kem.new("ML-KEM-512")' + "\nkem.length_public_key")

    expect(run_example(source)).to eq([])
  end

  it "Sigの基本フロー+改竄検知の例が、書かれている通りに動く(2つのコードブロックを結合)" do
    main_flow = find_block('PqcRails::Sig.open("ML-DSA-44") do |sig|')
    tampered_check = find_block('sig.verify("tampered message"')

    # 改竄検知の例はブロックスコープの外に書かれているが、実際にはmain_flowのsig.openブロック内で
    # 定義されたsig/keypair/signatureを参照する続きの例。main_flowの末尾のendの直前に差し込む。
    merged = main_flow.sub(/\nend\n\z/, "\n  #{tampered_check.strip}\nend\n")

    expect(run_example(merged)).to eq([])
  end

  it "Sigの鍵長・署名長参照の例が、書かれている値と一致する" do
    source = find_block('sig = PqcRails::Sig.new("ML-DSA-44")')

    expect(run_example(source)).to eq([])
  end
end
