# frozen_string_literal: true

module PqcRails
  # liboqsのビルド・同梱スクリプト(extconf.rb / vendor_liboqs.rb)が外部コマンドを実行する共通処理。
  #
  # コマンドは引数の配列として受け取り、シェルを経由せずに実行する。gemのインストール先パスなど
  # コマンドに埋め込む値にスペースやシェルのメタ文字(`;`・`$()`等)が含まれていても、
  # 分割・解釈されず1つの引数としてそのまま渡る。
  module BuildShell
    module_function

    # コマンドを実行し、失敗したらabortでビルドを止める。
    def sh!(*cmd)
      puts "-- #{cmd.join(' ')}"
      system(*cmd) || abort("command failed: #{cmd.join(' ')}")
    end

    # コマンドを実行し、標準出力を文字列で返す。
    def capture(*cmd)
      IO.popen(cmd, &:read)
    end
  end
end
