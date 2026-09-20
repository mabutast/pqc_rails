# frozen_string_literal: true

# liboqsのソースを`rake vendor:liboqs`実行時にダウンロードし、gemパッケージに同梱する
# ext/pqc_rails/vendor/liboqs/ へ展開するスクリプト。エンドユーザーの`bundle install`時に
# ネットワーク取得が発生しないようにするため、この処理はgemのリリース作業(`gem build`前)で
# メンテナが一度だけ実行する運用とする(release-checklist.html参照)。
#
# テスト・ドキュメント・言語バインディング関連ディレクトリ(tests/docs/scripts/zephyr/cpp)は
# コアライブラリのCMakeビルド(OQS_BUILD_ONLY_LIB=ON)には不要なため除外し、同梱サイズを抑える。
# アルゴリズムファミリごとのサブディレクトリ(src/kem/*, src/sig/*)は、CMakeLists.txtの
# add_subdirectory呼び出しが無条件に存在を前提とする構造のため、全て残す
# (ML-KEM/ML-DSAだけに絞り込むにはCMakeLists.txt自体の改変が必要になり、liboqsのバージョン
# アップごとに追従コストが発生するため見送った。判断の詳細は同日付のナレッジHTML参照)。

require "fileutils"
require "tmpdir"

module PqcRails
  module VendorLiboqs
    TAG = "0.15.0"
    EXCLUDE_TOP_LEVEL = %w[.git tests docs scripts zephyr cpp].freeze
    VENDOR_DIR = File.expand_path("vendor/liboqs", __dir__)

    module_function

    def run
      Dir.mktmpdir do |tmp|
        clone_dir = File.join(tmp, "liboqs")
        sh!("git clone --branch #{TAG} --depth 1 " \
            "https://github.com/open-quantum-safe/liboqs.git #{clone_dir}")

        FileUtils.rm_rf(VENDOR_DIR)
        FileUtils.mkdir_p(VENDOR_DIR)

        entries = Dir.children(clone_dir) - EXCLUDE_TOP_LEVEL
        entries.each do |entry|
          FileUtils.cp_r(File.join(clone_dir, entry), File.join(VENDOR_DIR, entry))
        end

        File.write(File.join(VENDOR_DIR, "PQC_RAILS_VENDOR_TAG"), "#{TAG}\n")
      end

      size = `du -sh #{VENDOR_DIR}`.split.first
      puts "-- vendored liboqs #{TAG} into #{VENDOR_DIR} (#{size})"
    end

    def sh!(cmd)
      puts "-- #{cmd}"
      system(cmd) || abort("command failed: #{cmd}")
    end
  end
end
