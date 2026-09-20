# frozen_string_literal: true

# liboqsをソースからビルドし、ビルド済み共有ライブラリをこのディレクトリ(拡張の出力先)に
# コピーする。RubyGemsの拡張ビルド機構(Gem::Ext::Builder)は最終的に`make`/`make install`を
# 呼び出す前提のため、実体のビルドはこのファイル内で完結させ、Makefileはそれを素通りさせる
# ダミーとして生成する(CMake依存のCライブラリを`mkmf`のExtensionビルドに乗せる際の定石)。
#
# プロトタイプの位置づけ(2026-09-20、Phase5 Step3):
# - 対象は1プラットフォーム(macOS arm64)のみ。他OS/アーキテクチャは未検証
# - liboqsのソースはこのビルド時にgit cloneで取得する(pinされたタグ)。本実装では
#   gemパッケージ自体にソースを同梱する方式に置き換える必要がある(このファイルの末尾コメント参照)

require "fileutils"
require "etc"

LIBOQS_TAG = "0.15.0"
EXT_DIR = __dir__
SRC_DIR = File.join(EXT_DIR, "liboqs-src")
BUILD_DIR = File.join(EXT_DIR, "liboqs-build")

def sh!(cmd)
  puts "-- #{cmd}"
  system(cmd) || abort("command failed: #{cmd}")
end

if ENV["PQC_RAILS_SKIP_LIBOQS_BUILD"] == "1"
  puts "PQC_RAILS_SKIP_LIBOQS_BUILD=1: liboqsの自動ビルドをスキップします。" \
       "PqcRails.configure { |c| c.liboqs_path = ... } で既存のliboqsを明示的に指定してください。"
else
  unless File.directory?(SRC_DIR)
    sh!("git clone --branch #{LIBOQS_TAG} --depth 1 " \
        "https://github.com/open-quantum-safe/liboqs.git #{SRC_DIR}")
  end

  sh!("cmake -S #{SRC_DIR} -B #{BUILD_DIR} " \
      "-DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON")
  sh!("cmake --build #{BUILD_DIR} --target oqs -- -j#{Etc.nprocessors}")

  built_lib = Dir.glob(File.join(BUILD_DIR, "lib", "liboqs.*dylib")).first ||
              Dir.glob(File.join(BUILD_DIR, "lib", "liboqs.so*")).first
  abort("liboqsのビルド成果物が見つかりません(#{BUILD_DIR}/lib)") unless built_lib

  dest_name = built_lib.end_with?(".so") || built_lib.include?(".so.") ? "liboqs.so" : "liboqs.dylib"
  FileUtils.cp(built_lib, File.join(EXT_DIR, dest_name))
  puts "-- installed #{dest_name} into #{EXT_DIR}"
end

# RubyGemsの拡張ビルドは `make` → `make install` の順で呼ぶため、
# 何もしない(既にビルド済み成果物をコピーし終えている)ダミーのMakefileを生成する。
File.write(File.join(EXT_DIR, "Makefile"), <<~MAKEFILE)
  all:
  \ttrue
  install:
  \ttrue
  clean:
  \ttrue
MAKEFILE

# 本実装(Phase5 Step3の本番版)で検討すべき変更点:
# - git cloneではなくgemパッケージ自体にliboqsソースを同梱する(ネットワーク依存を無くす)
# - `--skip-liboqs`をbundle configの正式なオプションとして提供する(現状はENV変数の代用)
# - 複数プラットフォーム(Linux、Windows)・複数アーキテクチャへの対応
# - liboqs(MIT)の著作権表示・NOTICE集約(PENDING.md Step3参照)
