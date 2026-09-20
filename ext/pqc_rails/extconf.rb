# frozen_string_literal: true

# liboqsをビルドし、ビルド済み共有ライブラリをこのディレクトリ(拡張の出力先)にコピーする。
# RubyGemsの拡張ビルド機構(Gem::Ext::Builder)は最終的に`make`/`make install`を呼び出す前提のため、
# 実体のビルドはこのファイル内で完結させ、Makefileはそれを素通りさせるダミーとして生成する
# (CMake依存のCライブラリを`mkmf`のExtensionビルドに乗せる際の定石)。
#
# ソースの取得元は2通り:
#   1. vendor/liboqs/ (rake vendor:liboqs でリリース前に取得・gemに同梱済み) — 通常の利用者はこちら
#   2. 上記が無い場合はgit cloneでその場取得する(コントリビュータがvendorタスクを走らせずに
#      specを動かす開発時用のフォールバック。リリースされたgemでは発生しない想定)
#
# 対応プラットフォーム: macOS arm64・Linux(x86_64/arm64、Docker/Colimaで検証)で確認済み。
# Windowsは未検証。詳細は~/knowledge/pqc_rails/2026-09-20-phase5-step3-liboqs-bundle-prototype.html
# (プロトタイプ)・同日付の本実装ナレッジHTML参照。

require "fileutils"
require "etc"

EXT_DIR = __dir__
VENDOR_DIR = File.join(EXT_DIR, "vendor", "liboqs")
DEV_CLONE_TAG = "0.15.0"
DEV_CLONE_DIR = File.join(EXT_DIR, "liboqs-src")
BUILD_DIR = File.join(EXT_DIR, "liboqs-build")

def sh!(cmd)
  puts "-- #{cmd}"
  system(cmd) || abort("command failed: #{cmd}")
end

def skip_build?
  ENV["PQC_RAILS_SKIP_LIBOQS_BUILD"] == "1" || ARGV.include?("--skip-liboqs")
end

def liboqs_source_dir
  return VENDOR_DIR if File.directory?(VENDOR_DIR)

  puts "-- vendor/liboqs が見つかりません。開発時フォールバックとしてgit cloneします" \
       "(リリースされたgemではこの経路は通らない想定。メンテナは`rake vendor:liboqs`を実行してください)"
  unless File.directory?(DEV_CLONE_DIR)
    sh!("git clone --branch #{DEV_CLONE_TAG} --depth 1 " \
        "https://github.com/open-quantum-safe/liboqs.git #{DEV_CLONE_DIR}")
  end
  DEV_CLONE_DIR
end

if skip_build?
  puts "liboqsの自動ビルドをスキップします(--skip-liboqs / PQC_RAILS_SKIP_LIBOQS_BUILD=1)。" \
       "PqcRails.configure { |c| c.liboqs_path = ... } で既存のliboqsを明示的に指定してください。"
else
  src_dir = liboqs_source_dir

  sh!("cmake -S #{src_dir} -B #{BUILD_DIR} " \
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
