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

# 取得したソースが改ざんされていないことは、2段階で確かめる。
#   1. clone直後に、HEADのコミットがCOMMITと一致するかを見る(上流でタグが付け替えられても気づける)
#   2. `rake vendor:verify`で、同梱済みのディレクトリを上流の同じコミットとファイルごとに比べる
#      (gemを`gem unpack`したディレクトリも DIR= で渡せる)
#
# TAGを上げる時は、COMMITも`git ls-remote https://github.com/open-quantum-safe/liboqs.git refs/tags/<TAG>`
# の値に更新する(注釈付きタグなら`refs/tags/<TAG>^{}`の値)。

require "digest"
require "fileutils"
require "tmpdir"
require_relative "build_shell"

module PqcRails
  module VendorLiboqs
    TAG = "0.16.0"
    COMMIT = "5a1a854b0dc9f2141bdc771c555ee60c37950183" # pragma: allowlist secret
    UPSTREAM_URL = "https://github.com/open-quantum-safe/liboqs.git"
    EXCLUDE_TOP_LEVEL = %w[.git tests docs scripts zephyr cpp].freeze
    MARKER_FILE = "PQC_RAILS_VENDOR_TAG"
    VENDOR_DIR = File.expand_path("vendor/liboqs", __dir__)

    module_function

    def run
      with_upstream_checkout do |clone_dir|
        FileUtils.rm_rf(VENDOR_DIR)
        FileUtils.mkdir_p(VENDOR_DIR)

        entries = Dir.children(clone_dir) - EXCLUDE_TOP_LEVEL
        entries.each do |entry|
          FileUtils.cp_r(File.join(clone_dir, entry), File.join(VENDOR_DIR, entry))
        end

        File.write(File.join(VENDOR_DIR, MARKER_FILE), "#{TAG}\n")
      end

      size = BuildShell.capture("du", "-sh", VENDOR_DIR).split.first
      puts "-- vendored liboqs #{TAG} (#{COMMIT}) into #{VENDOR_DIR} (#{size})"
    end

    # 同梱済みのディレクトリが、上流のCOMMITと(除外したディレクトリを除いて)一致するかを確かめる。
    # 一致しなければ違いを表示してabortする。
    def verify(vendored_dir = VENDOR_DIR)
      abort("#{vendored_dir} がありません。先に rake vendor:liboqs を実行してください。") unless File.directory?(vendored_dir)

      differences = with_upstream_checkout { |clone_dir| tree_differences(clone_dir, vendored_dir) }
      if differences.empty?
        puts "-- #{vendored_dir} matches liboqs #{TAG} (#{COMMIT})"
      else
        warn differences.first(50).join("\n")
        abort("#{vendored_dir} differs from liboqs #{TAG} (#{COMMIT}) in #{differences.size} file(s)")
      end
    end

    # 上流のTAGをshallow cloneし、コミットを確かめてからブロックに渡す。
    def with_upstream_checkout
      Dir.mktmpdir do |tmp|
        clone_dir = File.join(tmp, "liboqs")
        BuildShell.sh!("git", "clone", "--quiet", "--branch", TAG, "--depth", "1", UPSTREAM_URL, clone_dir)
        verify_commit!(clone_dir)
        yield clone_dir
      end
    end

    def verify_commit!(dir, expected: COMMIT)
      actual = BuildShell.capture("git", "-C", dir, "rev-parse", "HEAD").strip
      return if actual == expected

      abort("liboqs #{TAG} resolved to #{actual}, which does not match the pinned commit #{expected}")
    end

    # 上流のチェックアウトと同梱済みのディレクトリを比べ、違いを "changed: path" / "missing: path" /
    # "extra: path" の形で返す。上流側はEXCLUDE_TOP_LEVELを、同梱側はMARKER_FILEを比較の対象から除く。
    def tree_differences(upstream_dir, vendored_dir)
      upstream = fingerprints(upstream_dir) { |path| EXCLUDE_TOP_LEVEL.include?(path.split("/").first) }
      vendored = fingerprints(vendored_dir) { |path| path == MARKER_FILE }

      changed = (upstream.keys & vendored.keys).reject { |path| upstream[path] == vendored[path] }
      changed.map { |path| "changed: #{path}" } +
        (upstream.keys - vendored.keys).map { |path| "missing: #{path}" } +
        (vendored.keys - upstream.keys).map { |path| "extra: #{path}" }
    end

    # ディレクトリ配下のファイルの相対パスから、内容のSHA-256(シンボリックリンクはリンク先)への対応を返す。
    # ブロックがtrueを返すパスは除く。
    def fingerprints(root)
      Dir.glob("**/*", File::FNM_DOTMATCH, base: root).sort.each_with_object({}) do |path, result|
        next if File.basename(path) == "." || yield(path)

        full = File.join(root, path)
        if File.symlink?(full)
          result[path] = "symlink:#{File.readlink(full)}"
        elsif File.file?(full)
          result[path] = Digest::SHA256.file(full).hexdigest
        end
      end
    end
  end
end
