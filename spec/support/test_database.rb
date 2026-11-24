# frozen_string_literal: true

require "active_record"
require "sqlite3"

# ActiveRecordのspecが使うDBへ接続する。PQC_TEST_DATABASE_URLがあればそのDB、無ければSQLiteのメモリ上のDB。
module TestDatabase
  def self.connect
    url = ENV.fetch("PQC_TEST_DATABASE_URL", nil)
    ::ActiveRecord::Base.establish_connection(url || { adapter: "sqlite3", database: ":memory:" })
  end
end
