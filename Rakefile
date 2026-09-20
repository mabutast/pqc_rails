# frozen_string_literal: true

require "bundler/gem_tasks"
task default: %i[]

namespace :vendor do
  desc "Vendor liboqs source into ext/pqc_rails/vendor/liboqs for gem packaging (run before gem build)"
  task :liboqs do
    require_relative "ext/pqc_rails/vendor_liboqs"
    PqcRails::VendorLiboqs.run
  end
end
