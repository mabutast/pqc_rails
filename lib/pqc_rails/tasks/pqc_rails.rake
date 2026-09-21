# frozen_string_literal: true

namespace :pqc_rails do
  desc "Check pqc_rails' runtime configuration (keys, session store, ActiveRecord::Encryption)"
  task status: :environment do
    results = PqcRails::StatusCheck.run

    results.each do |result|
      icon = result.ok ? "✅" : "❌"
      puts "#{icon} #{result.name}: #{result.detail}"
    end

    exit(1) if results.any? { |result| !result.ok }
  end
end
