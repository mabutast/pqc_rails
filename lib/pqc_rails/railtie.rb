# frozen_string_literal: true

require "rails/railtie"

module PqcRails
  # `rails pqc_rails:status` を提供するためだけのRailtie。
  class Railtie < ::Rails::Railtie
    rake_tasks do
      load File.expand_path("tasks/pqc_rails.rake", __dir__)
    end
  end
end
