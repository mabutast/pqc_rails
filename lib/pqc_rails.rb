# frozen_string_literal: true

module PqcRails
  class Error < StandardError; end
end

require_relative "pqc_rails/version"
require_relative "pqc_rails/configuration"
require_relative "pqc_rails/kem"
require_relative "pqc_rails/sig"
