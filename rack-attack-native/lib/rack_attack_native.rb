# frozen_string_literal: true

require_relative "rack_attack_native/version"

begin
  require_relative "rack_attack_native/rack_attack_native"
rescue LoadError => e
  warn "Failed to load rack_attack_native native extension: #{e.message}"
  raise
end
