# frozen_string_literal: true

require_relative "lib/rack_attack_native/version"

Gem::Specification.new do |spec|
  spec.name = "rack-attack-native"
  spec.version = RackAttackNative::VERSION
  spec.authors = ["Rack::Attack contributors"]
  spec.summary = "Native Rust rule engine for Rack::Attack"
  spec.description = "A compiled Rust extension that evaluates declarative JSON WAF rules for Rack::Attack, " \
                     "providing significant speedup for CIDR matching, regex evaluation, and rule engine throughput."
  spec.homepage = "https://github.com/rack/rack-attack"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.0.0"

  spec.files = Dir["lib/**/*.rb", "ext/**/*.{rs,toml,rb,lock}", "LICENSE", "README.md"]
  spec.require_paths = ["lib"]
  spec.extensions = ["ext/rack_attack_native/extconf.rb"]

  spec.add_dependency "rb_sys", "~> 0.9"

  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rake-compiler", "~> 1.2"
  spec.add_development_dependency "minitest", "~> 5.0"
  spec.add_development_dependency "benchmark-ips", "~> 2.12"
end
