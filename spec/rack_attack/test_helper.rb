# frozen_string_literal: true

# Standalone test helper that doesn't require bundler/setup
require "logger"
require "minitest/autorun"
require "minitest/pride"
require "rack/test"
require "active_support"
require "rack/attack"

class Minitest::Spec
  include Rack::Test::Methods

  before do
    if Object.const_defined?(:Rails) && Rails.respond_to?(:cache) && Rails.cache.respond_to?(:clear)
      Rails.cache.clear
    end
  end

  after do
    Rack::Attack.clear_configuration
    Rack::Attack.instance_variable_set(:@cache, nil)
  end

  def app
    Rack::Builder.new do
      use Rack::Lint
      use Rack::Attack
      use Rack::Attack
      use Rack::Lint

      run lambda { |_env| [200, {}, ['Hello World']] }
    end.to_app
  end
end
