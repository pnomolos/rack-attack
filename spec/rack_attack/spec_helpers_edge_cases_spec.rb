# frozen_string_literal: true

require_relative "test_helper"
require "rack/attack/spec_helpers/minitest"

describe "MinitestHelpers failure messages" do
  include Rack::Attack::MinitestHelpers

  before do
    Rack::Attack.clear_configuration
    Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
  end

  after do
    Rack::Attack.clear_configuration
    Rack::Attack.instance_variable_set(:@cache, nil)
  end

  describe "assert_safelisted" do
    it "fails with helpful message when not safelisted" do
      Rack::Attack.blocklist("block-it") { |req| req.ip == "6.6.6.6" }

      err = assert_raises(Minitest::Assertion) do
        assert_safelisted(ip: "6.6.6.6")
      end
      _(err.message).must_match(/safelisted/)
    end
  end

  describe "assert_blocklisted" do
    it "fails with helpful message when no rules configured" do
      err = assert_raises(Minitest::Assertion) do
        assert_blocklisted(ip: "1.2.3.4")
      end
      _(err.message).must_match(/blocklisted/)
    end
  end

  describe "assert_throttled_after" do
    it "fails when no throttle matches request path" do
      Rack::Attack.throttle("login-limit", limit: 5, period: 60) do |req|
        req.ip if req.path == "/login"
      end

      err = assert_raises(Minitest::Assertion) do
        assert_throttled_after(5, path: "/other", ip: "1.2.3.4")
      end
      _(err.message).must_match(/throttle/)
    end
  end

  describe "assert_allowed" do
    it "passes with no rules configured" do
      assert_allowed(ip: "1.2.3.4", path: "/anything")
    end
  end

  describe "assert_blocklisted_by" do
    it "fails with helpful message when wrong rule matches" do
      Rack::Attack.blocklist("rule-a") { |req| req.ip == "6.6.6.6" }
      Rack::Attack.blocklist("rule-b") { |req| req.ip == "9.9.9.9" }

      err = assert_raises(Minitest::Assertion) do
        assert_blocklisted_by("rule-b", ip: "6.6.6.6")
      end
      _(err.message).must_match(/rule-a/)
    end
  end
end
