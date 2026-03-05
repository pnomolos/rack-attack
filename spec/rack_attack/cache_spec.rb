# frozen_string_literal: true

require_relative "test_helper"
require "stringio"

describe "Rack::Attack::Cache" do
  before do
    Rack::Attack.clear_configuration
  end

  after do
    Rack::Attack.clear_configuration
    Rack::Attack.instance_variable_set(:@cache, nil)
  end

  # ===========================================================================
  # Store assignment
  # ===========================================================================

  describe "store assignment" do
    it "accepts ActiveSupport::Cache::MemoryStore as a valid store" do
      store = ActiveSupport::Cache::MemoryStore.new
      cache = Rack::Attack::Cache.new(store: store)
      # The store may be wrapped in a proxy, but should not be nil
      _(cache.store).wont_be_nil
    end

    it "accepts nil store (delays error until use)" do
      cache = Rack::Attack::Cache.new(store: nil)
      _(cache.store).must_be_nil
    end

    it "raises MissingStoreError when reading with nil store" do
      cache = Rack::Attack::Cache.new(store: nil)
      _(-> { cache.read("test-key") }).must_raise Rack::Attack::MissingStoreError
    end

    it "raises MissingStoreError when counting with nil store" do
      cache = Rack::Attack::Cache.new(store: nil)
      _(-> { cache.count("test-key", 60) }).must_raise Rack::Attack::MissingStoreError
    end
  end

  # ===========================================================================
  # Store method validation
  # ===========================================================================

  describe "store method validation" do
    it "raises MisconfiguredStoreError when store lacks increment method" do
      bad_store = Object.new
      def bad_store.write(*); end
      def bad_store.read(*); end

      cache = Rack::Attack::Cache.new
      cache.instance_variable_set(:@store, bad_store)

      _(-> { cache.count("test-key", 60) }).must_raise Rack::Attack::MisconfiguredStoreError
    end

    it "raises MisconfiguredStoreError when store lacks read method" do
      bad_store = Object.new
      # Has nothing

      cache = Rack::Attack::Cache.new
      cache.instance_variable_set(:@store, bad_store)

      _(-> { cache.read("test-key") }).must_raise Rack::Attack::MisconfiguredStoreError
    end
  end

  # ===========================================================================
  # increment returning nil edge case
  # ===========================================================================

  describe "increment returning nil" do
    it "falls back to write(1) when increment returns nil" do
      # Create a store whose increment always returns nil (like some stores
      # do for uninitialized keys)
      nil_increment_store = Object.new
      def nil_increment_store.increment(key, amount, expires_in:)
        @last_key = key
        nil
      end
      def nil_increment_store.write(key, value, expires_in:)
        @written = { key: key, value: value }
      end
      def nil_increment_store.read(key)
        nil
      end

      class << nil_increment_store
        attr_reader :last_key, :written
      end

      cache = Rack::Attack::Cache.new
      cache.instance_variable_set(:@store, nil_increment_store)

      result = cache.count("test-key", 60)

      # When increment returns nil, count should return 1 (the fallback write value)
      _(result).must_equal 1
      # And it should have written value=1 to the store
      _(nil_increment_store.written[:value]).must_equal 1
    end

    it "returns the increment result when increment returns a number" do
      counting_store = Object.new
      counting_store.instance_variable_set(:@counts, {})
      def counting_store.increment(key, amount, expires_in:)
        @counts[key] = (@counts[key] || 0) + amount
      end
      def counting_store.write(key, value, expires_in:); end
      def counting_store.read(key); nil; end

      cache = Rack::Attack::Cache.new
      cache.instance_variable_set(:@store, counting_store)

      result1 = cache.count("test-key", 60)
      result2 = cache.count("test-key", 60)

      _(result1).must_equal 1
      _(result2).must_equal 2
    end
  end

  # ===========================================================================
  # Prefix and key generation
  # ===========================================================================

  describe "prefix" do
    it "defaults to 'rack::attack'" do
      cache = Rack::Attack::Cache.new(store: ActiveSupport::Cache::MemoryStore.new)
      _(cache.prefix).must_equal "rack::attack"
    end

    it "can be changed" do
      cache = Rack::Attack::Cache.new(store: ActiveSupport::Cache::MemoryStore.new)
      cache.prefix = "custom::prefix"
      _(cache.prefix).must_equal "custom::prefix"
    end
  end

  # ===========================================================================
  # reset! behavior
  # ===========================================================================

  describe "reset!" do
    it "raises IncompatibleStoreError when store lacks delete_matched" do
      store = Object.new
      def store.increment(*); 1; end
      def store.write(*); end
      def store.read(*); end

      cache = Rack::Attack::Cache.new
      cache.instance_variable_set(:@store, store)

      _(-> { cache.reset! }).must_raise Rack::Attack::IncompatibleStoreError
    end

    it "works when store has delete_matched" do
      store = ActiveSupport::Cache::MemoryStore.new
      cache = Rack::Attack::Cache.new(store: store)

      # Write something, then reset
      cache.write("test-key", "value", 60)
      cache.reset!

      # After reset, the key should be gone
      _(cache.read("test-key")).must_be_nil
    end
  end
end
