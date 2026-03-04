# frozen_string_literal: true

require "rack/attack"

module Rack
  class Attack
    module RSpecMatchers
      def request(**opts)
        opts
      end

      RSpec::Matchers.define :be_safelisted do
        match do |request_opts|
          @result = Rack::Attack.simulate(**request_opts)
          @result.safelisted?
        end

        failure_message do
          "expected request to be safelisted, but outcome was :#{@result.outcome}"
        end

        failure_message_when_negated do
          "expected request not to be safelisted, but it was safelisted by \"#{@result.safelisted_by}\""
        end
      end

      RSpec::Matchers.define :be_safelisted_by do |expected_name|
        match do |request_opts|
          @result = Rack::Attack.simulate(**request_opts)
          @result.safelisted_by == expected_name
        end

        failure_message do
          "expected request to be safelisted by \"#{expected_name}\", but safelisted_by was #{@result.safelisted_by.inspect}"
        end
      end

      RSpec::Matchers.define :be_blocklisted do
        match do |request_opts|
          @result = Rack::Attack.simulate(**request_opts)
          @result.blocklisted?
        end

        failure_message do
          "expected request to be blocklisted, but outcome was :#{@result.outcome}"
        end

        failure_message_when_negated do
          "expected request not to be blocklisted, but it was blocklisted by \"#{@result.blocked_by}\""
        end
      end

      RSpec::Matchers.define :be_blocklisted_by do |expected_name|
        match do |request_opts|
          @result = Rack::Attack.simulate(**request_opts)
          @result.blocked_by == expected_name
        end

        failure_message do
          "expected request to be blocklisted by \"#{expected_name}\", but blocked_by was #{@result.blocked_by.inspect}"
        end
      end

      RSpec::Matchers.define :be_throttled_on do |expected_name|
        match do |request_opts|
          @result = Rack::Attack.simulate(**request_opts)
          @result.throttle_matches.any? { |m| m[:name] == expected_name }
        end

        failure_message do
          names = @result.throttle_matches.map { |m| m[:name] }
          "expected request to match throttle \"#{expected_name}\", but matched: #{names.inspect}"
        end
      end

      RSpec::Matchers.define :be_tracked_by do |expected_name|
        match do |request_opts|
          @result = Rack::Attack.simulate(**request_opts)
          @result.track_matches.include?(expected_name)
        end

        failure_message do
          "expected request to be tracked by \"#{expected_name}\", but tracked by: #{@result.track_matches.inspect}"
        end
      end

      RSpec::Matchers.define :be_allowed do
        match do |request_opts|
          @result = Rack::Attack.simulate(**request_opts)
          @result.outcome == :allow
        end

        failure_message do
          "expected request to be allowed, but outcome was :#{@result.outcome}"
        end

        failure_message_when_negated do
          "expected request not to be allowed, but it was"
        end
      end

      RSpec::Matchers.define :be_throttled_after do |expected_count|
        match do |request_opts|
          @result = Rack::Attack.simulate(**request_opts)
          @throttle_matches = @result.throttle_matches
          return false if @throttle_matches.empty?

          @match = @throttle_matches.min_by { |m| m[:limit] }
          @match[:limit] == expected_count
        end

        failure_message do
          if @throttle_matches.empty?
            "expected request to match a throttle rule, but no throttles matched"
          else
            "expected throttle after #{expected_count} requests, but limit is #{@match[:limit]}"
          end
        end
      end
    end
  end
end

if defined?(RSpec)
  RSpec.configure do |config|
    config.include Rack::Attack::RSpecMatchers
  end
end
