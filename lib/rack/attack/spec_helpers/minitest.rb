# frozen_string_literal: true

require "rack/attack"

module Rack
  class Attack
    module MinitestHelpers
      def simulate_request(**opts)
        Rack::Attack.simulate(**opts)
      end

      def assert_safelisted(msg = nil, **request_opts)
        result = simulate_request(**request_opts)
        msg ||= "Expected request to be safelisted, but outcome was :#{result.outcome}"
        assert result.safelisted?, msg
      end

      def assert_safelisted_by(name, msg = nil, **request_opts)
        result = simulate_request(**request_opts)
        msg ||= "Expected request to be safelisted by \"#{name}\", but safelisted_by was #{result.safelisted_by.inspect}"
        assert_equal name, result.safelisted_by, msg
      end

      def assert_blocklisted(msg = nil, **request_opts)
        result = simulate_request(**request_opts)
        msg ||= "Expected request to be blocklisted, but outcome was :#{result.outcome}"
        assert result.blocklisted?, msg
      end

      def assert_blocklisted_by(name, msg = nil, **request_opts)
        result = simulate_request(**request_opts)
        msg ||= "Expected request to be blocklisted by \"#{name}\", but blocked_by was #{result.blocked_by.inspect}"
        assert_equal name, result.blocked_by, msg
      end

      def assert_throttled_on(name, msg = nil, **request_opts)
        result = simulate_request(**request_opts)
        throttle_names = result.throttle_matches.map { |m| m[:name] }
        msg ||= "Expected request to match throttle \"#{name}\", but matched: #{throttle_names.inspect}"
        assert throttle_names.include?(name), msg
      end

      def assert_tracked_by(name, msg = nil, **request_opts)
        result = simulate_request(**request_opts)
        msg ||= "Expected request to be tracked by \"#{name}\", but tracked by: #{result.track_matches.inspect}"
        assert result.track_matches.include?(name), msg
      end

      def assert_allowed(msg = nil, **request_opts)
        result = simulate_request(**request_opts)
        msg ||= "Expected request to be allowed, but outcome was :#{result.outcome}"
        assert_equal :allow, result.outcome, msg
      end

      def assert_throttled_after(count, msg = nil, **request_opts)
        result = simulate_request(**request_opts)
        throttle_matches = result.throttle_matches

        msg ||= if throttle_matches.empty?
                  "Expected request to match a throttle rule, but no throttles matched"
                else
                  match = throttle_matches.min_by { |m| m[:limit] }
                  "Expected throttle after #{count} requests, but limit is #{match[:limit]}"
                end

        refute throttle_matches.empty?, "No throttle rules matched" if throttle_matches.empty?
        match = throttle_matches.min_by { |m| m[:limit] }
        assert_equal count, match[:limit], msg
      end
    end
  end
end
