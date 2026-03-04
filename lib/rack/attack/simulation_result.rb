# frozen_string_literal: true

module Rack
  class Attack
    class SimulationResult
      attr_reader :safelisted_by, :blocked_by, :throttle_matches, :track_matches

      def initialize(safelisted_by: nil, blocked_by: nil, throttle_matches: [], track_matches: [])
        @safelisted_by = safelisted_by
        @blocked_by = blocked_by
        @throttle_matches = throttle_matches
        @track_matches = track_matches
      end

      def safelisted?
        !@safelisted_by.nil?
      end

      def blocklisted?
        !@blocked_by.nil?
      end

      def throttled?
        @throttle_matches.any?
      end

      def tracked?
        @track_matches.any?
      end

      def outcome
        if safelisted?
          :safelist
        elsif blocklisted?
          :blocklist
        elsif throttled?
          :throttle
        else
          :allow
        end
      end

      def matched_rules
        rules = []
        rules << @safelisted_by if @safelisted_by
        rules << @blocked_by if @blocked_by
        @throttle_matches.each { |tm| rules << tm[:name] }
        rules.concat(@track_matches)
        rules
      end
    end
  end
end
