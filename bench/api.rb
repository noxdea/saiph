# frozen_string_literal: true

require "benchmark"
require_relative "../lib/saiph"

iterations = 100_000
policy_time = Benchmark.realtime do
  iterations.times { Saiph::Policy.new([], [], false, false, []) }
end
Saiph.available?
backend_time = Benchmark.realtime do
  iterations.times { Saiph.backend }
end

policy_us = policy_time * 1_000_000 / iterations
backend_us = backend_time * 1_000_000 / iterations
puts "policy: #{policy_us.round(3)} us"
puts "backend: #{backend_us.round(3)} us"

if ENV["BUDGET"] == "1"
  raise "Policy construction exceeded 10 us" if policy_us > 10
  raise "cached backend lookup exceeded 10 us" if backend_us > 10
end
