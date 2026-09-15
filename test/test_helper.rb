# frozen_string_literal: true

ENV["MT_NO_PLUGINS"] = "1"
gem "minitest", "~> 5.0"
require "minitest/autorun"
require "rbconfig"
require "socket"
require "tempfile"
require "timeout"
require "tmpdir"
require "saiph"

module SaiphTestHelpers
  def policy(**changes)
    Saiph::Policy.new(**{
      read_paths: [], write_paths: [], network: false, exec: false, env: []
    }.merge(changes))
  end

  def wait_for(pid)
    Timeout.timeout(15) { Process.waitpid2(pid).last }
  rescue Timeout::Error
    Process.kill("KILL", pid)
    Process.wait(pid)
    flunk("sandbox child timed out")
  end

  def sandbox_exit(code, selected_policy = policy, *arguments, **options)
    skip("native sandbox unavailable") unless Saiph.available?

    redirects = {in: File::NULL, out: File::NULL, err: File::NULL}.merge(options)
    wait_for(Saiph.spawn([RbConfig.ruby, "-e", code, *arguments], policy: selected_policy, **redirects))
  end
end

class Minitest::Test
  include SaiphTestHelpers
end
