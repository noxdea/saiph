# frozen_string_literal: true

require_relative "../saiph" unless defined?(Saiph::Policy)

module Saiph
  module Runner
    module_function

    def run
      fd = Integer(ENV.delete("SAIPH_PAYLOAD_FD"), 10)
      requested = ENV.delete("SAIPH_BACKEND")
      input = IO.for_fd(fd)
      payload = JSON.parse(input.read)
      input.close
      values = payload.fetch("policy").values_at("read_paths", "write_paths", "network", "exec", "env")
      policy = Policy.new(*values)
      implementation = Saiph.send(:require_backend!)
      raise Unsupported, "sandbox backend changed while starting" unless implementation.name.to_s == requested

      if implementation.respond_to?(:launch)
        exit!(implementation.launch(payload.fetch("command"), policy: policy))
      end

      implementation.apply!(policy, command: payload.fetch("command"))
      exec(*payload.fetch("command"))
    rescue Exception => error
      warn("saiph: #{error.message}")
      exit!(126)
    end
  end
end
