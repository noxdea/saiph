# frozen_string_literal: true

module Saiph
  module Backends
    module Spawn
      module_function

      def call(backend, command, policy:, **options)
        overrides = options.delete(:env) || {}
        raise ArgumentError, "env must be a hash" unless overrides.is_a?(Hash)

        overrides = overrides.to_h { |key, value| [String(key), value.nil? ? nil : String(value)] }
        denied = overrides.keys - policy.env
        raise ArgumentError, "environment variable is not allowed: #{denied.first}" unless denied.empty?

        environment = policy.env.to_h { |name| [name, overrides.fetch(name, ENV[name])] }
        reader, writer = IO.pipe
        fd = 3
        environment["SAIPH_PAYLOAD_FD"] = fd.to_s
        environment["SAIPH_BACKEND"] = backend.name.to_s
        payload = JSON.generate(
          "command" => command,
          "policy" => {
            "read_paths" => policy.read_paths,
            "write_paths" => policy.write_paths,
            "network" => policy.network,
            "exec" => policy.exec,
            "env" => policy.env
          }
        )
        redirects = options.merge(fd => reader, close_others: true, unsetenv_others: true)
        pid = Process.spawn(environment, RbConfig.ruby, "-I", File.expand_path("..", __dir__), "-rsaiph/runner", "-e", "Saiph::Runner.run", redirects)
        reader.close
        writer.write(payload)
        writer.close
        pid
      rescue Exception
        if pid
          begin
            Process.kill("TERM", pid)
          rescue Errno::ESRCH
            nil
          end
          begin
            Process.wait(pid)
          rescue Errno::ECHILD
            nil
          end
        end
        reader&.close unless reader&.closed?
        writer&.close unless writer&.closed?
        raise
      end
    end
  end
end
