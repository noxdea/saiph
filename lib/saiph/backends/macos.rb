# frozen_string_literal: true

require "fiddle"

require_relative "../backend"

module Saiph
  module Backends
    module MacOS
      module_function

      LIBRARIES = ["/usr/lib/libsandbox.1.dylib", "/usr/lib/libSystem.B.dylib"].freeze
      BASE_READ_PATHS = ["/System", "/usr/lib", "/private/var/db/dyld", RbConfig::CONFIG["prefix"]].compact.freeze

      def name = :seatbelt

      def available?
        return @available if defined?(@available_pid) && @available_pid == Process.pid

        @available_pid = Process.pid
        @available = probe
      rescue StandardError, LoadError
        @available = false
      end

      def spawn(command, policy:, **options) = Spawn.call(self, command, policy: policy, **options)

      def apply!(policy, command: nil)
        profile = build_profile(policy, command)
        error = [0].pack("J")
        result = sandbox_init.call(Fiddle::Pointer[profile], 0, Fiddle::Pointer[error])
        return true if result.zero?

        pointer = error.unpack1("J")
        message = pointer.zero? ? "sandbox_init failed" : Fiddle::Pointer.new(pointer).to_s
        sandbox_free_error.call(pointer) unless pointer.zero?
        raise Error, message
      end

      def build_profile(policy, command = nil)
        reads = (BASE_READ_PATHS + policy.read_paths + policy.write_paths + Array(command&.first)).uniq
        lines = ["(version 1)", "(deny default)", "(allow sysctl-read)", "(allow process-info*)"]
        lines << rule("file-read*", reads)
        lines << rule("file-write*", policy.write_paths) unless policy.write_paths.empty?
        lines << "(allow network*)" if policy.network
        if command
          lines << "(allow process-exec (literal #{quote(command.first)}))"
          lines << "(allow process-fork)" if policy.exec
        elsif policy.exec
          lines << rule("process-exec", policy.read_paths)
          lines << "(allow process-fork)"
        end
        lines.join("\n")
      end

      def rule(operation, paths)
        filters = paths.filter_map do |path|
          next unless File.exist?(path)

          "(#{File.directory?(path) ? 'subpath' : 'literal'} #{quote(path)})"
        end
        "(allow #{operation} #{filters.join(' ')})"
      end

      def quote(value) = JSON.generate(value)

      def probe
        pid = Process.fork do
          STDERR.reopen(File::NULL, "w")
          command = [File.realpath(RbConfig.ruby), "-e", "exit!(0)"]
          apply!(Policy.new([], [], false, false, []), command: command)
          exec({}, *command, unsetenv_others: true)
        rescue Exception
          exit!(1)
        end
        Process.waitpid2(pid).last.success?
      end

      def library
        @library ||= LIBRARIES.lazy.filter_map do |path|
          Fiddle.dlopen(path)
        rescue Fiddle::DLError
          nil
        end.first or raise LoadError, "sandbox library not found"
      end

      def sandbox_init
        @sandbox_init ||= Fiddle::Function.new(
          library["sandbox_init"],
          [Fiddle::TYPE_VOIDP, Fiddle::TYPE_LONG_LONG, Fiddle::TYPE_VOIDP],
          Fiddle::TYPE_INT
        )
      end

      def sandbox_free_error
        @sandbox_free_error ||= Fiddle::Function.new(library["sandbox_free_error"], [Fiddle::TYPE_VOIDP], Fiddle::TYPE_VOID)
      end
    end
  end
end
