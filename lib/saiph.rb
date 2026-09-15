# frozen_string_literal: true

require "json"
require "rbconfig"

require_relative "saiph/version"

module Saiph
  class Error < StandardError; end
  class Unsupported < Error; end

  module Value
    module_function

    def define(*members)
      return Data.define(*members) if defined?(Data)

      Struct.new(*members) do
        members.each { |member| undef_method("#{member}=") }

        def initialize(*values, **keywords)
          unless keywords.empty?
            raise ArgumentError, "cannot mix positional and keyword arguments" unless values.empty?

            missing = self.class.members - keywords.keys
            unknown = keywords.keys - self.class.members
            raise ArgumentError, "missing keyword: #{missing.first.inspect}" unless missing.empty?
            raise ArgumentError, "unknown keyword: #{unknown.first.inspect}" unless unknown.empty?

            values = self.class.members.map { |member| keywords.fetch(member) }
          end
          raise ArgumentError, "wrong number of arguments" unless values.length == self.class.members.length

          super(*values)
          freeze
        end
      end
    end
  end

  Policy = Value.define(:read_paths, :write_paths, :network, :exec, :env)
  private_constant :Value

  class << self
    def available? = !!(platform && platform.available?)
    def backend = available? ? platform.name : nil

    def spawn(command, policy:, **spawn_options)
      normalized = normalize_policy(policy)
      executable = resolve_command(command)
      require_backend!.spawn(executable, policy: normalized, **spawn_options)
    end

    def apply!(policy)
      normalized = normalize_policy(policy)
      require_backend!.apply!(normalized)
      ENV.keep_if { |name, _value| normalized.env.include?(name) }
      true
    end

    private

    def platform
      @platform ||= case RUBY_PLATFORM
      when /darwin/ then require_relative("saiph/backends/macos") && Backends::MacOS
      when /linux/ then require_relative("saiph/backends/linux") && Backends::Linux
      when /mswin|mingw/ then require_relative("saiph/backends/windows") && Backends::Windows
      else false
      end
      @platform || nil
    end

    def require_backend!
      candidate = platform
      raise Unsupported, "no supported sandbox backend is available" unless candidate&.available?

      candidate
    end

    def normalize_policy(policy)
      raise ArgumentError, "policy must be a Saiph::Policy" unless policy.is_a?(Policy)

      reads = normalize_paths(policy.read_paths, :read_paths)
      writes = normalize_paths(policy.write_paths, :write_paths)
      raise ArgumentError, "network must be true or false" unless [true, false].include?(policy.network)
      raise ArgumentError, "exec must be true or false" unless [true, false].include?(policy.exec)

      names = Array(policy.env).map do |name|
        value = String(name)
        raise ArgumentError, "invalid environment name" if value.empty? || value.include?("=") || value.include?("\0")

        value.freeze
      end.uniq.freeze
      Policy.new(reads, writes, policy.network, policy.exec, names)
    end

    def normalize_paths(paths, field)
      Array(paths).map do |path|
        value = String(path)
        raise ArgumentError, "#{field} must contain absolute paths" unless File.absolute_path(value) == value
        raise ArgumentError, "#{field} path does not exist: #{value}" unless File.exist?(value)

        File.realpath(value).freeze
      end.uniq.freeze
    end

    def resolve_command(command)
      parts = (command.is_a?(Array) ? command : [command]).map do |part|
        value = String(part)
        raise ArgumentError, "command contains a null byte" if value.include?("\0")

        value
      end
      raise ArgumentError, "command must not be empty" if parts.empty? || parts.first.empty?

      executable = parts.first
      separators = [File::SEPARATOR, File::ALT_SEPARATOR].compact
      unless separators.any? { |separator| executable.include?(separator) }
        executable = ENV.fetch("PATH", "").split(File::PATH_SEPARATOR).find do |directory|
          path = File.expand_path(executable, directory)
          break path if File.file?(path) && File.executable?(path)
        end
      else
        executable = File.expand_path(executable)
      end
      raise ArgumentError, "command executable was not found" unless executable && File.file?(executable) && File.executable?(executable)

      parts[0] = File.realpath(executable)
      parts.freeze
    end
  end
end

require_relative "saiph/runner"
