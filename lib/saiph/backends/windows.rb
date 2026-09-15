# frozen_string_literal: true

require "fiddle"
require "securerandom"

require_relative "../backend"

module Saiph
  module Backends
    module Windows
      module_function

      P = Fiddle::TYPE_VOIDP
      I = Fiddle::TYPE_INT
      U = Fiddle::TYPE_INT
      N = Fiddle::TYPE_SIZE_T
      L = Fiddle::TYPE_LONG
      V = Fiddle::TYPE_VOID
      PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
      EXTENDED_STARTUPINFO_PRESENT = 0x00080000
      CREATE_UNICODE_ENVIRONMENT = 0x00000400
      CREATE_SUSPENDED = 0x00000004
      STARTF_USESTDHANDLES = 0x00000100
      JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
      JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
      JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
      INFINITE = 0xffffffff

      def name = :appcontainer

      def available?
        return false unless Fiddle::SIZEOF_VOIDP == 8
        return @available if defined?(@available_pid) && @available_pid == Process.pid

        @available_pid = Process.pid
        profile, sid = create_profile("Probe")
        @available = create_and_wait([RbConfig.ruby, "-e", "exit!(0)"], sid, allow_children: false).zero?
      rescue StandardError, LoadError, Fiddle::DLError
        @available = false
      ensure
        free_sid.call(sid) if sid && !sid.zero?
        delete_profile.call(wide(profile)) if profile
      end

      def spawn(command, policy:, **options)
        validate_policy!(policy)
        Spawn.call(self, command, policy: policy, **options)
      end

      def apply!(_policy, command: nil)
        raise Unsupported, "AppContainer can only be applied while creating a child process"
      end

      def launch(command, policy:)
        validate_policy!(policy)
        profile, sid = create_profile("Process")
        create_and_wait(command, sid, allow_children: policy.exec)
      ensure
        free_sid.call(sid) if sid && !sid.zero?
        delete_profile.call(wide(profile)) if profile
      end

      def validate_policy!(policy)
        unless policy.read_paths.empty? && policy.write_paths.empty?
          raise Unsupported, "AppContainer path grants require explicit Windows ACL provisioning"
        end
        raise Unsupported, "AppContainer network capabilities are not available" if policy.network
      end

      def create_and_wait(command, sid, allow_children:)
        attributes = initialize_attributes
        security = [sid, 0, 0, 0].pack("JJL<L<")
        check(update_attributes.call(attributes, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
          Fiddle::Pointer[security], security.bytesize, 0, 0), "UpdateProcThreadAttribute")
        startup = startup_info(attributes)
        information = "\0".b * 24
        line = wide(command.map { |argument| quote_argument(argument) }.join(" "))
        flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED
        check(create_process.call(wide(command.first), line, 0, 0, 1, flags, 0, 0, Fiddle::Pointer[startup], Fiddle::Pointer[information]), "CreateProcessW")
        process, thread = information.unpack("JJ")
        job = create_job.call(0, 0)
        check(job, "CreateJobObjectW")
        configure_job(job, allow_children: allow_children)
        check(assign_job.call(job, process), "AssignProcessToJobObject")
        resumed = resume_thread.call(thread)
        raise SystemCallError.new("ResumeThread", Fiddle.last_error) if resumed == 0xffffffff

        check(wait.call(process, INFINITE) != 0xffffffff ? 1 : 0, "WaitForSingleObject")
        status = [0].pack("L<")
        check(exit_code.call(process, Fiddle::Pointer[status]), "GetExitCodeProcess")
        status.unpack1("L<")
      rescue Exception
        terminate.call(process, 126) if process && !process.zero?
        raise
      ensure
        delete_attributes.call(attributes) if attributes
        [thread, process, job].compact.each { |handle| close_handle.call(handle) unless handle.zero? }
      end

      def configure_job(job, allow_children:)
        information = "\0".b * 144
        flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        unless allow_children
          flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS
          information[40, 4] = [1].pack("L<")
        end
        information[16, 4] = [flags].pack("L<")
        check(set_job.call(job, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, Fiddle::Pointer[information], information.bytesize),
          "SetInformationJobObject")
      end

      def initialize_attributes
        size = [0].pack("J")
        initialize_attribute_list.call(0, 1, 0, Fiddle::Pointer[size])
        attributes = Fiddle::Pointer.malloc(size.unpack1("J"), Fiddle::RUBY_FREE)
        check(initialize_attribute_list.call(attributes, 1, 0, Fiddle::Pointer[size]), "InitializeProcThreadAttributeList")
        attributes
      end

      def startup_info(attributes)
        value = "\0".b * 112
        value[0, 4] = [112].pack("L<")
        value[60, 4] = [STARTF_USESTDHANDLES].pack("L<")
        value[80, 24] = [-10, -11, -12].map { |number| get_std_handle.call(number) }.pack("J3")
        value[104, 8] = [attributes.to_i].pack("J")
        value
      end

      def create_profile(suffix)
        name = "Noxdea.Saiph.#{suffix}.#{Process.pid}.#{SecureRandom.hex(8)}"
        sid = [0].pack("J")
        result = create_profile_fn.call(wide(name), wide("Saiph"), wide("Ephemeral Saiph sandbox"), 0, 0, Fiddle::Pointer[sid])
        raise Error, "CreateAppContainerProfile failed (0x#{(result & 0xffffffff).to_s(16)})" if (result & 0x80000000) != 0

        [name, sid.unpack1("J")]
      end

      def quote_argument(value)
        return value unless value.empty? || value.match?(/[\s"]/)

        '"' + value.gsub(/(\\*)"/) { Regexp.last_match(1) * 2 + '\\"' }
          .sub(/(\\+)\z/) { Regexp.last_match(1) * 2 } + '"'
      end

      def wide(value) = value.encode("UTF-16LE").b + "\0\0"

      def check(result, operation)
        raise SystemCallError.new(operation, Fiddle.last_error) if result.to_i.zero?

        result
      end

      def library(name) = Fiddle.dlopen(name)
      def kernel = (@kernel ||= library("kernel32.dll"))
      def userenv = (@userenv ||= library("userenv.dll"))
      def advapi = (@advapi ||= library("advapi32.dll"))
      def fn(handle, name, arguments, result) = Fiddle::Function.new(handle[name], arguments, result)
      def create_profile_fn = (@create_profile_fn ||= fn(userenv, "CreateAppContainerProfile", [P, P, P, P, U, P], L))
      def delete_profile = (@delete_profile ||= fn(userenv, "DeleteAppContainerProfile", [P], L))
      def free_sid = (@free_sid ||= fn(advapi, "FreeSid", [P], P))
      def initialize_attribute_list = (@initialize_attribute_list ||= fn(kernel, "InitializeProcThreadAttributeList", [P, U, U, P], I))
      def update_attributes = (@update_attributes ||= fn(kernel, "UpdateProcThreadAttribute", [P, U, N, P, N, P, P], I))
      def delete_attributes = (@delete_attributes ||= fn(kernel, "DeleteProcThreadAttributeList", [P], V))
      def create_process = (@create_process ||= fn(kernel, "CreateProcessW", [P, P, P, P, I, U, P, P, P, P], I))
      def get_std_handle = (@get_std_handle ||= fn(kernel, "GetStdHandle", [I], P))
      def create_job = (@create_job ||= fn(kernel, "CreateJobObjectW", [P, P], P))
      def set_job = (@set_job ||= fn(kernel, "SetInformationJobObject", [P, I, P, U], I))
      def assign_job = (@assign_job ||= fn(kernel, "AssignProcessToJobObject", [P, P], I))
      def resume_thread = (@resume_thread ||= fn(kernel, "ResumeThread", [P], U))
      def wait = (@wait ||= fn(kernel, "WaitForSingleObject", [P, U], U))
      def exit_code = (@exit_code ||= fn(kernel, "GetExitCodeProcess", [P, P], I))
      def terminate = (@terminate ||= fn(kernel, "TerminateProcess", [P, U], I))
      def close_handle = (@close_handle ||= fn(kernel, "CloseHandle", [P], I))
    end
  end
end
