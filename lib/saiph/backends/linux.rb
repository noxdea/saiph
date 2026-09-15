# frozen_string_literal: true

require "fiddle"

require_relative "../backend"

module Saiph
  module Backends
    module Linux
      module_function

      CLONE_NEWNS = 0x00020000
      CLONE_NEWUSER = 0x10000000
      CLONE_NEWNET = 0x40000000
      MS_REC = 0x4000
      MS_PRIVATE = 1 << 18
      PR_SET_SECCOMP = 22
      PR_SET_NO_NEW_PRIVS = 38
      SECCOMP_MODE_FILTER = 2
      LANDLOCK_CREATE_RULESET_VERSION = 1
      LANDLOCK_RULE_PATH_BENEATH = 1
      O_PATH = 0x200000
      O_CLOEXEC = 0x80000

      FS_EXECUTE = 1 << 0
      FS_WRITE_FILE = 1 << 1
      FS_READ_FILE = 1 << 2
      FS_READ_DIR = 1 << 3
      FS_REMOVE_DIR = 1 << 4
      FS_REMOVE_FILE = 1 << 5
      FS_MAKE_CHAR = 1 << 6
      FS_MAKE_DIR = 1 << 7
      FS_MAKE_REG = 1 << 8
      FS_MAKE_SOCK = 1 << 9
      FS_MAKE_FIFO = 1 << 10
      FS_MAKE_BLOCK = 1 << 11
      FS_MAKE_SYM = 1 << 12
      FS_REFER = 1 << 13
      FS_TRUNCATE = 1 << 14
      FS_IOCTL_DEV = 1 << 15
      FS_BASE = (1 << 13) - 1
      FS_WRITE = FS_WRITE_FILE | FS_REMOVE_DIR | FS_REMOVE_FILE | FS_MAKE_DIR |
        FS_MAKE_REG | FS_MAKE_SOCK | FS_MAKE_FIFO | FS_MAKE_SYM

      BPF_LD_W_ABS = 0x20
      BPF_JMP_JEQ_K = 0x15
      BPF_JMP_JSET_K = 0x45
      BPF_RET_K = 0x06
      SECCOMP_RET_KILL_PROCESS = 0x80000000
      SECCOMP_RET_ERRNO = 0x00050000
      SECCOMP_RET_ALLOW = 0x7fff0000
      EPERM = 1
      CLONE_THREAD = 0x00010000

      SYSTEM_READ_PATHS = ["/lib", "/lib64", "/usr/lib", "/etc/ld.so.cache", RbConfig::CONFIG["prefix"]].freeze
      AUDIT_ARCH = {"x86_64" => 0xc000003e, "aarch64" => 0xc00000b7, "arm64" => 0xc00000b7}.freeze
      SYSCALLS = {
        "x86_64" => {
          clone: 56, fork: 57, vfork: 58, clone3: 435, ptrace: 101, bpf: 321, perf_event_open: 298,
          userfaultfd: 323, kexec_load: 246, finit_module: 313, init_module: 175, delete_module: 176,
          reboot: 169, swapon: 167, swapoff: 168, mount: 165, umount2: 166, pivot_root: 155,
          setns: 308, unshare: 272, keyctl: 250, add_key: 248, request_key: 249,
          process_vm_readv: 310, process_vm_writev: 311, open_by_handle_at: 304, kill: 62, tkill: 200,
          tgkill: 234, rt_sigqueueinfo: 129, rt_tgsigqueueinfo: 297, pidfd_send_signal: 424,
          socket: 41, connect: 42, accept: 43, sendto: 44, recvfrom: 45, sendmsg: 46, recvmsg: 47,
          bind: 49, listen: 50, socketpair: 53, accept4: 288, recvmmsg: 299, sendmmsg: 307
        },
        "aarch64" => {
          clone: 220, clone3: 435, ptrace: 117, bpf: 280, perf_event_open: 241, userfaultfd: 282,
          kexec_load: 104, finit_module: 273, init_module: 105, delete_module: 106, reboot: 142,
          swapon: 224, swapoff: 225, mount: 40, umount2: 39, pivot_root: 41, setns: 268,
          unshare: 97, keyctl: 219, add_key: 217, request_key: 218, process_vm_readv: 270,
          process_vm_writev: 271, open_by_handle_at: 265, kill: 129, tkill: 130, tgkill: 131,
          rt_sigqueueinfo: 138, rt_tgsigqueueinfo: 240, pidfd_send_signal: 424, socket: 198,
          socketpair: 199, bind: 200, listen: 201, accept: 202, connect: 203, sendto: 206,
          recvfrom: 207, sendmsg: 211, recvmsg: 212, accept4: 242, recvmmsg: 243, sendmmsg: 269
        }
      }.freeze

      def name = :seccomp

      def available?
        return @available if defined?(@available_pid) && @available_pid == Process.pid

        @available_pid = Process.pid
        @available = supported_architecture? && landlock_abi.positive? && probe
      rescue StandardError, LoadError
        @available = false
      end

      def spawn(command, policy:, **options) = Spawn.call(self, command, policy: policy, **options)

      def apply!(policy, command: nil)
        raise Unsupported, "Linux sandbox requires x86-64 or AArch64" unless supported_architecture?

        setup_namespaces(network: policy.network)
        apply_landlock(policy, command)
        apply_seccomp(policy)
        true
      end

      def setup_namespaces(network:)
        flags = CLONE_NEWNS | (network ? 0 : CLONE_NEWNET)
        original_uid, original_gid = Process.uid, Process.gid
        if unshare.call(flags | CLONE_NEWUSER).zero?
          File.write("/proc/self/setgroups", "deny") if File.exist?("/proc/self/setgroups")
          File.write("/proc/self/uid_map", "0 #{original_uid} 1")
          File.write("/proc/self/gid_map", "0 #{original_gid} 1")
        elsif unshare.call(flags) != 0
          system_error("unshare")
        end
        system_error("mount private namespace") unless mount.call(0, "/", 0, MS_REC | MS_PRIVATE, 0).zero?
      end

      def apply_landlock(policy, command)
        abi = landlock_abi
        handled = FS_BASE
        handled |= FS_REFER if abi >= 2
        handled |= FS_TRUNCATE if abi >= 3
        handled |= FS_IOCTL_DEV if abi >= 5
        ruleset = landlock_create(Fiddle::Pointer[[handled].pack("Q<")], 8, 0)
        system_error("landlock_create_ruleset") if ruleset.negative?

        begin
          rules = {}
          SYSTEM_READ_PATHS.each { |path| merge_rule(rules, path, read_rights(path) | FS_EXECUTE) }
          policy.read_paths.each { |path| merge_rule(rules, path, read_rights(path)) }
          policy.write_paths.each { |path| merge_rule(rules, path, read_rights(path) | write_rights(path, abi)) }
          policy.read_paths.each { |path| merge_rule(rules, path, FS_EXECUTE) } if policy.exec
          merge_rule(rules, command.first, FS_EXECUTE | FS_READ_FILE) if command
          rules.each { |path, rights| add_landlock_rule(ruleset, path, rights & handled) }

          system_error("prctl(PR_SET_NO_NEW_PRIVS)") unless prctl.call(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0).zero?
          system_error("landlock_restrict_self") unless landlock_restrict(ruleset, 0).zero?
        ensure
          IO.new(ruleset).close
        end
      end

      def merge_rule(rules, path, rights)
        return unless path && File.exist?(path)

        canonical = File.realpath(path)
        rules[canonical] = rules.fetch(canonical, 0) | rights
      end

      def read_rights(path) = FS_READ_FILE | (File.directory?(path) ? FS_READ_DIR : 0)

      def write_rights(path, abi)
        rights = FS_WRITE
        rights |= FS_REFER if abi >= 2
        rights |= FS_TRUNCATE if abi >= 3
        File.directory?(path) ? rights : (FS_WRITE_FILE | (abi >= 3 ? FS_TRUNCATE : 0))
      end

      def add_landlock_rule(ruleset, path, rights)
        descriptor = IO.sysopen(path, O_PATH | O_CLOEXEC)
        attribute = [rights, descriptor].pack("Q<l<x4")
        system_error("landlock_add_rule") unless landlock_add(ruleset, LANDLOCK_RULE_PATH_BENEATH, Fiddle::Pointer[attribute], 0).zero?
      ensure
        IO.new(descriptor).close if descriptor
      end

      def apply_seccomp(policy)
        calls = syscall_table
        denied = %i[ptrace bpf perf_event_open userfaultfd kexec_load finit_module init_module delete_module reboot
          swapon swapoff mount umount2 pivot_root setns unshare keyctl add_key request_key process_vm_readv
          process_vm_writev open_by_handle_at kill tkill tgkill rt_sigqueueinfo rt_tgsigqueueinfo pidfd_send_signal]
        denied.concat(%i[socket socketpair bind listen accept accept4 connect sendto recvfrom sendmsg recvmsg recvmmsg sendmmsg]) unless policy.network
        filters = [[BPF_LD_W_ABS, 0, 0, 4], [BPF_JMP_JEQ_K, 1, 0, audit_arch], [BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS], [BPF_LD_W_ABS, 0, 0, 0]]
        unless policy.exec
          if calls[:clone]
            filters.concat([[BPF_JMP_JEQ_K, 0, 4, calls[:clone]], [BPF_LD_W_ABS, 0, 0, 16],
              [BPF_JMP_JSET_K, 1, 0, CLONE_THREAD], [BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | EPERM], [BPF_LD_W_ABS, 0, 0, 0]])
          end
          denied.concat(%i[fork vfork clone3])
        end
        denied.filter_map { |name| calls[name] }.uniq.each do |number|
          filters << [BPF_JMP_JEQ_K, 0, 1, number]
          filters << [BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | EPERM]
        end
        filters << [BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW]
        install_filter(filters)
      end

      def install_filter(filters)
        bytes = filters.map { |filter| filter.pack("S<CCL<") }.join
        pointer = Fiddle::Pointer[bytes]
        program = [filters.length].pack("S<") + "\0" * 6 + [pointer.to_i].pack("Q<")
        system_error("prctl(PR_SET_SECCOMP)") unless prctl.call(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, Fiddle::Pointer[program], 0, 0).zero?
      end

      def probe
        pid = Process.fork do
          command = [File.realpath(RbConfig.ruby), "-e", "exit!(0)"]
          apply!(Policy.new([], [], false, false, []), command: command)
          exec({}, *command, unsetenv_others: true)
        rescue Exception
          exit!(1)
        end
        Process.waitpid2(pid).last.success?
      end

      def host_cpu = RbConfig::CONFIG["host_cpu"]
      def supported_architecture? = Fiddle::SIZEOF_VOIDP == 8 && AUDIT_ARCH.key?(host_cpu)
      def audit_arch = AUDIT_ARCH.fetch(host_cpu)
      def syscall_table = SYSCALLS.fetch(host_cpu == "arm64" ? "aarch64" : host_cpu)

      def landlock_abi
        @landlock_abi ||= landlock_create(0, 0, LANDLOCK_CREATE_RULESET_VERSION)
      end

      def function(name, arguments, result = Fiddle::TYPE_INT)
        Fiddle::Function.new(Fiddle::Handle::DEFAULT[name], arguments, result)
      end

      def unshare = (@unshare ||= function("unshare", [Fiddle::TYPE_INT]))
      def mount = (@mount ||= function("mount", [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_LONG, Fiddle::TYPE_VOIDP]))
      def prctl = (@prctl ||= function("prctl", [Fiddle::TYPE_INT, Fiddle::TYPE_LONG, Fiddle::TYPE_LONG, Fiddle::TYPE_LONG, Fiddle::TYPE_LONG]))

      def landlock_create(pointer, size, flags)
        fn = (@landlock_create ||= function("syscall", [Fiddle::TYPE_LONG, Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T, Fiddle::TYPE_INT], Fiddle::TYPE_LONG))
        fn.call(444, pointer, size, flags)
      end

      def landlock_add(ruleset, type, pointer, flags)
        fn = (@landlock_add ||= function("syscall", [Fiddle::TYPE_LONG, Fiddle::TYPE_INT, Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT], Fiddle::TYPE_LONG))
        fn.call(445, ruleset, type, pointer, flags)
      end

      def landlock_restrict(ruleset, flags)
        fn = (@landlock_restrict ||= function("syscall", [Fiddle::TYPE_LONG, Fiddle::TYPE_INT, Fiddle::TYPE_INT], Fiddle::TYPE_LONG))
        fn.call(446, ruleset, flags)
      end

      def system_error(operation) = raise(SystemCallError.new(operation, Fiddle.last_error))
    end
  end
end
