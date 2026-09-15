# Saiph

Saiph applies native operating-system restrictions to child processes. It is a
small, Pure Ruby boundary for running untrusted plugins without depending on an
editor or plugin API.

Saiph fails closed. `available?` is true only after the native backend passes a
local capability probe, and a child exits with status 126 if setup fails. Saiph
never substitutes an ordinary unsandboxed process.

## Installation

```bash
bundle add saiph
```

Saiph supports Ruby 3.1 and later.

## Usage

```ruby
require "saiph"

unless Saiph.available?
  warn "OS sandbox unavailable"
  return
end

policy = Saiph::Policy.new(
  read_paths: [File.expand_path("plugin.rb", __dir__)],
  write_paths: [File.expand_path("tmp", __dir__)],
  network: false,
  exec: false,
  env: ["LANG"]
)

pid = Saiph.spawn(
  [RbConfig.ruby, File.expand_path("plugin.rb", __dir__)],
  policy: policy,
  env: {"LANG" => "en_US.UTF-8"},
  out: $stdout,
  err: $stderr
)
status = Process.waitpid2(pid).last
raise "sandbox setup failed" if status.exitstatus == 126
```

`spawn` returns a process ID and accepts normal `Process.spawn` redirections
and options. Pass the command as an argument array. A string is treated as one
executable name; Saiph never invokes a shell.

`Policy` fields have these meanings:

- `read_paths`: existing absolute files or directory trees the child may read.
- `write_paths`: existing absolute files or directory trees the child may read
  and modify.
- `network`: whether network access is allowed.
- `exec`: whether the child may create descendant processes.
- `env`: names of environment variables visible to the child. Values may be
  overridden with `spawn(..., env: {...})`; undeclared names are rejected.

The launcher and system dynamic libraries need a small implicit read-only
runtime allowance. On Unix this covers the selected executable, the active
Ruby installation, and system library directories. It does not include the
home directory or temporary directories.

`Saiph.apply!(policy)` restricts the current process and is irreversible. Use
`spawn` unless the current process was created solely to become a sandbox.

## Backends

| Platform | `backend` | Enforcement |
| --- | --- | --- |
| macOS | `:seatbelt` | `sandbox_init` profile with deny-by-default file, network, and process rules |
| Linux | `:seccomp` | user/mount/network namespaces, Landlock filesystem rules, and seccomp-BPF |
| Windows | `:appcontainer` | ephemeral AppContainer plus a Job Object process limit |

Linux reports unavailable unless namespaces, Landlock, and seccomp all work in
the current environment. This is common in restricted CI containers and is an
expected reason to skip integration tests.

Windows 0.1 supports a no-filesystem-grant, no-network policy. Non-empty path
grants and `network: true` raise `Saiph::Unsupported` because safely changing
host ACLs requires application-owned provisioning. `apply!` is also unsupported
on Windows; AppContainer tokens must be selected at process creation.

## Security and cleanup

- Paths are resolved before launch, so a symlink cannot retarget an allowance.
- The child environment is rebuilt from its allowlist.
- Policy transfer uses a private inherited pipe, not a temporary file.
- Backend probes run in disposable children because Unix restrictions cannot be
  relaxed.
- AppContainer profiles, native handles, pipes, and Landlock descriptors are
  closed on both success and failure.

Saiph reduces OS capabilities; it does not validate plugin code or replace
application-level authentication and authorization.

## Development

```bash
bundle install
bundle exec rake test
bundle exec rbs -I sig validate
BUDGET=1 bundle exec rake bench
gem build --strict saiph.gemspec
```

## License

MIT.
