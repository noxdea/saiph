# frozen_string_literal: true

require "test_helper"

class SaiphTest < Minitest::Test
  def test_reports_backend_without_raising
    assert_includes [true, false], Saiph.available?
    assert_includes [nil, :seatbelt, :seccomp, :appcontainer], Saiph.backend
    assert_equal Saiph.available?, !Saiph.backend.nil?
  end

  def test_policy_is_an_immutable_value
    value = policy(read_paths: [Dir.tmpdir], env: ["PATH"])

    assert_equal [Dir.tmpdir], value.read_paths
    assert_predicate value, :frozen?
    assert_raises(NoMethodError) { value.read_paths = [] }
  end

  def test_rejects_invalid_policy_before_launch
    invalid = policy(read_paths: ["relative"])

    assert_raises(ArgumentError) { Saiph.spawn([RbConfig.ruby, "-e", "exit"], policy: invalid) }
    assert_raises(ArgumentError) { Saiph.spawn([], policy: policy) }
    assert_raises(ArgumentError) { Saiph.spawn(["missing-saiph-command"], policy: policy) }
  end

  def test_unsupported_environment_fails_closed
    return if Saiph.available?

    assert_raises(Saiph::Unsupported) { Saiph.apply!(policy) }
    assert_raises(Saiph::Unsupported) { Saiph.spawn([RbConfig.ruby, "-e", "exit"], policy: policy) }
  end

  def test_child_starts_inside_sandbox
    assert_predicate sandbox_exit("exit!(0)"), :success?
  end

  def test_environment_is_allowlisted
    previous = ENV["SAIPH_TEST_SECRET"]
    ENV["SAIPH_TEST_SECRET"] = "hidden"
    code = 'exit!(ENV["VISIBLE"] == "yes" && !ENV.key?("SAIPH_TEST_SECRET") ? 0 : 1)'

    status = sandbox_exit(code, policy(env: ["VISIBLE"]), env: {"VISIBLE" => "yes"})

    assert_predicate status, :success?
  ensure
    ENV["SAIPH_TEST_SECRET"] = previous
  end

  def test_denies_undeclared_read
    Dir.mktmpdir do |directory|
      path = File.join(directory, "secret")
      File.write(path, "secret")
      code = "begin; File.read(ARGV.fetch(0)); exit!(1); rescue SystemCallError; exit!(0); end"

      assert_predicate sandbox_exit(code, policy, path), :success?
    end
  end

  def test_allows_declared_read
    skip("AppContainer path grants are deliberately unavailable") if Saiph.backend == :appcontainer

    Tempfile.create do |file|
      file.write("visible")
      file.flush
      code = 'exit!(File.read(ARGV.fetch(0)) == "visible" ? 0 : 1)'

      assert_predicate sandbox_exit(code, policy(read_paths: [file.path]), file.path), :success?
    end
  end

  def test_write_scope
    skip("AppContainer path grants are deliberately unavailable") if Saiph.backend == :appcontainer

    Dir.mktmpdir do |root|
      allowed = File.join(root, "allowed")
      forbidden = File.join(root, "forbidden")
      Dir.mkdir(allowed)
      Dir.mkdir(forbidden)
      code = <<~'RUBY'
        File.write(File.join(ARGV.fetch(0), "created"), "ok")
        begin
          File.write(File.join(ARGV.fetch(1), "created"), "bad")
          exit!(1)
        rescue SystemCallError
          exit!(0)
        end
      RUBY

      assert_predicate sandbox_exit(code, policy(write_paths: [allowed]), allowed, forbidden), :success?
      assert_equal "ok", File.read(File.join(allowed, "created"))
      refute_path_exists File.join(forbidden, "created")
    end
  end

  def test_network_is_denied
    code = <<~'RUBY'
      require "socket"
      begin
        TCPSocket.new("127.0.0.1", 9).close
        exit!(1)
      rescue Errno::EACCES, Errno::EPERM
        exit!(0)
      rescue SystemCallError
        exit!(2)
      end
    RUBY

    assert_predicate sandbox_exit(code, policy), :success?
  end

  def test_child_process_creation_is_denied
    code = 'exit!(system(RbConfig.ruby, "-e", "exit!(0)") ? 1 : 0)'

    assert_predicate sandbox_exit(code, policy), :success?
  end

  def test_child_process_creation_can_be_declared
    code = 'exit!(system(RbConfig.ruby, "-e", "exit!(0)") ? 0 : 1)'

    assert_predicate sandbox_exit(code, policy(exec: true)), :success?
  end

  def test_network_can_be_declared
    skip("AppContainer network grants are deliberately unavailable") if Saiph.backend == :appcontainer
    code = 'require "socket"; socket = Socket.new(:INET, :STREAM); socket.close; exit!(0)'

    assert_predicate sandbox_exit(code, policy(network: true)), :success?
  end

  def test_apply_restricts_current_process
    skip("native sandbox unavailable") unless Saiph.available?
    skip("AppContainer cannot retrofit the current process") if Saiph.backend == :appcontainer

    Dir.mktmpdir do |directory|
      forbidden = File.join(directory, "secret")
      File.write(forbidden, "secret")
      pid = Process.fork do
        Saiph.apply!(policy(env: []))
        begin
          File.read(forbidden)
          exit!(1)
        rescue SystemCallError
          exit!(ENV.empty? ? 0 : 2)
        end
      rescue Exception
        exit!(3)
      end

      assert_predicate wait_for(pid), :success?
    end
  end
end
