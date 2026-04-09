"""Tests for CommandRunner caching."""

import pytest

from mcp_windbg.adapters.windbg_adapter import WinDbgAdapter
from mcp_windbg.session.command_runner import CommandRunner


class MockCDBSession:
    """Mock CDBSession for unit testing."""

    def __init__(self):
        self.call_count = {}
        self.responses = {}

    def set_response(self, command: str, output: list):
        """Set a canned response for a command."""
        self.responses[command.strip().lower()] = output

    def send_command(self, command, timeout=None):
        """Simulate send_command with canned responses."""
        key = command.strip().lower()
        self.call_count[key] = self.call_count.get(key, 0) + 1
        if key in self.responses:
            return self.responses[key]
        return [f"output for: {command}"]


class TestCommandRunner:
    """Test CommandRunner caching behavior."""

    def test_basic_command(self):
        """Test basic command execution without caching."""
        mock = MockCDBSession()
        mock.set_response("lm", ["ntdll kernel32"])
        runner = CommandRunner(mock)

        result = runner.run("lm", use_cache=False)
        assert result == ["ntdll kernel32"]

    def test_cache_hit(self):
        """Test that second call returns cached result."""
        mock = MockCDBSession()
        mock.set_response("lm", ["module1", "module2"])
        runner = CommandRunner(mock)

        # First call
        result1 = runner.run("lm")
        assert result1 == ["module1", "module2"]
        assert mock.call_count["lm"] == 1

        # Second call should be cached
        result2 = runner.run("lm")
        assert result2 == ["module1", "module2"]
        assert mock.call_count["lm"] == 1  # Not incremented

    def test_cacheable_command(self):
        """Test that known commands are cached."""
        mock = MockCDBSession()
        runner = CommandRunner(mock)

        cacheable = ["lm", "!analyze -v", ".ecxr", ".lastevent", "vertarget", ".time", "~"]
        for cmd in cacheable:
            mock.set_response(cmd, [f"output_{cmd}"])
            runner.run(cmd)
            # Second call should be cached
            runner.run(cmd)

        for cmd in cacheable:
            assert mock.call_count[cmd.strip().lower()] == 1, f"{cmd} should be cached"

    def test_non_cacheable_command(self):
        """Test that unknown commands are not cached."""
        mock = MockCDBSession()
        runner = CommandRunner(mock)

        # 'k' is not in CACHEABLE_COMMANDS (it depends on thread context)
        runner.run("k")
        runner.run("k")

        assert mock.call_count["k"] == 2  # Called twice, not cached

    def test_invalidate_all(self):
        """Test cache invalidation."""
        mock = MockCDBSession()
        mock.set_response("lm", ["module1"])
        runner = CommandRunner(mock)

        runner.run("lm")
        runner.invalidate_all()
        runner.run("lm")

        assert mock.call_count["lm"] == 2  # Called again after invalidation

    def test_switch_thread_invalidates_context_caches(self):
        """Test that adapter-level thread switching invalidates thread-sensitive caches."""
        mock = MockCDBSession()
        mock.set_response(".lastevent", ["Last event: 1.2: Access violation - code c0000005"])
        mock.set_response(".ecxr", ["exception_info"])
        mock.set_response("r", ["rip=00007ff700131ee4"])
        mock.set_response("~0s", ["thread switched"])
        runner = CommandRunner(mock)
        adapter = WinDbgAdapter(runner)

        adapter.get_exception_context()
        adapter.switch_thread(0)
        adapter.get_exception_context()

        assert mock.call_count[".ecxr"] == 2
        assert mock.call_count[".lastevent"] == 2
        assert mock.call_count["r"] == 2

    def test_append_symbol_path_invalidates_symbol_caches(self):
        """Test that appending symbol paths invalidates symbol-sensitive caches."""
        mock = MockCDBSession()
        mock.set_response("!analyze -v", ["analysis"])
        mock.set_response(".ecxr", ["exception_info"])
        mock.set_response(".lastevent", ["Last event: 1.2: Access violation - code c0000005"])
        mock.set_response("r", ["rip=00007ff700131ee4"])
        mock.set_response(".sympath+ c:\\symbols", ["path updated"])
        runner = CommandRunner(mock)
        adapter = WinDbgAdapter(runner)

        adapter.get_analysis()
        adapter.get_exception_context()
        adapter.append_symbol_path(r"C:\symbols")
        adapter.get_analysis()
        adapter.get_exception_context()

        assert mock.call_count["!analyze -v"] == 2
        assert mock.call_count[".ecxr"] == 2
        assert mock.call_count[".lastevent"] == 2
        assert mock.call_count["r"] == 2

    def test_run_raw_thread_switch_invalidates_context_caches(self):
        """Test that raw thread-switch commands invalidate thread-sensitive caches."""
        mock = MockCDBSession()
        mock.set_response(".lastevent", ["Last event: 1.2: Access violation - code c0000005"])
        mock.set_response(".ecxr", ["exception_info"])
        mock.set_response("r", ["rip=00007ff700131ee4"])
        mock.set_response("~0s", ["thread switched"])
        runner = CommandRunner(mock)
        adapter = WinDbgAdapter(runner)

        adapter.get_exception_context()
        adapter.run_raw("~0s")
        adapter.get_exception_context()

        assert mock.call_count[".ecxr"] == 2
        assert mock.call_count[".lastevent"] == 2
        assert mock.call_count["r"] == 2

    def test_run_raw_frame_switch_invalidates_context_caches(self):
        """Test that raw frame-switch commands invalidate thread-sensitive caches."""
        mock = MockCDBSession()
        mock.set_response(".lastevent", ["Last event: 1.2: Access violation - code c0000005"])
        mock.set_response(".ecxr", ["exception_info"])
        mock.set_response("r", ["rip=00007ff700131ee4"])
        mock.set_response(".frame 1", ["frame switched"])
        runner = CommandRunner(mock)
        adapter = WinDbgAdapter(runner)

        adapter.get_exception_context()
        adapter.run_raw(".frame 1")
        adapter.get_exception_context()

        assert mock.call_count[".ecxr"] == 2
        assert mock.call_count[".lastevent"] == 2
        assert mock.call_count["r"] == 2

    def test_run_raw_symbol_change_invalidates_symbol_caches(self):
        """Test that raw symbol-path commands invalidate symbol-sensitive caches."""
        mock = MockCDBSession()
        mock.set_response("!analyze -v", ["analysis"])
        mock.set_response(".ecxr", ["exception_info"])
        mock.set_response(".lastevent", ["Last event: 1.2: Access violation - code c0000005"])
        mock.set_response("r", ["rip=00007ff700131ee4"])
        mock.set_response(".sympath+ c:\\symbols", ["path updated"])
        runner = CommandRunner(mock)
        adapter = WinDbgAdapter(runner)

        adapter.get_analysis()
        adapter.get_exception_context()
        adapter.run_raw(r".sympath+ C:\symbols")
        adapter.get_analysis()
        adapter.get_exception_context()

        assert mock.call_count["!analyze -v"] == 2
        assert mock.call_count[".ecxr"] == 2
        assert mock.call_count[".lastevent"] == 2
        assert mock.call_count["r"] == 2

    def test_get_cpp_exception_parses_common_exr_output(self):
        """Test parsing of standard .exr -1 output without 0x prefixes."""
        mock = MockCDBSession()
        mock.set_response(
            ".exr -1",
            [
                "ExceptionCode: e06d7363 (C++ EH exception)",
                "ExceptionFlags: 00000001",
                "ExceptionAddress: 00007ff6`a1234567",
                "NumberParameters = 4",
                "Parameter[0]: 00000000`19930520",
                "Parameter[1]: 00000000`00000000",
            ],
        )
        runner = CommandRunner(mock)
        adapter = WinDbgAdapter(runner)

        result = adapter.get_cpp_exception()

        assert result["exception_code"] == "0xE06D7363"
        assert result["exception_flags"] == "0x00000001"
        assert result["exception_address"] == "00007ff6`a1234567"
        assert result["parameters"] == ["00000000`19930520", "00000000`00000000"]
        assert "C++ EH exception" in result["raw_text"]

    def test_cache_disabled(self):
        """Test that use_cache=False bypasses cache."""
        mock = MockCDBSession()
        mock.set_response("lm", ["module1"])
        runner = CommandRunner(mock)

        runner.run("lm")
        runner.run("lm", use_cache=False)

        assert mock.call_count["lm"] == 2

    def test_lmv_prefix_cached(self):
        """Test that lmv commands are cached."""
        mock = MockCDBSession()
        mock.set_response("lmv m ntdll", ["details"])
        runner = CommandRunner(mock)

        runner.run("lmv m ntdll")
        runner.run("lmv m ntdll")

        assert mock.call_count["lmv m ntdll"] == 1
