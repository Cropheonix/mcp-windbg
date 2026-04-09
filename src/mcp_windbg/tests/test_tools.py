"""Unit tests for all MCP tool handlers.

Uses mock CommandRunner to test tool handler logic without CDB.
"""

from pathlib import Path

import pytest
from unittest.mock import MagicMock, patch

from mcp_windbg.session.manager import SessionManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_sm(runner_mock):
    """Create a SessionManager mock that returns the given runner."""
    sm = MagicMock(spec=SessionManager)
    sm.get_runner.return_value = runner_mock
    return sm


def _make_runner_mock():
    """Create a mock CommandRunner."""
    return MagicMock()


def _get_handler(module, runner_mock):
    """Register a tool module and return its handlers dict."""
    sm = _make_mock_sm(runner_mock)
    _, handlers = module.register(sm)
    return handlers


BASE_ARGS = {"dump_path": "test.dmp"}
FIXTURE_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> list[str]:
    """Load a test fixture as a list of lines."""
    return (FIXTURE_DIR / name).read_text(encoding="utf-8").splitlines()


# ---------------------------------------------------------------------------
# get_cpp_exception
# ---------------------------------------------------------------------------

class TestCppExceptionTool:
    def setup_method(self):
        from mcp_windbg.tools import cpp_exception
        self.module = cpp_exception

    def test_register(self):
        runner = _make_runner_mock()
        tools, handlers = self.module.register(_make_mock_sm(runner))
        assert tools[0].name == "get_cpp_exception"
        assert "get_cpp_exception" in handlers

    def test_parse_exception_code(self):
        runner = _make_runner_mock()
        runner.run.return_value = [
            "ExceptionCode: e06d7363 (C++ EH exception)",
            "ExceptionFlags: 00000001",
            "ExceptionAddress: 00007ff6`a1234567",
            "NumberParameters = 4",
            "Parameter[0]: 00000000`19930520",
        ]
        result = _get_handler(self.module, runner)["get_cpp_exception"]({
            **BASE_ARGS, "detail_level": "summary",
        })
        text = result[0].text
        assert "0xE06D7363" in text
        assert "C++ Exception" in text
        assert "00007ff6`a1234567" in text

    def test_missing_exception_code(self):
        runner = _make_runner_mock()
        runner.run.return_value = ["Unable to get exception record."]
        result = _get_handler(self.module, runner)["get_cpp_exception"]({
            **BASE_ARGS, "detail_level": "summary",
        })
        assert "N/A" in result[0].text


# ---------------------------------------------------------------------------
# get_lock_status (enhanced !locks -v parser)
# ---------------------------------------------------------------------------

class TestLockStatusTool:
    def setup_method(self):
        from mcp_windbg.tools import lock_status
        self.module = lock_status

    def test_register(self):
        runner = _make_runner_mock()
        tools, _ = self.module.register(_make_mock_sm(runner))
        assert tools[0].name == "get_lock_status"

    def test_no_locks(self):
        runner = _make_runner_mock()
        runner.run.return_value = ["No locks found."]
        result = _get_handler(self.module, runner)["get_lock_status"]({
            **BASE_ARGS, "detail_level": "summary",
        })
        assert "Locked: 0" in result[0].text

    def test_locked_with_owner(self):
        runner = _make_runner_mock()
        runner.run.return_value = [
            "CritSec 00007ff6`a1002000 at 00007ff6`a1002000",
            "WaitersWoken    : 0",
            "LockCount       : 1",
            "RecursionCount  : 1",
            "OwningThread    : 1a2b",
            "*** Locked",
            "",
            "CritSec 00007ff6`a1003000 at 00007ff6`a1003000",
            "LockCount       : 0",
            "*** NOT Locked",
        ]
        result = _get_handler(self.module, runner)["get_lock_status"]({
            **BASE_ARGS, "detail_level": "summary",
        })
        text = result[0].text
        assert "Locked: 1" in text

    def test_lock_with_waiters(self):
        runner = _make_runner_mock()
        runner.run.return_value = [
            "CritSec 00007ff6`a1002000 at 00007ff6`a1002000",
            "LockCount       : 2",
            "RecursionCount  : 1",
            "OwningThread    : 1a2b",
            "*** Locked",
            "Thread 2:3c4d  waiting",
            "Thread 3:5e6f  waiting",
        ]
        result = _get_handler(self.module, runner)["get_lock_status"]({
            **BASE_ARGS, "detail_level": "structured",
        })
        text = result[0].text
        assert "2 waiter(s)" in text
        assert "potential deadlock" in text.lower()


# ---------------------------------------------------------------------------
# inspect_cpp_object
# ---------------------------------------------------------------------------

class TestCppObjectTool:
    def setup_method(self):
        from mcp_windbg.tools import cpp_object
        self.module = cpp_object

    def test_register(self):
        runner = _make_runner_mock()
        tools, _ = self.module.register(_make_mock_sm(runner))
        assert tools[0].name == "inspect_cpp_object"

    def test_parse_object_fields(self):
        runner = _make_runner_mock()
        runner.run.return_value = [
            "   +0x000 __VFN_table : 0x00007ff6`a2003000",
            "   +0x008 m_title      : 0x00007ff6`a1002000 \"Hello\"",
            "   +0x010 m_width      : 0n800",
            "   +0x014 m_height     : 0n600",
            "   +0x018 m_active     : true",
        ]
        result = _get_handler(self.module, runner)["inspect_cpp_object"]({
            **BASE_ARGS,
            "address": "0x00007ff6`a1001000",
            "type_name": "MyApp!MainWindow",
            "depth": 1,
            "detail_level": "structured",
        })
        assert "MainWindow" in result[0].text
        assert "5 fields" in result[0].text

    def test_auto_detect_type(self):
        runner = _make_runner_mock()
        runner.run.return_value = [
            "   +0x000 field_a : 1",
            "   +0x004 field_b : 2",
        ]
        result = _get_handler(self.module, runner)["inspect_cpp_object"]({
            **BASE_ARGS, "address": "0x12345678",
            "detail_level": "summary",
        })
        assert "auto-detect" in result[0].text
        assert "2 fields" in result[0].text


# ---------------------------------------------------------------------------
# analyze_heap_block
# ---------------------------------------------------------------------------

class TestHeapBlockTool:
    def setup_method(self):
        from mcp_windbg.tools import heap_block
        self.module = heap_block

    def test_register(self):
        runner = _make_runner_mock()
        tools, _ = self.module.register(_make_mock_sm(runner))
        assert tools[0].name == "analyze_heap_block"

    def test_analyze_specific_block(self):
        runner = _make_runner_mock()
        runner.run.return_value = [
            "    address 00007ff6`a1001234 found in",
            "    _HEAP at 00007ff6`a1000000",
            "      size: 256",
            "      flags: busy",
            "    stack trace:",
            "        0  00007ff6`a2001000 MyApp!operator_new+0x20",
            "        1  00007ff6`a2002000 MyApp!CreateBuffer+0x3c",
        ]
        result = _get_handler(self.module, runner)["analyze_heap_block"]({
            **BASE_ARGS, "address": "00007ff6`a1001234",
            "detail_level": "structured",
        })
        text = result[0].text
        assert "256 bytes" in text
        assert "busy" in text

    def test_heap_summary(self):
        runner = _make_runner_mock()
        runner.run.return_value = [
            "Heap Flags   Reserved  Committed  Blocks",
            "00007ff6`a1000000 00000002  1024000    512000     128",
            "00007ff6`a2000000 00001000   256000     64000      64",
        ]
        result = _get_handler(self.module, runner)["analyze_heap_block"]({
            **BASE_ARGS, "detail_level": "summary",
        })
        assert "2 heap" in result[0].text

    def test_no_address_gives_summary(self):
        runner = _make_runner_mock()
        runner.run.return_value = ["Heap Flags   Reserved  Committed  Blocks"]
        result = _get_handler(self.module, runner)["analyze_heap_block"](BASE_ARGS)
        assert "heap" in result[0].text.lower()


# ---------------------------------------------------------------------------
# analyze_thread_cpu (NEW)
# ---------------------------------------------------------------------------

class TestThreadCpuTool:
    def setup_method(self):
        from mcp_windbg.tools import thread_cpu
        self.module = thread_cpu

    def test_register(self):
        runner = _make_runner_mock()
        tools, _ = self.module.register(_make_mock_sm(runner))
        assert tools[0].name == "analyze_thread_cpu"

    def test_parse_runaway_output(self):
        runner = _make_runner_mock()
        runner.run.return_value = [
            " User mode time",
            "  Thread       Time",
            "   0:1ebc       0 days 0:00:05.123",
            "   1:2a3f       0 days 0:00:00.015",
            " Kernel mode time",
            "  Thread       Time",
            "   0:1ebc       0 days 0:00:01.456",
            "   1:2a3f       0 days 0:00:00.002",
        ]
        result = _get_handler(self.module, runner)["analyze_thread_cpu"]({
            **BASE_ARGS, "detail_level": "structured",
        })
        text = result[0].text
        assert "2 threads" in text
        assert "thread #0" in text
        # Total = 5.123 + 1.456 = 6.579
        assert "6.579" in text

    def test_empty_runaway(self):
        runner = _make_runner_mock()
        runner.run.return_value = ["No runnable threads found."]
        result = _get_handler(self.module, runner)["analyze_thread_cpu"]({
            **BASE_ARGS, "detail_level": "summary",
        })
        assert "0 threads" in result[0].text


# ---------------------------------------------------------------------------
# check_handles (NEW)
# ---------------------------------------------------------------------------

class TestHandlesTool:
    def setup_method(self):
        from mcp_windbg.tools import handles
        self.module = handles

    def test_register(self):
        runner = _make_runner_mock()
        tools, _ = self.module.register(_make_mock_sm(runner))
        assert tools[0].name == "check_handles"

    def test_handle_summary(self):
        runner = _make_runner_mock()
        runner.run.return_value = [
            "245 handles of type File",
            "180 handles of type Event",
            "42 handles of type Mutex",
            "1500 handles of type Section",
        ]
        result = _get_handler(self.module, runner)["check_handles"]({
            **BASE_ARGS, "detail_level": "summary",
        })
        text = result[0].text
        assert "1967 total handles" in text
        # Section with 1500 should trigger leak warning
        assert "warning" in text.lower()

    def test_handle_type_filter(self):
        runner = _make_runner_mock()
        runner.run.return_value = [
            "HANDLE 000000A0: File",
            "HANDLE 000000B4: File",
            "HANDLE 000000C8: File",
        ]
        result = _get_handler(self.module, runner)["check_handles"]({
            **BASE_ARGS, "handle_type": "File",
            "detail_level": "structured",
        })
        text = result[0].text
        assert "3 handle(s)" in text
        assert "File" in text

    def test_empty_handles(self):
        runner = _make_runner_mock()
        runner.run.return_value = ["0 Handles"]
        result = _get_handler(self.module, runner)["check_handles"]({
            **BASE_ARGS, "detail_level": "summary",
        })
        assert "0 total handles" in result[0].text


# ---------------------------------------------------------------------------
# Structured tools (dump_summary, stack_frames, module_status, exception_context)
# ---------------------------------------------------------------------------

class TestDumpSummaryTool:
    def setup_method(self):
        from mcp_windbg.tools import dump_summary
        self.module = dump_summary

    def test_register(self):
        runner = _make_runner_mock()
        tools, _ = self.module.register(_make_mock_sm(runner))
        assert tools[0].name == "analyze_dump_summary"

    def test_summary_output(self):
        runner = _make_runner_mock()
        command_map = {
            "!analyze -v": load_fixture("analyze_v_access_violation.txt"),
            ".ecxr": load_fixture("ecxr_access_violation.txt"),
            ".lastevent": load_fixture("lastevent.txt"),
            "r": load_fixture("registers.txt"),
            "lm": load_fixture("lm_with_symbols.txt"),
            "kv": load_fixture("kv_simple.txt"),
        }

        def run_side_effect(command, timeout=None, use_cache=True):
            return command_map[command]

        runner.run.side_effect = run_side_effect
        result = _get_handler(self.module, runner)["analyze_dump_summary"]({
            **BASE_ARGS, "detail_level": "summary",
        })
        text = result[0].text
        assert "0xC0000005" in text
        assert "Access violation" in text
        assert "DemoCrash1" in text
        assert "DemoCrash1+1ee4" in text


class TestStackFramesTool:
    def setup_method(self):
        from mcp_windbg.tools import stack_frames
        self.module = stack_frames

    def test_register(self):
        runner = _make_runner_mock()
        tools, _ = self.module.register(_make_mock_sm(runner))
        assert tools[0].name == "get_stack_frames"

    @patch("mcp_windbg.tools.stack_frames.WinDbgAdapter")
    def test_stack_with_frame_labels(self, MockAdapter):
        from mcp_windbg.models.dump_models import StackFrame, StackResult
        mock_adapter = MockAdapter.return_value
        mock_adapter.get_stack.return_value = StackResult(
            frames=[
                StackFrame(frame_number=0, module="MyApp", function="main",
                           offset=0x20, is_user_code=True, frame_label="user"),
                StackFrame(frame_number=1, module="Qt6Core", function="QMetaObject::activate",
                           offset=0x120, is_framework=True, frame_label="framework"),
                StackFrame(frame_number=2, module="ntdll", function="NtWaitForSingleObject",
                           offset=0x14, is_system=True, frame_label="system"),
            ],
            total_frames=3,
            command_used="kv",
            raw_text="fake stack",
        )
        runner = _make_runner_mock()
        sm = _make_mock_sm(runner)
        _, handlers = self.module.register(sm)

        result = handlers["get_stack_frames"]({
            **BASE_ARGS, "detail_level": "summary",
        })
        text = result[0].text
        assert "3 frames" in text
        assert "1 user" in text
        assert "1 framework" in text
        assert "1 system" in text

    @patch("mcp_windbg.tools.stack_frames.WinDbgAdapter")
    def test_thread_switch_and_stack(self, MockAdapter):
        from mcp_windbg.models.dump_models import StackFrame, StackResult
        mock_adapter = MockAdapter.return_value
        mock_adapter.get_stack.return_value = StackResult(
            frames=[StackFrame(frame_number=0, module="MyApp", function="worker",
                                offset=0x10, is_user_code=True, frame_label="user")],
            total_frames=1,
            command_used="k",
            raw_text="",
        )
        runner = _make_runner_mock()
        _, handlers = self.module.register(_make_mock_sm(runner))

        result = handlers["get_stack_frames"]({
            **BASE_ARGS, "thread_id": 3, "stack_command": "k",
            "detail_level": "summary",
        })
        text = result[0].text
        assert "Thread 3" in text
        mock_adapter.switch_thread.assert_called_once_with(3)


class TestModuleStatusTool:
    def setup_method(self):
        from mcp_windbg.tools import module_status
        self.module = module_status

    def test_register(self):
        runner = _make_runner_mock()
        tools, _ = self.module.register(_make_mock_sm(runner))
        assert tools[0].name == "get_modules_status"

    @patch("mcp_windbg.tools.module_status.WinDbgAdapter")
    def test_modules_with_symbol_warnings(self, MockAdapter):
        from mcp_windbg.models.dump_models import ModuleInfo, ModuleListResult
        mock_adapter = MockAdapter.return_value
        mock_adapter.get_modules.return_value = ModuleListResult(
            modules=[
                ModuleInfo(name="MyApp", base_address="0x1000", end_address="0x2000",
                           has_symbols=True, is_user_module=True),
                ModuleInfo(name="ntdll", base_address="0x7000", end_address="0x8000",
                           has_symbols=True, is_user_module=False),
                ModuleInfo(name="MyLib", base_address="0x3000", end_address="0x4000",
                           has_symbols=False, is_user_module=True, symbol_type="deferred"),
            ],
            total_count=3,
            symbol_warnings=["MyLib has no symbols (deferred)"],
            raw_text="fake lm",
        )
        runner = _make_runner_mock()
        _, handlers = self.module.register(_make_mock_sm(runner))

        result = handlers["get_modules_status"]({
            **BASE_ARGS, "detail_level": "structured",
        })
        text = result[0].text
        assert "3 modules" in text
        assert "User modules: 2" in text
        assert "1 without" in text
        assert "1 warning" in text


class TestExceptionContextTool:
    def setup_method(self):
        from mcp_windbg.tools import exception_context
        self.module = exception_context

    def test_register(self):
        runner = _make_runner_mock()
        tools, _ = self.module.register(_make_mock_sm(runner))
        assert tools[0].name == "get_exception_context"

    @patch("mcp_windbg.tools.exception_context.WinDbgAdapter")
    def test_exception_context_output(self, MockAdapter):
        from mcp_windbg.models.dump_models import ExceptionContextResult
        mock_adapter = MockAdapter.return_value
        mock_adapter.get_exception_context.return_value = ExceptionContextResult(
            exception_code="0xC0000005",
            exception_type="Access Violation",
            exception_address="0x00007ff6`a0001234",
            registers={"rax": "0x0000000000000000", "rbx": "0x00007ff6a1001000"},
            last_event="Access violation - code c0000005",
            raw_text="fake ctx",
        )
        runner = _make_runner_mock()
        _, handlers = self.module.register(_make_mock_sm(runner))

        result = handlers["get_exception_context"]({
            **BASE_ARGS, "detail_level": "summary",
        })
        text = result[0].text
        assert "Access Violation" in text
        assert "0xC0000005" in text
        assert "0x00007ff6" in text

    def test_exception_context_uses_real_fixtures(self):
        runner = _make_runner_mock()
        command_map = {
            ".ecxr": load_fixture("ecxr_access_violation.txt"),
            ".lastevent": load_fixture("lastevent.txt"),
            "r": load_fixture("registers.txt"),
        }

        def run_side_effect(command, timeout=None, use_cache=True):
            return command_map[command]

        runner.run.side_effect = run_side_effect
        result = _get_handler(self.module, runner)["get_exception_context"]({
            **BASE_ARGS, "detail_level": "summary",
        })

        text = result[0].text
        assert "0xC0000005" in text
        assert "Access violation" in text
        assert "00007ff700131ee4" in text


# ---------------------------------------------------------------------------
# Iterative tools (thread_list, frame_locals, read_memory)
# ---------------------------------------------------------------------------

class TestThreadListTool:
    def setup_method(self):
        from mcp_windbg.tools import thread_list
        self.module = thread_list

    def test_register(self):
        runner = _make_runner_mock()
        tools, _ = self.module.register(_make_mock_sm(runner))
        assert tools[0].name == "list_threads"

    @patch("mcp_windbg.tools.thread_list.WinDbgAdapter")
    def test_thread_list_basic(self, MockAdapter):
        from mcp_windbg.models.dump_models import ThreadInfo, ThreadListResult
        mock_adapter = MockAdapter.return_value
        mock_adapter.get_threads.return_value = ThreadListResult(
            threads=[
                ThreadInfo(thread_number=0, os_id="1a2b", suspend_count=0, is_current=True),
                ThreadInfo(thread_number=1, os_id="3c4d", suspend_count=1, is_current=False),
            ],
            current_thread=0,
            total_count=2,
            raw_text="fake threads",
        )
        runner = _make_runner_mock()
        _, handlers = self.module.register(_make_mock_sm(runner))

        result = handlers["list_threads"]({**BASE_ARGS, "detail_level": "summary"})
        text = result[0].text
        assert "2 threads" in text
        assert "Current thread: 0" in text

    @patch("mcp_windbg.tools.thread_list.WinDbgAdapter")
    def test_thread_list_with_stacks(self, MockAdapter):
        from mcp_windbg.models.dump_models import ThreadInfo, ThreadListResult
        mock_adapter = MockAdapter.return_value
        mock_adapter.get_threads.return_value = ThreadListResult(
            threads=[ThreadInfo(thread_number=0, os_id="1a2b", suspend_count=0, is_current=True)],
            current_thread=0, total_count=1, raw_text="",
        )
        mock_adapter.get_thread_stacks.return_value = "  0  addr1  addr2  ntdll!func"
        runner = _make_runner_mock()
        _, handlers = self.module.register(_make_mock_sm(runner))

        result = handlers["list_threads"]({
            **BASE_ARGS, "include_stacks": True, "detail_level": "structured",
        })
        text = result[0].text
        assert "1 threads" in text
        mock_adapter.get_thread_stacks.assert_called_once_with("k")


class TestFrameLocalsTool:
    def setup_method(self):
        from mcp_windbg.tools import frame_locals
        self.module = frame_locals

    def test_register(self):
        runner = _make_runner_mock()
        tools, _ = self.module.register(_make_mock_sm(runner))
        assert tools[0].name == "get_frame_locals"

    @patch("mcp_windbg.tools.frame_locals.WinDbgAdapter")
    def test_frame_locals_output(self, MockAdapter):
        from mcp_windbg.parsers.locals_parser import LocalVariable, FrameLocalsResult
        mock_adapter = MockAdapter.return_value
        mock_adapter.get_frame_locals.return_value = FrameLocalsResult(
            frame_number=2,
            frame_function="MyApp!ProcessData",
            locals=[
                LocalVariable(name="buffer", type_name="char*", address="0x0012ff60",
                              value="0x00007ff6`a1001000", is_param=False),
                LocalVariable(name="size", type_name="int", value="256", is_param=True),
            ],
            raw_text="fake dv",
        )
        runner = _make_runner_mock()
        _, handlers = self.module.register(_make_mock_sm(runner))

        result = handlers["get_frame_locals"]({
            **BASE_ARGS, "frame_number": 2, "detail_level": "structured",
        })
        text = result[0].text
        assert "Frame 2" in text
        assert "ProcessData" in text
        assert "2 variables" in text
        assert "1 parameters" in text


class TestReadMemoryTool:
    def setup_method(self):
        from mcp_windbg.tools import read_memory
        self.module = read_memory

    def test_register(self):
        runner = _make_runner_mock()
        tools, _ = self.module.register(_make_mock_sm(runner))
        assert tools[0].name == "read_memory"

    @patch("mcp_windbg.tools.read_memory.WinDbgAdapter")
    def test_read_memory_hex(self, MockAdapter):
        from mcp_windbg.parsers.memory_parser import MemoryLine, MemoryResult
        mock_adapter = MockAdapter.return_value
        mock_adapter.read_memory.return_value = MemoryResult(
            address="0x0012ff60",
            length=128,
            format="hex",
            lines=[
                MemoryLine(address="0x0012ff60", hex_data="48 65 6c 6c 6f",
                           ascii_data="Hello"),
                MemoryLine(address="0x0012ff65", hex_data="00 00 00 00",
                           ascii_data="...."),
            ],
            raw_text="fake db",
        )
        runner = _make_runner_mock()
        _, handlers = self.module.register(_make_mock_sm(runner))

        result = handlers["read_memory"]({
            **BASE_ARGS, "address": "0x0012ff60", "format": "hex",
            "length": 128, "detail_level": "structured",
        })
        text = result[0].text
        assert "0x0012ff60" in text
        assert "hex" in text
        assert "2 lines" in text
        mock_adapter.read_memory.assert_called_once_with(
            address="0x0012ff60", length=128, format="hex"
        )
