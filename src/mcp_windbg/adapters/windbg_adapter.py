"""Unified adapter for CDB command execution with parsing."""

import re
from typing import List, Optional

from mcp_windbg.session.command_runner import CommandRunner
from mcp_windbg.models.dump_models import (
    AnalyzeResult,
    StackResult,
    ModuleListResult,
    ModuleInfo,
    ExceptionContextResult,
    ThreadListResult,
)
from mcp_windbg.parsers.analyze_parser import parse_analyze_output
from mcp_windbg.parsers.stack_parser import parse_stack_output
from mcp_windbg.parsers.module_parser import parse_module_list, parse_module_detail
from mcp_windbg.parsers.exception_parser import parse_exception_context
from mcp_windbg.parsers.thread_parser import parse_thread_list
from mcp_windbg.parsers.locals_parser import parse_frame_locals, FrameLocalsResult
from mcp_windbg.parsers.memory_parser import parse_memory_output, MemoryResult


class WinDbgAdapter:
    """Unified interface for running CDB commands and getting parsed results.

    Each method executes a CDB command via CommandRunner, passes the raw
    output to the appropriate parser, and returns a typed Pydantic model.
    """

    def __init__(self, runner: CommandRunner):
        self._runner = runner

    THREAD_SWITCH_RE = re.compile(r"^~\d+\s*[sS]$")
    FRAME_SWITCH_RE = re.compile(r"^\.frame\b", re.IGNORECASE)
    SYMBOL_INVALIDATION_PREFIXES = (".sympath", ".symfix", ".reload")

    def get_analysis(self) -> AnalyzeResult:
        """Run !analyze -v and return parsed result."""
        raw = self._runner.run("!analyze -v")
        return parse_analyze_output(raw)

    def switch_thread(self, thread_id: int) -> List[str]:
        """Switch debugger context to a different thread and invalidate thread-sensitive caches."""
        raw = self._runner.run(f"~{thread_id}s", use_cache=False)
        self._runner.invalidate_stack_caches()
        return raw

    def set_frame(self, frame_number: int) -> List[str]:
        """Switch debugger context to a different frame and invalidate thread-sensitive caches."""
        raw = self._runner.run(f".frame {frame_number}", use_cache=False)
        self._runner.invalidate_stack_caches()
        return raw

    def append_symbol_path(self, path: str) -> List[str]:
        """Append a symbol path and invalidate symbol-sensitive caches."""
        raw = self._runner.run(f".sympath+ {path}", use_cache=False)
        self._runner.invalidate_symbol_caches()
        return raw

    def get_stack(self, command: str = "kv") -> StackResult:
        """Run a stack command (k/kv/kp/kn) and return parsed result."""
        raw = self._runner.run(command)
        return parse_stack_output(raw, command)

    def get_modules(self) -> ModuleListResult:
        """Run lm and return parsed module list."""
        raw = self._runner.run("lm")
        return parse_module_list(raw)

    def get_module_detail(self, module_name: str) -> ModuleInfo:
        """Run lmv m <module> and return detailed module info."""
        raw = self._runner.run(f"lmv m {module_name}")
        return parse_module_detail(raw)

    def get_exception_context(self) -> ExceptionContextResult:
        """Run .ecxr, .lastevent, r and return parsed exception context."""
        ecxr_lines = self._runner.run(".ecxr")
        lastevent_lines = self._runner.run(".lastevent")
        register_lines = self._runner.run("r")
        return parse_exception_context(ecxr_lines, lastevent_lines, register_lines)

    def get_threads(self) -> ThreadListResult:
        """Run ~ and return parsed thread list."""
        raw = self._runner.run("~")
        return parse_thread_list(raw)

    def get_thread_stacks(self, command: str = "k") -> str:
        """Run ~*k and return raw text for all thread stacks."""
        raw = self._runner.run(f"~*{command}", use_cache=False)
        return "\n".join(raw)

    def get_frame_locals(self, frame_number: int) -> FrameLocalsResult:
        """Switch to a stack frame and get local variables.

        Runs: .frame <N>, dv /t /i
        """
        frame_output = self.set_frame(frame_number)
        dv_output = self._runner.run("dv /t /i", use_cache=False)
        return parse_frame_locals(frame_number, frame_output, dv_output)

    def read_memory(
        self,
        address: str,
        length: int = 128,
        format: str = "hex",
    ) -> MemoryResult:
        """Read memory at a given address.

        Args:
            address: Hex address string.
            length: Bytes to read.
            format: One of hex(db), dword(dd), qword(dq), unicode(du), ascii(da).
        """
        cmd_map = {
            "hex": "db",
            "dword": "dd",
            "qword": "dq",
            "unicode": "du",
            "ascii": "da",
        }
        cdb_cmd = cmd_map.get(format, "db")

        # For db/dd/dq, calculate number of elements from bytes
        element_sizes = {"db": 1, "dd": 4, "dq": 8}
        if cdb_cmd in element_sizes:
            count = max(1, length // element_sizes[cdb_cmd])
            full_cmd = f"{cdb_cmd} {address} L{count}"
        else:
            # du/da — just pass length
            full_cmd = f"{cdb_cmd} {address} L{max(1, length)}"

        raw = self._runner.run(full_cmd, use_cache=False)
        return parse_memory_output(raw, address, length, format)

    def get_cpp_exception(self) -> dict:
        """Run .exr -1 to get C++ exception record details.

        Returns dict with: exception_code, exception_flags, exception_address,
        p1/p2/p3/p4 (C++ exception params: type_info, throw_info, etc.),
        and raw_text.
        """
        raw = self._runner.run(".exr -1", use_cache=False)
        result = {"raw_text": "\n".join(raw)}
        for line in raw:
            code = self._extract_cpp_exception_field(
                line,
                r"ExceptionCode:\s*(?:0[xX])?([0-9a-fA-F]+)",
            )
            if code:
                result["exception_code"] = self._normalize_hex(code)

            flags = self._extract_cpp_exception_field(
                line,
                r"ExceptionFlags:\s*(?:0[xX])?([0-9a-fA-F]+)",
            )
            if flags:
                result["exception_flags"] = self._normalize_hex(flags)

            address = self._extract_cpp_exception_field(
                line,
                r"ExceptionAddress:\s*([0-9a-fA-F`]+)",
            )
            if address:
                result["exception_address"] = address

            # C++ exception parameters: support both "Parameter 0:" and "Parameter[0]:"
            param = self._extract_cpp_exception_field(
                line,
                r"Parameter(?:\[\d+\]|\s+\d+)\s*:\s*([0-9a-fA-F`]+)",
            )
            if param:
                result.setdefault("parameters", []).append(param)
        return result

    def get_lock_status(self) -> List[str]:
        """Run !locks -v and return raw output for detailed lock/critical section analysis."""
        return self._runner.run("!locks -v", use_cache=False)

    def inspect_cpp_object(self, type_name: Optional[str], address: str, depth: int = 1) -> List[str]:
        """Run dt command to display C++ object structure.

        Args:
            type_name: Optional type name (e.g., 'MyApp!MainWindow').
            address: Object address.
            depth: Recursion depth.
        """
        if type_name:
            cmd = f"dt -d{depth} {type_name} {address}"
        else:
            cmd = f"dt -d{depth} {address}"
        return self._runner.run(cmd, use_cache=False)

    def analyze_heap_block(self, address: str) -> List[str]:
        """Run !heap -p -a <address> to analyze a heap block."""
        return self._runner.run(f"!heap -p -a {address}", use_cache=False)

    def get_heap_summary(self) -> List[str]:
        """Run !heap -s to get heap summary statistics."""
        return self._runner.run("!heap -s", use_cache=False)

    def get_thread_cpu_time(self) -> List[str]:
        """Run !runaway to show thread CPU time consumption."""
        return self._runner.run("!runaway", use_cache=False)

    def get_handle_info(self, handle_type: Optional[str] = None) -> List[str]:
        """Run !handle to show handle information.

        Args:
            handle_type: Optional type filter (e.g., 'File', 'Event', 'Mutex').
                         If None, shows handle summary.
        """
        if handle_type:
            return self._runner.run(f"!handle 0 0 {handle_type}", use_cache=False)
        else:
            return self._runner.run("!handle", use_cache=False)

    def run_raw(self, command: str) -> List[str]:
        """Execute an arbitrary CDB command and return raw output.

        Used by the legacy run_windbg_cmd tool.
        """
        output = self._runner.run(command, use_cache=False)
        self._invalidate_after_raw_command(command)
        return output

    def _invalidate_after_raw_command(self, command: str) -> None:
        """Invalidate caches after a raw command mutates debugger state."""
        stack_sensitive = False
        symbol_sensitive = False

        for segment in (part.strip() for part in command.split(";")):
            if not segment:
                continue

            if self.THREAD_SWITCH_RE.match(segment) or self.FRAME_SWITCH_RE.match(segment):
                stack_sensitive = True

            lowered = segment.lower()
            if lowered.startswith(self.SYMBOL_INVALIDATION_PREFIXES):
                symbol_sensitive = True

        if stack_sensitive:
            self._runner.invalidate_stack_caches()

        if symbol_sensitive:
            self._runner.invalidate_symbol_caches()

    @staticmethod
    def _extract_cpp_exception_field(line: str, pattern: str) -> Optional[str]:
        match = re.search(pattern, line, re.IGNORECASE)
        if not match:
            return None
        return match.group(1).strip()

    @staticmethod
    def _normalize_hex(value: str) -> str:
        cleaned = value.strip()
        if cleaned.lower().startswith("0x"):
            cleaned = cleaned[2:]
        return f"0x{cleaned.upper()}"

    @property
    def runner(self) -> CommandRunner:
        """Access the underlying CommandRunner."""
        return self._runner
