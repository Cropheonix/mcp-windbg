# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MCP server that bridges AI models with WinDbg/CDB for Windows crash dump analysis and live debugging. Python package `mcp-windbg`, distributed via PyPI. Requires Windows with Debugging Tools installed.

Provides four tiers of tools (20 total):
- **Legacy tools** (7): `open_windbg_dump`, `open_windbg_remote`, `run_windbg_cmd`, `send_ctrl_break`, `close_windbg_dump`, `close_windbg_remote`, `list_windbg_dumps` — raw CDB command forwarding
- **Structured tools** (4): `analyze_dump_summary`, `get_stack_frames`, `get_modules_status`, `get_exception_context` — parsed, typed output with frame labeling
- **Iterative debugging** (3): `list_threads`, `get_frame_locals`, `read_memory` — step-by-step crash investigation
- **C++ deep debugging** (6): `get_cpp_exception`, `get_lock_status`, `inspect_cpp_object`, `analyze_heap_block`, `analyze_thread_cpu`, `check_handles` — advanced C++ crash analysis, deadlock detection, resource leak diagnosis

## Build & Test Commands

```bash
# Install dev dependencies (uses uv)
uv sync --dev

# Run all tests
uv run pytest src/mcp_windbg/tests/ -v

# Run only unit tests (no CDB required)
uv run pytest src/mcp_windbg/tests/test_parsers/ src/mcp_windbg/tests/test_session/ src/mcp_windbg/tests/test_models.py -v

# Run a single test file
uv run pytest src/mcp_windbg/tests/test_cdb.py -v

# Run the server locally
uv run python -m mcp_windbg --verbose
uv run python -m mcp_windbg --transport streamable-http --port 8000

# Run with source roots (Phase 2)
uv run python -m mcp_windbg --source-roots D:\repo\app

# Validate version consistency
powershell -File scripts/check-version-consistency.ps1

# Validate server.json against MCP schema
uv run python scripts/validate-server-schema.py
```

Tests require CDB installed and test dump files from Git LFS (`git lfs pull`).

## Architecture

```
src/mcp_windbg/
  __init__.py          # CLI entry point (--source-roots, --transport)
  server.py            # MCP registration shell, imports tools
  cdb_session.py       # Re-export shim → session/cdb_session.py
  session/
    cdb_session.py     # CDB subprocess wrapper (marker-based completion)
    manager.py         # SessionManager: lifecycle + CommandRunner instances
    command_runner.py  # CommandRunner: caching for deterministic commands
  adapters/
    windbg_adapter.py  # CDB command → parsed result (glues runners + parsers)
    symbol_path.py     # Symbol path construction
  parsers/
    analyze_parser.py  # !analyze -v → AnalyzeResult
    stack_parser.py    # k/kv → StackResult (frame labeling: user/framework/system)
    module_parser.py   # lm/lmv → ModuleListResult (symbol warnings)
    exception_parser.py # .ecxr/.lastevent/r → ExceptionContextResult
    thread_parser.py   # ~ → ThreadListResult
    locals_parser.py   # dv /t /i → FrameLocalsResult
    memory_parser.py   # db/dd/dq/du/da → MemoryResult
  tools/
    legacy.py          # Existing 7 tools (refactored to use adapter internally)
    dump_summary.py    # analyze_dump_summary: fixed command sequence, structured output
    stack_frames.py    # get_stack_frames: parsed frames with labeling
    module_status.py   # get_modules_status: modules + symbol warnings
    exception_context.py # get_exception_context: structured exception info
    thread_list.py     # list_threads: thread enumeration
    frame_locals.py    # get_frame_locals: frame variable inspection
    read_memory.py     # read_memory: address-based memory reading
    cpp_exception.py   # get_cpp_exception: .exr -1 C++ exception details
    lock_status.py     # get_lock_status: !locks -v critical section status with waiter detection
    cpp_object.py      # inspect_cpp_object: dt C++ object structure
    heap_block.py      # analyze_heap_block: heap block analysis & summary
    thread_cpu.py      # analyze_thread_cpu: !runaway thread CPU time analysis
    handles.py         # check_handles: !handle handle leak detection
  models/
    session_models.py  # Pydantic parameter models for all tools
    dump_models.py     # Structured output models + EXCEPTION_CODE_MAP
    response_models.py # OutputTier, TieredResponse (summary/structured/raw_excerpt/raw_full)
```

**Data flow**: Tool handler → `SessionManager.get_runner()` → `WinDbgAdapter` → `CommandRunner.run()` → `CDBSession.send_command()` → raw text → `Parser` → typed `Pydantic model` → `TieredResponse` → `TextContent`

**Frame labeling** (`stack_parser.label_frame`): Each stack frame is labeled as `user` (your code), `framework` (Qt5/Qt6 modules), or `system` (ntdll, kernel32, etc.).

**Caching** (`CommandRunner`): `lm`, `!analyze -v`, `.ecxr`, `.lastevent`, `vertarget`, `.time`, `~` are cached per session. Thread-switch commands invalidate stack/register caches.

## Version Management

Version must be synchronized in three places before release:
1. `pyproject.toml` — `version = "X.Y.Z"`
2. `server.json` — `"version"` (two occurrences)
3. `CHANGELOG.md` — `## [X.Y.Z] - YYYY-MM-DD`

Tag-based release: pushing a `v*` tag triggers `publish-mcp.yml` which tests, builds, and publishes to PyPI.

## Key Dependencies

- `mcp` — MCP SDK (server, transports, types)
- `pydantic` — Input validation and structured output models
- `starlette` + `uvicorn` — HTTP transport
