# MCP Server for WinDbg Crash Analysis

MCP WinDbg is a Model Context Protocol server for Windows crash dump analysis and remote debugging. It wraps WinDbg/CDB so an MCP-compatible client can inspect dumps, query debugger state, and run targeted commands from natural language.

<!-- mcp-name: io.github.svnscha/mcp-windbg -->

## What It Does

- Analyze crash dumps with WinDbg/CDB
- Connect to remote debugging sessions
- Return structured summaries for common debugger output
- Preserve raw WinDbg command access for advanced investigations

This project is best for:

- Crash triage
- Hang and deadlock investigation
- Symbol and stack analysis
- Thread, memory, and lock inspection

It is not an auto-fix tool. It is a debugger bridge that helps an AI assistant ask better questions and interpret the results.

## Requirements

- Windows
- WinDbg or CDB installed
- Python 3.10+
- An MCP-compatible client such as Claude Desktop, Cursor, VS Code, Cline, or Windsurf

Useful environment variables:

- `CDB_PATH` to point at a custom `cdb.exe`
- `_NT_SYMBOL_PATH` to define your symbol search path

## Installation

### From PyPI

```powershell
pip install mcp-windbg
```

### From Source

```powershell
git clone https://github.com/Cropheonix/mcp-windbg.git
cd mcp-windbg
uv sync --dev
```

## Running The Server

### Stdio Transport

This is the default mode and works best for local MCP clients.

```powershell
mcp-windbg
```

You can also run it directly from Python:

```powershell
python -m mcp_windbg
```

### Streamable HTTP Transport

Use this when your client connects over HTTP or you want to run the server separately.

```powershell
mcp-windbg --transport streamable-http --host 127.0.0.1 --port 8000
```

The MCP endpoint is:

```text
http://127.0.0.1:8000/mcp
```

## Command Line Options

```text
--cdb-path PATH          Custom path to cdb.exe
--symbols-path PATH      Custom symbol path
--timeout SECONDS        Command timeout in seconds (default: 30)
--verbose                Enable verbose logging
--transport              stdio or streamable-http (default: stdio)
--host HOST              HTTP bind host (default: 127.0.0.1)
--port PORT              HTTP bind port (default: 8000)
--source-roots PATH...   Source roots for future source correlation
```

## Client Setup

### Visual Studio Code

Open the MCP configuration UI and add a server entry like this:

```json
{
  "servers": {
    "mcp_windbg": {
      "type": "stdio",
      "command": "mcp-windbg",
      "args": [],
      "env": {
        "_NT_SYMBOL_PATH": "SRV*C:\\Symbols*https://msdl.microsoft.com/download/symbols"
      }
    }
  }
}
```

If you prefer HTTP transport, point the client at:

```json
{
  "servers": {
    "mcp_windbg_http": {
      "type": "http",
      "url": "http://127.0.0.1:8000/mcp"
    }
  }
}
```

### Claude Desktop / Other MCP Clients

Use the same idea:

- Start `mcp-windbg` in `stdio` mode for local integrations
- Start `mcp-windbg --transport streamable-http ...` for HTTP clients
- Set `CDB_PATH` if WinDbg/CDB is not on the default path
- Set `_NT_SYMBOL_PATH` if you want symbol server caching

## Recommended Workflow

1. Open a crash dump with `open_windbg_dump` or connect to a live target with `open_windbg_remote`.
2. Start triage with `dump_summary`, `exception_context`, `stack_frames`, `module_status`, and `thread_list`.
3. Use deeper tools when needed:
   - `cpp_exception` for C++ exception records
   - `lock_status` for deadlock or critical section analysis
   - `cpp_object` for object inspection
   - `heap_block` for heap corruption or allocation tracing
   - `thread_cpu` for runaway thread analysis
   - `handles` for handle leak investigation
   - `frame_locals` for per-frame locals
   - `read_memory` for raw memory inspection
4. Fall back to `run_windbg_cmd` when you need a raw WinDbg command that is not exposed as a dedicated tool.

## Tool Reference

### Session Management

| Tool | Purpose |
|------|---------|
| `open_windbg_dump` | Open a crash dump and begin analysis |
| `open_windbg_remote` | Connect to a remote debugging target |
| `close_windbg_dump` | Close a dump session |
| `close_windbg_remote` | Close a remote session |
| `list_windbg_dumps` | Discover local dump files |
| `send_ctrl_break` | Break into the active debugger session |
| `run_windbg_cmd` | Run a raw WinDbg command |

### Structured Analysis

| Tool | Purpose |
|------|---------|
| `dump_summary` | High-level crash summary |
| `stack_frames` | Parsed stack trace for the current thread |
| `module_status` | Loaded module information |
| `exception_context` | Exception record, last event, and registers |
| `thread_list` | Debugger thread list |
| `frame_locals` | Local variables for a frame |
| `read_memory` | Read memory at an address |

### Deeper Investigation

| Tool | Purpose |
|------|---------|
| `cpp_exception` | Inspect C++ exception records |
| `lock_status` | Inspect critical sections and locks |
| `cpp_object` | Inspect C++ object layout |
| `heap_block` | Analyze a heap block |
| `thread_cpu` | Show CPU time by thread |
| `handles` | Inspect handle usage |

## Example Prompts

- "Open the dump and give me a concise triage summary."
- "Show me the current exception context and explain the likely root cause."
- "Compare the top user frames and highlight anything suspicious."
- "Check for lock contention or deadlocks."
- "Inspect this heap address and tell me whether it looks corrupted."
- "Break into the live target and show all thread stacks."

## Troubleshooting

### WinDbg/CDB Not Found

If the server cannot locate `cdb.exe`, set `CDB_PATH` explicitly.

### Symbols Are Missing

Set `_NT_SYMBOL_PATH` or use `--symbols-path` so WinDbg can resolve symbols.

### No Dumps Appear

The `list_windbg_dumps` tool looks in the configured local dump directory. If nothing appears, make sure your dumps exist and that your client has access to the directory.

### Version Mismatch

Run the consistency check:

```powershell
.\scripts\check-version-consistency.ps1
```

## Development

```powershell
uv sync --dev
uv run pytest src/mcp_windbg/tests/ -v
```

To run the server in development:

```powershell
uv run python -m mcp_windbg --verbose
```

## License

MIT
