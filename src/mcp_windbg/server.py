"""MCP server for WinDbg crash analysis — thin registration shell."""

import os
import traceback
import logging
from typing import Optional, List
from contextlib import asynccontextmanager

from mcp.shared.exceptions import McpError
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.types import (
    ErrorData,
    TextContent,
    Prompt,
    PromptArgument,
    PromptMessage,
    GetPromptResult,
    Tool,
    INVALID_PARAMS,
    INTERNAL_ERROR,
)

from mcp_windbg.session.manager import SessionManager, get_local_dumps_path
from mcp_windbg.prompts import load_prompt

# Backward-compatible module-level session functions for existing tests
_default_sm: Optional[SessionManager] = None


def _get_default_sm() -> SessionManager:
    global _default_sm
    if _default_sm is None:
        _default_sm = SessionManager()
    return _default_sm


def get_or_create_session(
    dump_path=None,
    connection_string=None,
    cdb_path=None,
    symbols_path=None,
    timeout=30,
    verbose=False,
):
    """Backward-compatible wrapper. Prefer SessionManager.get_or_create()."""
    sm = _get_default_sm()
    # Update config on each call (tests may pass different values)
    if cdb_path:
        sm._cdb_path = cdb_path
    if symbols_path:
        sm._symbols_path = symbols_path
    if timeout:
        sm._timeout = timeout
    if verbose:
        sm._verbose = verbose
    return sm.get_or_create(dump_path=dump_path, connection_string=connection_string)


def unload_session(dump_path=None, connection_string=None):
    """Backward-compatible wrapper. Prefer SessionManager.unload()."""
    sm = _get_default_sm()
    return sm.unload(dump_path=dump_path, connection_string=connection_string)


# Backward-compatible access to active sessions dict for existing tests
active_sessions = _get_default_sm()._sessions


# Import tool modules
from mcp_windbg.tools import (
    legacy,
    dump_summary,
    stack_frames,
    module_status,
    exception_context,
    thread_list,
    frame_locals,
    read_memory,
    cpp_exception,
    lock_status,
    cpp_object,
    heap_block,
    thread_cpu,
    handles,
)

logger = logging.getLogger(__name__)


async def serve(
    cdb_path: Optional[str] = None,
    symbols_path: Optional[str] = None,
    timeout: int = 30,
    verbose: bool = False,
    source_roots: Optional[List[str]] = None,
) -> None:
    """Run the WinDbg MCP server with stdio transport."""
    server = _create_server(cdb_path, symbols_path, timeout, verbose, source_roots)
    options = server.create_initialization_options()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, options, raise_exceptions=True)


async def serve_http(
    host: str = "127.0.0.1",
    port: int = 8000,
    cdb_path: Optional[str] = None,
    symbols_path: Optional[str] = None,
    timeout: int = 30,
    verbose: bool = False,
    source_roots: Optional[List[str]] = None,
) -> None:
    """Run the WinDbg MCP server with Streamable HTTP transport."""
    from starlette.applications import Starlette
    from starlette.routing import Mount
    from starlette.types import Receive, Scope, Send
    import uvicorn

    server = _create_server(cdb_path, symbols_path, timeout, verbose, source_roots)

    session_manager = StreamableHTTPSessionManager(
        app=server,
        json_response=True,
    )

    async def handle_streamable_http(scope: Scope, receive: Receive, send: Send) -> None:
        await session_manager.handle_request(scope, receive, send)

    @asynccontextmanager
    async def lifespan(app: Starlette):
        async with session_manager.run():
            yield

    app = Starlette(
        debug=verbose,
        routes=[
            Mount("/mcp", app=handle_streamable_http),
        ],
        lifespan=lifespan,
    )

    logger.info(f"Starting MCP WinDbg server with streamable-http transport on {host}:{port}")
    print(f"MCP WinDbg server running on http://{host}:{port}")
    print(f"  MCP endpoint: http://{host}:{port}/mcp")

    config = uvicorn.Config(app, host=host, port=port, log_level="info" if verbose else "warning")
    server_instance = uvicorn.Server(config)
    await server_instance.serve()


def _create_server(
    cdb_path: Optional[str] = None,
    symbols_path: Optional[str] = None,
    timeout: int = 30,
    verbose: bool = False,
    source_roots: Optional[List[str]] = None,
) -> Server:
    """Create and configure the MCP server with all tools and prompts."""
    server = Server("mcp-windbg")

    # Create session manager
    sm = SessionManager(
        cdb_path=cdb_path,
        symbols_path=symbols_path,
        timeout=timeout,
        verbose=verbose,
    )

    # Collect tools from all modules
    # source_roots is passed to each module for Phase 2 (source code integration)
    all_tools = []
    all_handlers = {}

    tool_modules = [legacy, dump_summary, stack_frames, module_status, exception_context,
                    thread_list, frame_locals, read_memory,
                    cpp_exception, lock_status, cpp_object, heap_block,
                    thread_cpu, handles]
    for mod in tool_modules:
        tools, handlers = mod.register(sm, source_roots)
        all_tools.extend(tools)
        all_handlers.update(handlers)

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return all_tools

    @server.call_tool()
    async def call_tool(name, arguments: dict) -> list[TextContent]:
        if name in all_handlers:
            return all_handlers[name](arguments)
        raise McpError(ErrorData(
            code=INVALID_PARAMS,
            message=f"Unknown tool: {name}"
        ))

    # Prompt registration
    DUMP_TRIAGE_PROMPT_NAME = "dump-triage"
    DUMP_TRIAGE_PROMPT_TITLE = "Crash Dump Triage Analysis"
    DUMP_TRIAGE_PROMPT_DESCRIPTION = (
        "Comprehensive single crash dump analysis with detailed metadata extraction and structured reporting"
    )

    @server.list_prompts()
    async def list_prompts() -> list[Prompt]:
        return [
            Prompt(
                name=DUMP_TRIAGE_PROMPT_NAME,
                title=DUMP_TRIAGE_PROMPT_TITLE,
                description=DUMP_TRIAGE_PROMPT_DESCRIPTION,
                arguments=[
                    PromptArgument(
                        name="dump_path",
                        description="Path to the Windows crash dump file to analyze (optional - will prompt if not provided)",
                        required=False,
                    ),
                ],
            ),
        ]

    @server.get_prompt()
    async def get_prompt(name: str, arguments: dict | None) -> GetPromptResult:
        if arguments is None:
            arguments = {}

        if name == DUMP_TRIAGE_PROMPT_NAME:
            dump_path = arguments.get("dump_path", "")
            try:
                prompt_content = load_prompt("dump-triage")
            except FileNotFoundError as e:
                raise McpError(ErrorData(
                    code=INTERNAL_ERROR,
                    message=f"Prompt file not found: {e}"
                ))

            if dump_path:
                prompt_text = f"**Dump file to analyze:** {dump_path}\n\n{prompt_content}"
            else:
                prompt_text = prompt_content

            return GetPromptResult(
                description=DUMP_TRIAGE_PROMPT_DESCRIPTION,
                messages=[
                    PromptMessage(
                        role="user",
                        content=TextContent(
                            type="text",
                            text=prompt_text
                        ),
                    ),
                ],
            )

        else:
            raise McpError(ErrorData(
                code=INVALID_PARAMS,
                message=f"Unknown prompt: {name}"
            ))

    return server


# Clean up on module exit
import atexit

def _cleanup():
    """Close all active CDB sessions on exit."""
    # Note: SessionManager cleanup is done per-instance.
    # This is a safety net for the module-level case.
    pass

atexit.register(_cleanup)
