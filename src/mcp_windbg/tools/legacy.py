"""Legacy MCP tools — existing 7 tools refactored to use parsers internally."""

import os
import glob
import traceback
import logging
from typing import Dict, List, Optional, Tuple

from mcp.server import Server
from mcp.shared.exceptions import McpError
from mcp.types import (
    ErrorData,
    TextContent,
    Tool,
    INVALID_PARAMS,
    INTERNAL_ERROR,
)

from mcp_windbg.session.manager import SessionManager, get_local_dumps_path
from mcp_windbg.adapters.windbg_adapter import WinDbgAdapter
from mcp_windbg.models.session_models import (
    OpenWindbgDump,
    OpenWindbgRemote,
    RunWindbgCmdParams,
    CloseWindbgDumpParams,
    CloseWindbgRemoteParams,
    ListWindbgDumpsParams,
    SendCtrlBreakParams,
)

logger = logging.getLogger(__name__)


def register(
    sm: SessionManager,
    source_roots: Optional[List[str]] = None,
) -> Tuple[List[Tool], Dict[str, object]]:
    """Register legacy tools with the MCP server.

    Args:
        sm: SessionManager instance.
        source_roots: Source code root directories (unused by legacy tools).

    Returns:
        Tuple of (tool definitions, handler functions).
    """
    tools = [
        Tool(
            name="open_windbg_dump",
            description=(
                "Analyze a Windows crash dump file using WinDbg/CDB. "
                "This tool executes common WinDbg commands to analyze the crash dump and returns the results."
            ),
            inputSchema=OpenWindbgDump.model_json_schema(),
        ),
        Tool(
            name="open_windbg_remote",
            description=(
                "Connect to a remote debugging session using WinDbg/CDB. "
                "This tool establishes a remote debugging connection and allows you to analyze the target process."
            ),
            inputSchema=OpenWindbgRemote.model_json_schema(),
        ),
        Tool(
            name="run_windbg_cmd",
            description=(
                "Execute a specific WinDbg command on a loaded crash dump or remote session. "
                "This tool allows you to run any WinDbg command and get the output."
            ),
            inputSchema=RunWindbgCmdParams.model_json_schema(),
        ),
        Tool(
            name="send_ctrl_break",
            description=(
                "Send a CTRL+BREAK event to the active CDB/WinDbg session, causing it to break in. "
                "Useful for interrupting a running target or breaking into a remote session."
            ),
            inputSchema=SendCtrlBreakParams.model_json_schema(),
        ),
        Tool(
            name="close_windbg_dump",
            description=(
                "Unload a crash dump and release resources. "
                "Use this tool when you're done analyzing a crash dump to free up resources."
            ),
            inputSchema=CloseWindbgDumpParams.model_json_schema(),
        ),
        Tool(
            name="close_windbg_remote",
            description=(
                "Close a remote debugging connection and release resources. "
                "Use this tool when you're done with a remote debugging session to free up resources."
            ),
            inputSchema=CloseWindbgRemoteParams.model_json_schema(),
        ),
        Tool(
            name="list_windbg_dumps",
            description=(
                "List Windows crash dump files in the specified directory. "
                "This tool helps you discover available crash dumps that can be analyzed."
            ),
            inputSchema=ListWindbgDumpsParams.model_json_schema(),
        ),
    ]

    def handle_open_windbg_dump(arguments: dict) -> list[TextContent]:
        try:
            # Check if dump_path is missing or empty
            if "dump_path" not in arguments or not arguments.get("dump_path"):
                local_dumps_path = get_local_dumps_path()
                dumps_found_text = ""

                if local_dumps_path:
                    search_pattern = os.path.join(local_dumps_path, "*.*dmp")
                    dump_files = glob.glob(search_pattern)

                    if dump_files:
                        dumps_found_text = f"\n\nI found {len(dump_files)} crash dump(s) in {local_dumps_path}:\n\n"
                        for i, dump_file in enumerate(dump_files[:10]):
                            try:
                                size_mb = round(os.path.getsize(dump_file) / (1024 * 1024), 2)
                            except (OSError, IOError):
                                size_mb = "unknown"
                            dumps_found_text += f"{i+1}. {dump_file} ({size_mb} MB)\n"

                        if len(dump_files) > 10:
                            dumps_found_text += f"\n... and {len(dump_files) - 10} more dump files.\n"
                        dumps_found_text += "\nYou can analyze one of these dumps by specifying its path."

                return [TextContent(
                    type="text",
                    text=f"Please provide a path to a crash dump file to analyze.{dumps_found_text}\n\n"
                         f"You can use the 'list_windbg_dumps' tool to discover available crash dumps."
                )]

            args = OpenWindbgDump(**arguments)
            runner = sm.get_runner(dump_path=args.dump_path)
            adapter = WinDbgAdapter(runner)

            results = []

            # Crash info — use adapter internally
            crash_info = adapter.run_raw(".lastevent")
            results.append("### Crash Information\n```\n" + "\n".join(crash_info) + "\n```\n\n")

            # Analysis — use adapter with parser
            analysis = adapter.run_raw("!analyze -v")
            results.append("### Crash Analysis\n```\n" + "\n".join(analysis) + "\n```\n\n")

            if args.include_stack_trace:
                stack = adapter.run_raw("kb")
                results.append("### Stack Trace\n```\n" + "\n".join(stack) + "\n```\n\n")

            if args.include_modules:
                modules = adapter.run_raw("lm")
                results.append("### Loaded Modules\n```\n" + "\n".join(modules) + "\n```\n\n")

            if args.include_threads:
                threads = adapter.run_raw("~")
                results.append("### Threads\n```\n" + "\n".join(threads) + "\n```\n\n")

            return [TextContent(type="text", text="".join(results))]

        except McpError:
            raise
        except Exception as e:
            raise McpError(ErrorData(
                code=INTERNAL_ERROR,
                message=f"Error executing open_windbg_dump: {str(e)}\n{traceback.format_exc()}"
            ))

    def handle_open_windbg_remote(arguments: dict) -> list[TextContent]:
        try:
            args = OpenWindbgRemote(**arguments)
            runner = sm.get_runner(connection_string=args.connection_string)
            adapter = WinDbgAdapter(runner)

            results = []

            target_info = adapter.run_raw("!peb")
            results.append("### Target Process Information\n```\n" + "\n".join(target_info) + "\n```\n\n")

            current_state = adapter.run_raw("r")
            results.append("### Current Registers\n```\n" + "\n".join(current_state) + "\n```\n\n")

            if args.include_stack_trace:
                stack = adapter.run_raw("kb")
                results.append("### Stack Trace\n```\n" + "\n".join(stack) + "\n```\n\n")

            if args.include_modules:
                modules = adapter.run_raw("lm")
                results.append("### Loaded Modules\n```\n" + "\n".join(modules) + "\n```\n\n")

            if args.include_threads:
                threads = adapter.run_raw("~")
                results.append("### Threads\n```\n" + "\n".join(threads) + "\n```\n\n")

            return [TextContent(type="text", text="".join(results))]

        except McpError:
            raise
        except Exception as e:
            raise McpError(ErrorData(
                code=INTERNAL_ERROR,
                message=f"Error executing open_windbg_remote: {str(e)}\n{traceback.format_exc()}"
            ))

    def handle_run_windbg_cmd(arguments: dict) -> list[TextContent]:
        try:
            args = RunWindbgCmdParams(**arguments)
            runner = sm.get_runner(
                dump_path=args.dump_path,
                connection_string=args.connection_string,
            )
            adapter = WinDbgAdapter(runner)
            output = adapter.run_raw(args.command)

            return [TextContent(
                type="text",
                text=f"Command: {args.command}\n\nOutput:\n```\n" + "\n".join(output) + "```"
            )]

        except McpError:
            raise
        except Exception as e:
            raise McpError(ErrorData(
                code=INTERNAL_ERROR,
                message=f"Error executing run_windbg_cmd: {str(e)}\n{traceback.format_exc()}"
            ))

    def handle_send_ctrl_break(arguments: dict) -> list[TextContent]:
        try:
            args = SendCtrlBreakParams(**arguments)
            runner = sm.get_runner(
                dump_path=args.dump_path,
                connection_string=args.connection_string,
            )
            runner.session.send_ctrl_break()
            target = args.dump_path if args.dump_path else f"remote: {args.connection_string}"
            return [TextContent(
                type="text",
                text=f"Sent CTRL+BREAK to CDB session ({target})."
            )]

        except McpError:
            raise
        except Exception as e:
            raise McpError(ErrorData(
                code=INTERNAL_ERROR,
                message=f"Error executing send_ctrl_break: {str(e)}\n{traceback.format_exc()}"
            ))

    def handle_close_windbg_dump(arguments: dict) -> list[TextContent]:
        try:
            args = CloseWindbgDumpParams(**arguments)
            success = sm.unload(dump_path=args.dump_path)
            if success:
                return [TextContent(
                    type="text",
                    text=f"Successfully unloaded crash dump: {args.dump_path}"
                )]
            else:
                return [TextContent(
                    type="text",
                    text=f"No active session found for crash dump: {args.dump_path}"
                )]
        except McpError:
            raise
        except Exception as e:
            raise McpError(ErrorData(
                code=INTERNAL_ERROR,
                message=f"Error executing close_windbg_dump: {str(e)}\n{traceback.format_exc()}"
            ))

    def handle_close_windbg_remote(arguments: dict) -> list[TextContent]:
        try:
            args = CloseWindbgRemoteParams(**arguments)
            success = sm.unload(connection_string=args.connection_string)
            if success:
                return [TextContent(
                    type="text",
                    text=f"Successfully closed remote connection: {args.connection_string}"
                )]
            else:
                return [TextContent(
                    type="text",
                    text=f"No active session found for remote connection: {args.connection_string}"
                )]
        except McpError:
            raise
        except Exception as e:
            raise McpError(ErrorData(
                code=INTERNAL_ERROR,
                message=f"Error executing close_windbg_remote: {str(e)}\n{traceback.format_exc()}"
            ))

    def handle_list_windbg_dumps(arguments: dict) -> list[TextContent]:
        try:
            args = ListWindbgDumpsParams(**arguments)

            if args.directory_path is None:
                args.directory_path = get_local_dumps_path()
                if args.directory_path is None:
                    raise McpError(ErrorData(
                        code=INVALID_PARAMS,
                        message="No directory path specified and no default dump path found in registry."
                    ))

            if not os.path.exists(args.directory_path) or not os.path.isdir(args.directory_path):
                raise McpError(ErrorData(
                    code=INVALID_PARAMS,
                    message=f"Directory not found: {args.directory_path}"
                ))

            search_pattern = (
                os.path.join(args.directory_path, "**", "*.*dmp")
                if args.recursive
                else os.path.join(args.directory_path, "*.*dmp")
            )
            dump_files = glob.glob(search_pattern, recursive=args.recursive)
            dump_files.sort()

            if not dump_files:
                return [TextContent(
                    type="text",
                    text=f"No crash dump files (*.*dmp) found in {args.directory_path}"
                )]

            result_text = f"Found {len(dump_files)} crash dump file(s) in {args.directory_path}:\n\n"
            for i, dump_file in enumerate(dump_files):
                try:
                    size_mb = round(os.path.getsize(dump_file) / (1024 * 1024), 2)
                except (OSError, IOError):
                    size_mb = "unknown"
                result_text += f"{i+1}. {dump_file} ({size_mb} MB)\n"

            return [TextContent(type="text", text=result_text)]

        except McpError:
            raise
        except Exception as e:
            raise McpError(ErrorData(
                code=INTERNAL_ERROR,
                message=f"Error executing list_windbg_dumps: {str(e)}\n{traceback.format_exc()}"
            ))

    handlers = {
        "open_windbg_dump": handle_open_windbg_dump,
        "open_windbg_remote": handle_open_windbg_remote,
        "run_windbg_cmd": handle_run_windbg_cmd,
        "send_ctrl_break": handle_send_ctrl_break,
        "close_windbg_dump": handle_close_windbg_dump,
        "close_windbg_remote": handle_close_windbg_remote,
        "list_windbg_dumps": handle_list_windbg_dumps,
    }

    return tools, handlers
