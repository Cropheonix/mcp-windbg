"""list_threads tool — list all threads with optional stacks."""

import traceback
import logging
from typing import Dict, List, Optional, Tuple

from mcp.shared.exceptions import McpError
from mcp.types import (
    ErrorData,
    TextContent,
    Tool,
    INTERNAL_ERROR,
)

from mcp_windbg.session.manager import SessionManager
from mcp_windbg.adapters.windbg_adapter import WinDbgAdapter
from mcp_windbg.models.session_models import ListThreadsParams
from mcp_windbg.models.response_models import TieredResponse, tiered_to_text_content

logger = logging.getLogger(__name__)


def register(
    sm: SessionManager,
    source_roots: Optional[List[str]] = None,
) -> Tuple[List[Tool], Dict[str, object]]:
    """Register the list_threads tool."""
    tools = [
        Tool(
            name="list_threads",
            description=(
                "List all threads in the debug session with their IDs, suspend counts, "
                "and current thread marker. Optionally include a brief stack trace for "
                "each thread. Use this to identify threads of interest before drilling "
                "down with get_stack_frames."
            ),
            inputSchema=ListThreadsParams.model_json_schema(),
        ),
    ]

    def handle(arguments: dict) -> list[TextContent]:
        try:
            args = ListThreadsParams(**arguments)
            runner = sm.get_runner(
                dump_path=args.dump_path,
                connection_string=args.connection_string,
            )
            adapter = WinDbgAdapter(runner)
            threads = adapter.get_threads()

            # Build summary
            summary = (
                f"{threads.total_count} threads. "
                f"Current thread: {threads.current_thread}."
            )

            structured_data = {
                "total_count": threads.total_count,
                "current_thread": threads.current_thread,
                "threads": [
                    {
                        "thread_number": t.thread_number,
                        "os_id": t.os_id,
                        "suspend_count": t.suspend_count,
                        "is_current": t.is_current,
                    }
                    for t in threads.threads
                ],
            }

            raw_excerpt = threads.raw_text[:3000] if threads.raw_text else None
            raw_full = threads.raw_text

            # Optionally include all thread stacks
            if args.include_stacks:
                all_stacks = adapter.get_thread_stacks("k")
                structured_data["all_stacks_raw"] = all_stacks[:8000]
                if not raw_full:
                    raw_full = all_stacks
                else:
                    raw_full = raw_full + "\n\n=== All Thread Stacks ===\n" + all_stacks

            response = TieredResponse(
                summary=summary,
                structured=structured_data,
                raw_excerpt=raw_excerpt,
                raw_full=raw_full,
            )

            return [tiered_to_text_content(response, args.detail_level)]

        except McpError:
            raise
        except Exception as e:
            raise McpError(ErrorData(
                code=INTERNAL_ERROR,
                message=f"Error executing list_threads: {str(e)}\n{traceback.format_exc()}"
            ))

    return tools, {"list_threads": handle}
