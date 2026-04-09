"""get_stack_frames tool — parsed stack frames with labeling."""

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
from mcp_windbg.models.session_models import GetStackFramesParams
from mcp_windbg.models.response_models import TieredResponse, tiered_to_text_content

logger = logging.getLogger(__name__)


def register(
    sm: SessionManager,
    source_roots: Optional[List[str]] = None,
) -> Tuple[List[Tool], Dict[str, object]]:
    """Register the get_stack_frames tool."""
    tools = [
        Tool(
            name="get_stack_frames",
            description=(
                "Get parsed stack frames for the current or specified thread, "
                "with automatic frame labeling (user code / framework / system). "
                "Useful for identifying which frames belong to your application vs. "
                "Qt framework vs. Windows system code."
            ),
            inputSchema=GetStackFramesParams.model_json_schema(),
        ),
    ]

    def handle(arguments: dict) -> list[TextContent]:
        try:
            args = GetStackFramesParams(**arguments)
            runner = sm.get_runner(
                dump_path=args.dump_path,
                connection_string=args.connection_string,
            )
            adapter = WinDbgAdapter(runner)

            # Switch thread if specified
            if args.thread_id is not None:
                adapter.switch_thread(args.thread_id)

            # Get stack
            stack = adapter.get_stack(args.stack_command)

            # Build summary
            user_frames = [f for f in stack.frames if f.is_user_code]
            framework_frames = [f for f in stack.frames if f.is_framework]
            system_frames = [f for f in stack.frames if f.is_system]

            if args.thread_id is not None:
                summary = f"Thread {args.thread_id}: {stack.total_frames} frames ({len(user_frames)} user, {len(framework_frames)} framework, {len(system_frames)} system)"
            else:
                summary = f"Current thread: {stack.total_frames} frames ({len(user_frames)} user, {len(framework_frames)} framework, {len(system_frames)} system)"

            if stack.overflow_warning:
                summary += f" WARNING: {stack.overflow_warning}"

            structured_data = {
                "thread_id": args.thread_id,
                "command_used": stack.command_used,
                "total_frames": stack.total_frames,
                "overflow_warning": stack.overflow_warning,
                "user_code_count": len(user_frames),
                "framework_count": len(framework_frames),
                "system_count": len(system_frames),
                "frames": [
                    {
                        "frame": f.frame_number,
                        "module": f.module,
                        "function": f.function,
                        "offset": f.offset,
                        "return_address": f.return_address,
                        "frame_label": f.frame_label,
                        "source_file": f.source_file,
                        "source_line": f.source_line,
                    }
                    for f in stack.frames
                ],
            }

            response = TieredResponse(
                summary=summary,
                structured=structured_data,
                raw_excerpt=stack.raw_text[:3000] if stack.raw_text else None,
                raw_full=stack.raw_text,
            )

            return [tiered_to_text_content(response, args.detail_level)]

        except McpError:
            raise
        except Exception as e:
            raise McpError(ErrorData(
                code=INTERNAL_ERROR,
                message=f"Error executing get_stack_frames: {str(e)}\n{traceback.format_exc()}"
            ))

    return tools, {"get_stack_frames": handle}
