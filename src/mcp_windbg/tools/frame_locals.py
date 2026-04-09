"""get_frame_locals tool — inspect local variables in a stack frame."""

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
from mcp_windbg.models.session_models import GetFrameLocalsParams
from mcp_windbg.models.response_models import TieredResponse, tiered_to_text_content

logger = logging.getLogger(__name__)


def register(
    sm: SessionManager,
    source_roots: Optional[List[str]] = None,
) -> Tuple[List[Tool], Dict[str, object]]:
    """Register the get_frame_locals tool."""
    tools = [
        Tool(
            name="get_frame_locals",
            description=(
                "Switch to a specific stack frame and display its local variables "
                "and function parameters. Requires symbols (PDB) to be loaded for "
                "the module containing that frame. Use get_stack_frames first to "
                "identify frame numbers, then use this tool to inspect variables."
            ),
            inputSchema=GetFrameLocalsParams.model_json_schema(),
        ),
    ]

    def handle(arguments: dict) -> list[TextContent]:
        try:
            args = GetFrameLocalsParams(**arguments)
            runner = sm.get_runner(
                dump_path=args.dump_path,
                connection_string=args.connection_string,
            )
            adapter = WinDbgAdapter(runner)
            result = adapter.get_frame_locals(args.frame_number)

            # Build summary
            var_count = len(result.locals)
            param_count = sum(1 for v in result.locals if v.is_param)
            func_name = result.frame_function or f"frame #{args.frame_number}"

            summary = (
                f"Frame {args.frame_number} ({func_name}): "
                f"{var_count} variables ({param_count} parameters)."
            )

            structured_data = {
                "frame_number": result.frame_number,
                "frame_function": result.frame_function,
                "variable_count": var_count,
                "parameter_count": param_count,
                "variables": [
                    {
                        "name": v.name,
                        "type": v.type_name,
                        "address": v.address,
                        "value": v.value,
                        "is_param": v.is_param,
                    }
                    for v in result.locals
                ],
            }

            response = TieredResponse(
                summary=summary,
                structured=structured_data,
                raw_excerpt=result.raw_text[:3000] if result.raw_text else None,
                raw_full=result.raw_text,
            )

            return [tiered_to_text_content(response, args.detail_level)]

        except McpError:
            raise
        except Exception as e:
            raise McpError(ErrorData(
                code=INTERNAL_ERROR,
                message=f"Error executing get_frame_locals: {str(e)}\n{traceback.format_exc()}"
            ))

    return tools, {"get_frame_locals": handle}
