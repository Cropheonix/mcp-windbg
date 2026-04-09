"""read_memory tool — read memory at a given address."""

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
from mcp_windbg.models.session_models import ReadMemoryParams
from mcp_windbg.models.response_models import TieredResponse, tiered_to_text_content

logger = logging.getLogger(__name__)


def register(
    sm: SessionManager,
    source_roots: Optional[List[str]] = None,
) -> Tuple[List[Tool], Dict[str, object]]:
    """Register the read_memory tool."""
    tools = [
        Tool(
            name="read_memory",
            description=(
                "Read memory content at a specified address. Supports multiple formats: "
                "hex bytes (db), DWORD (dd), QWORD (dq), Unicode string (du), ASCII string (da). "
                "Use this to inspect pointer values, string contents, object fields, or verify "
                "null/wild pointers found in crash analysis."
            ),
            inputSchema=ReadMemoryParams.model_json_schema(),
        ),
    ]

    def handle(arguments: dict) -> list[TextContent]:
        try:
            args = ReadMemoryParams(**arguments)
            runner = sm.get_runner(
                dump_path=args.dump_path,
                connection_string=args.connection_string,
            )
            adapter = WinDbgAdapter(runner)
            result = adapter.read_memory(
                address=args.address,
                length=args.length,
                format=args.format,
            )

            # Build summary
            line_count = len(result.lines)
            summary = (
                f"Memory at {args.address} ({args.format}, {args.length} bytes): "
                f"{line_count} lines read."
            )

            structured_data = {
                "address": args.address,
                "length": args.length,
                "format": args.format,
                "lines": [
                    {
                        "address": ml.address,
                        "hex_data": ml.hex_data,
                        "ascii": ml.ascii_data,
                    }
                    for ml in result.lines
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
                message=f"Error executing read_memory: {str(e)}\n{traceback.format_exc()}"
            ))

    return tools, {"read_memory": handle}
