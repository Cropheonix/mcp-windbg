"""get_cpp_exception tool — inspect C++ exception details via .exr -1."""

import traceback
import logging
from typing import Dict, List, Optional, Tuple

from mcp.shared.exceptions import McpError
from mcp.types import ErrorData, TextContent, Tool, INTERNAL_ERROR

from mcp_windbg.session.manager import SessionManager
from mcp_windbg.adapters.windbg_adapter import WinDbgAdapter
from mcp_windbg.models.session_models import GetCppExceptionParams
from mcp_windbg.models.dump_models import EXCEPTION_CODE_MAP
from mcp_windbg.models.response_models import TieredResponse, tiered_to_text_content

logger = logging.getLogger(__name__)


def register(
    sm: SessionManager,
    source_roots: Optional[List[str]] = None,
) -> Tuple[List[Tool], Dict[str, object]]:
    tools = [
        Tool(
            name="get_cpp_exception",
            description=(
                "Get detailed C++ exception information using .exr -1. "
                "Shows the exception record including exception code, address, "
                "and C++ specific parameters (type info, throw info, etc.). "
                "Essential for diagnosing uncaught C++ exceptions (0xE06D7363)."
            ),
            inputSchema=GetCppExceptionParams.model_json_schema(),
        ),
    ]

    def handle(arguments: dict) -> list[TextContent]:
        try:
            args = GetCppExceptionParams(**arguments)
            runner = sm.get_runner(
                dump_path=args.dump_path,
                connection_string=args.connection_string,
            )
            adapter = WinDbgAdapter(runner)
            result = adapter.get_cpp_exception()

            exc_code = result.get("exception_code", "N/A")
            # Normalize hex for MAP lookup: 0xe06d7363 -> 0xE06D7363
            if exc_code != "N/A" and exc_code.startswith(("0x", "0X")):
                exc_key = "0x" + exc_code[2:].upper()
            else:
                exc_key = exc_code.upper() if exc_code != "N/A" else exc_code
            exc_type = EXCEPTION_CODE_MAP.get(exc_key, "Unknown") if exc_code != "N/A" else "N/A"

            summary = f"C++ exception: {exc_type} ({exc_code})"
            if "exception_address" in result:
                summary += f" at {result['exception_address']}"

            response = TieredResponse(
                summary=summary,
                structured=result,
                raw_excerpt=result.get("raw_text", "")[:3000],
                raw_full=result.get("raw_text", ""),
            )

            return [tiered_to_text_content(response, args.detail_level)]

        except McpError:
            raise
        except Exception as e:
            raise McpError(ErrorData(
                code=INTERNAL_ERROR,
                message=f"Error executing get_cpp_exception: {str(e)}\n{traceback.format_exc()}"
            ))

    return tools, {"get_cpp_exception": handle}
