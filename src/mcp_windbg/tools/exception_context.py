"""get_exception_context tool — structured exception information."""

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
from mcp_windbg.models.session_models import GetExceptionContextParams
from mcp_windbg.models.response_models import TieredResponse, tiered_to_text_content

logger = logging.getLogger(__name__)


def register(
    sm: SessionManager,
    source_roots: Optional[List[str]] = None,
) -> Tuple[List[Tool], Dict[str, object]]:
    """Register the get_exception_context tool."""
    tools = [
        Tool(
            name="get_exception_context",
            description=(
                "Get structured exception context information including exception code, "
                "type, address, parameters, and register values. Translates numeric "
                "exception codes to human-readable names (e.g., 0xC0000005 -> Access Violation)."
            ),
            inputSchema=GetExceptionContextParams.model_json_schema(),
        ),
    ]

    def handle(arguments: dict) -> list[TextContent]:
        try:
            args = GetExceptionContextParams(**arguments)
            runner = sm.get_runner(
                dump_path=args.dump_path,
                connection_string=args.connection_string,
            )
            adapter = WinDbgAdapter(runner)
            ctx = adapter.get_exception_context()

            # Build summary
            exc_type = ctx.exception_type or "Unknown"
            exc_code = ctx.exception_code or "N/A"
            exc_addr = ctx.exception_address or "N/A"

            summary = f"Exception: {exc_type} ({exc_code}) at address {exc_addr}"
            if ctx.last_event:
                summary += f". Last event: {ctx.last_event}"

            structured_data = {
                "exception_code": ctx.exception_code,
                "exception_type": ctx.exception_type,
                "exception_address": ctx.exception_address,
                "exception_flags": ctx.exception_flags,
                "exception_parameters": ctx.parameters,
                "registers": ctx.registers,
                "last_event": ctx.last_event,
            }

            response = TieredResponse(
                summary=summary,
                structured=structured_data,
                raw_excerpt=ctx.raw_text[:3000] if ctx.raw_text else None,
                raw_full=ctx.raw_text,
            )

            return [tiered_to_text_content(response, args.detail_level)]

        except McpError:
            raise
        except Exception as e:
            raise McpError(ErrorData(
                code=INTERNAL_ERROR,
                message=f"Error executing get_exception_context: {str(e)}\n{traceback.format_exc()}"
            ))

    return tools, {"get_exception_context": handle}
