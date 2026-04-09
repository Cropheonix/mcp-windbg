"""get_modules_status tool — parsed module list with symbol warnings."""

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
from mcp_windbg.models.session_models import GetModulesStatusParams
from mcp_windbg.models.response_models import TieredResponse, tiered_to_text_content

logger = logging.getLogger(__name__)


def register(
    sm: SessionManager,
    source_roots: Optional[List[str]] = None,
) -> Tuple[List[Tool], Dict[str, object]]:
    """Register the get_modules_status tool."""
    tools = [
        Tool(
            name="get_modules_status",
            description=(
                "Get the list of loaded modules with symbol status. "
                "Reports which modules have PDB symbols loaded and generates "
                "warnings for user modules missing symbols. This is critical for "
                "verifying that crash analysis will be reliable."
            ),
            inputSchema=GetModulesStatusParams.model_json_schema(),
        ),
    ]

    def handle(arguments: dict) -> list[TextContent]:
        try:
            args = GetModulesStatusParams(**arguments)
            runner = sm.get_runner(
                dump_path=args.dump_path,
                connection_string=args.connection_string,
            )
            adapter = WinDbgAdapter(runner)
            modules = adapter.get_modules()

            # Build summary
            user_modules = [m for m in modules.modules if m.is_user_module]
            symbol_ok = [m for m in user_modules if m.has_symbols]
            symbol_missing = [m for m in user_modules if not m.has_symbols]

            summary = (
                f"{modules.total_count} modules loaded. "
                f"User modules: {len(user_modules)} "
                f"({len(symbol_ok)} with symbols, {len(symbol_missing)} without)."
            )

            if modules.symbol_warnings:
                summary += f" {len(modules.symbol_warnings)} warning(s)."

            structured_data = {
                "total_count": modules.total_count,
                "user_module_count": len(user_modules),
                "modules_with_symbols": len(symbol_ok),
                "modules_without_symbols": len(symbol_missing),
                "symbol_warnings": modules.symbol_warnings,
                "modules": [
                    {
                        "name": m.name,
                        "base_address": m.base_address,
                        "end_address": m.end_address,
                        "has_symbols": m.has_symbols,
                        "symbol_type": m.symbol_type,
                        "is_user_module": m.is_user_module,
                    }
                    for m in modules.modules
                ],
            }

            response = TieredResponse(
                summary=summary,
                structured=structured_data,
                raw_excerpt=modules.raw_text[:3000] if modules.raw_text else None,
                raw_full=modules.raw_text,
            )

            return [tiered_to_text_content(response, args.detail_level)]

        except McpError:
            raise
        except Exception as e:
            raise McpError(ErrorData(
                code=INTERNAL_ERROR,
                message=f"Error executing get_modules_status: {str(e)}\n{traceback.format_exc()}"
            ))

    return tools, {"get_modules_status": handle}
