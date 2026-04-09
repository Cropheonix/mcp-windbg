"""analyze_dump_summary tool — comprehensive dump summary in one call."""

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
from mcp_windbg.models.session_models import AnalyzeDumpSummaryParams
from mcp_windbg.models.response_models import TieredResponse, tiered_to_text_content

logger = logging.getLogger(__name__)


def register(
    sm: SessionManager,
    source_roots: Optional[List[str]] = None,
) -> Tuple[List[Tool], Dict[str, object]]:
    """Register the analyze_dump_summary tool."""
    tools = [
        Tool(
            name="analyze_dump_summary",
            description=(
                "Perform comprehensive crash dump analysis in a single call. "
                "Runs a fixed sequence of WinDbg commands (!analyze -v, .ecxr, r, lm, kv) "
                "and returns structured results with exception code, faulting module/symbol, "
                "bucket hint, and module status. This is the recommended entry point for "
                "crash dump analysis."
            ),
            inputSchema=AnalyzeDumpSummaryParams.model_json_schema(),
        ),
    ]

    def handle(arguments: dict) -> list[TextContent]:
        try:
            args = AnalyzeDumpSummaryParams(**arguments)
            runner = sm.get_runner(dump_path=args.dump_path)
            adapter = WinDbgAdapter(runner)

            # Set up symbols if additional paths provided
            if args.symbol_paths:
                for sp in args.symbol_paths:
                    adapter.append_symbol_path(sp)

            # Run analysis sequence (uses caching internally)
            analysis = adapter.get_analysis()
            exception_ctx = adapter.get_exception_context()
            modules = adapter.get_modules()
            stack = adapter.get_stack("kv")

            # Build summary text
            exc_type = analysis.exception_type or "Unknown"
            exc_code = analysis.exception_code or "N/A"
            faulting_mod = analysis.faulting_module or "Unknown"
            faulting_sym = analysis.probably_caused_by or "Unknown"
            bucket = analysis.bucket_hint or "N/A"

            summary = (
                f"Crash: {exc_type} ({exc_code}) in {faulting_mod}. "
                f"Faulting symbol: {faulting_sym}. "
                f"Bucket: {bucket}. "
                f"Modules loaded: {modules.total_count}."
            )

            # Count user code frames
            user_frames = [f for f in stack.frames if f.is_user_code]
            framework_frames = [f for f in stack.frames if f.is_framework]
            system_frames = [f for f in stack.frames if f.is_system]

            structured_data = {
                "exception_code": analysis.exception_code,
                "exception_type": analysis.exception_type,
                "exception_address": analysis.exception_address,
                "faulting_module": analysis.faulting_module,
                "faulting_module_base": analysis.faulting_module_base,
                "faulting_symbol": analysis.probably_caused_by,
                "bucket_id": analysis.bucket_id,
                "bucket_id_func": analysis.bucket_id_func,
                "bucket_hint": analysis.bucket_hint,
                "exception_flags": exception_ctx.exception_flags,
                "exception_parameters": exception_ctx.parameters,
                "registers": exception_ctx.registers,
                "stack_summary": {
                    "total_frames": stack.total_frames,
                    "overflow_warning": stack.overflow_warning,
                    "user_code_frames": len(user_frames),
                    "framework_frames": len(framework_frames),
                    "system_frames": len(system_frames),
                    "top_user_frames": [
                        {
                            "frame": f.frame_number,
                            "module": f.module,
                            "function": f.function,
                            "offset": f.offset,
                            "source_file": f.source_file,
                            "source_line": f.source_line,
                        }
                        for f in user_frames[:5]
                    ],
                },
                "modules_summary": {
                    "total_count": modules.total_count,
                    "symbol_warnings": modules.symbol_warnings,
                },
            }

            response = TieredResponse(
                summary=summary,
                structured=structured_data,
                raw_excerpt=stack.raw_text[:3000] if stack.raw_text else None,
                raw_full=(
                    f"=== !analyze -v ===\n{analysis.raw_text or ''}\n\n"
                    f"=== .ecxr ===\n{exception_ctx.raw_text or ''}\n\n"
                    f"=== lm ===\n{modules.raw_text or ''}\n\n"
                    f"=== kv ===\n{stack.raw_text or ''}"
                ),
            )

            return [tiered_to_text_content(response, args.detail_level)]

        except McpError:
            raise
        except Exception as e:
            raise McpError(ErrorData(
                code=INTERNAL_ERROR,
                message=f"Error executing analyze_dump_summary: {str(e)}\n{traceback.format_exc()}"
            ))

    return tools, {"analyze_dump_summary": handle}
