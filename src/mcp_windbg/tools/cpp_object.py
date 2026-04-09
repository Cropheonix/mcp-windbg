"""inspect_cpp_object tool — display C++ object structure via dt."""

import traceback
import logging
from typing import Dict, List, Optional, Tuple

from mcp.shared.exceptions import McpError
from mcp.types import ErrorData, TextContent, Tool, INTERNAL_ERROR

from mcp_windbg.session.manager import SessionManager
from mcp_windbg.adapters.windbg_adapter import WinDbgAdapter
from mcp_windbg.models.session_models import InspectCppObjectParams
from mcp_windbg.models.response_models import TieredResponse, tiered_to_text_content

logger = logging.getLogger(__name__)


def register(
    sm: SessionManager,
    source_roots: Optional[List[str]] = None,
) -> Tuple[List[Tool], Dict[str, object]]:
    tools = [
        Tool(
            name="inspect_cpp_object",
            description=(
                "Display C++ object structure and member values using the dt (display type) command. "
                "Requires symbols (PDB) for the module. Pass a type name and address to inspect "
                "a specific object, or just an address for auto-detection. "
                "Use this to examine 'this' pointer values, vtable pointers, and member variables "
                "at crash time."
            ),
            inputSchema=InspectCppObjectParams.model_json_schema(),
        ),
    ]

    def handle(arguments: dict) -> list[TextContent]:
        try:
            args = InspectCppObjectParams(**arguments)
            runner = sm.get_runner(
                dump_path=args.dump_path,
                connection_string=args.connection_string,
            )
            adapter = WinDbgAdapter(runner)
            raw = adapter.inspect_cpp_object(args.type_name, args.address, args.depth)
            raw_text = "\n".join(raw)

            # Parse dt output for structured data
            members = []
            for line in raw:
                stripped = line.strip()
                if not stripped or stripped.startswith("0:"):
                    continue
                if "+0x" not in stripped or ":" not in stripped:
                    continue
                # dt output: "   +0x000 member_name : value" or "   +0x000 member_name : type value"
                if "+0x" in stripped:
                    parts = stripped.split(":", 1)
                    if len(parts) == 2:
                        member_desc = parts[0].strip()
                        member_val = parts[1].strip()
                        members.append({
                            "field": member_desc,
                            "value": member_val,
                        })

            type_info = args.type_name or "auto-detect"
            summary = f"Object at {args.address} (type: {type_info}): {len(members)} fields found."

            structured_data = {
                "address": args.address,
                "type_name": type_info,
                "depth": args.depth,
                "field_count": len(members),
                "fields": members,
            }

            response = TieredResponse(
                summary=summary,
                structured=structured_data,
                raw_excerpt=raw_text[:3000],
                raw_full=raw_text,
            )

            return [tiered_to_text_content(response, args.detail_level)]

        except McpError:
            raise
        except Exception as e:
            raise McpError(ErrorData(
                code=INTERNAL_ERROR,
                message=f"Error executing inspect_cpp_object: {str(e)}\n{traceback.format_exc()}"
            ))

    return tools, {"inspect_cpp_object": handle}
