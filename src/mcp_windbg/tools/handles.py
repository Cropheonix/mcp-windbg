"""check_handles tool — handle leak detection via !handle."""

import re
import traceback
import logging
from typing import Dict, List, Optional, Tuple

from mcp.shared.exceptions import McpError
from mcp.types import ErrorData, TextContent, Tool, INTERNAL_ERROR

from mcp_windbg.session.manager import SessionManager
from mcp_windbg.adapters.windbg_adapter import WinDbgAdapter
from mcp_windbg.models.session_models import CheckHandlesParams
from mcp_windbg.models.response_models import TieredResponse, tiered_to_text_content

logger = logging.getLogger(__name__)


def register(
    sm: SessionManager,
    source_roots: Optional[List[str]] = None,
) -> Tuple[List[Tool], Dict[str, object]]:
    tools = [
        Tool(
            name="check_handles",
            description=(
                "Check handle usage using !handle. Without a type filter, shows handle "
                "summary statistics (counts by type). With a type filter (e.g., 'File', "
                "'Event', 'Mutex'), lists handles of that type. Essential for diagnosing "
                "handle leaks — look for abnormally high handle counts (thousands+) or "
                "unexpected handle types in long-running processes."
            ),
            inputSchema=CheckHandlesParams.model_json_schema(),
        ),
    ]

    def handle(arguments: dict) -> list[TextContent]:
        try:
            args = CheckHandlesParams(**arguments)
            runner = sm.get_runner(
                dump_path=args.dump_path,
                connection_string=args.connection_string,
            )
            adapter = WinDbgAdapter(runner)
            raw = adapter.get_handle_info(args.handle_type)
            raw_text = "\n".join(raw)

            if args.handle_type:
                # Detailed handle listing
                handles = []
                for line in raw:
                    stripped = line.strip()
                    # Handle entry: "HANDLE XXXXXXXX: <type>"
                    m = re.match(
                        r"HANDLE\s+([0-9a-fA-F]+)\s*:\s*(\S+)",
                        stripped,
                    )
                    if m:
                        handles.append({
                            "handle": m.group(1),
                            "type": m.group(2),
                        })

                summary = f"Handle scan for type '{args.handle_type}': {len(handles)} handle(s) found."

                structured_data = {
                    "filter_type": args.handle_type,
                    "handle_count": len(handles),
                    "handles": handles[:200],  # Cap at 200 to avoid huge responses
                    "raw_output": raw_text[:8000],
                }
            else:
                # Handle summary
                handle_types = {}
                total_handles = 0
                for line in raw:
                    stripped = line.strip()
                    # Summary line: "NNNN handles of type <Type>"
                    m = re.match(
                        r"(\d+)\s+handles?\s+of\s+type\s+(\S+)",
                        stripped,
                        re.IGNORECASE,
                    )
                    if m:
                        count = int(m.group(1))
                        htype = m.group(2)
                        handle_types[htype] = count
                        total_handles += count

                # Also check for total count line: "NNNN Handles"
                m = re.match(r"(\d+)\s+Handles?", raw[0].strip() if raw else "", re.IGNORECASE)
                if m and not handle_types:
                    total_handles = int(m.group(1))

                # Identify potential leaks (high counts)
                leak_warnings = []
                for htype, count in sorted(handle_types.items(), key=lambda x: -x[1]):
                    if count >= 1000:
                        leak_warnings.append(
                            f"High {htype} count: {count} — potential leak"
                        )

                summary = f"Handle summary: {total_handles} total handles in {len(handle_types)} type(s)."
                if leak_warnings:
                    summary += f" {len(leak_warnings)} warning(s)."

                structured_data = {
                    "total_handles": total_handles,
                    "type_count": len(handle_types),
                    "handle_types": handle_types,
                    "leak_warnings": leak_warnings,
                    "raw_output": raw_text[:8000],
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
                message=f"Error executing check_handles: {str(e)}\n{traceback.format_exc()}"
            ))

    return tools, {"check_handles": handle}
