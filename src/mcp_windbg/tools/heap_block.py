"""analyze_heap_block tool — heap block analysis and heap summary."""

import re
import traceback
import logging
from typing import Dict, List, Optional, Tuple

from mcp.shared.exceptions import McpError
from mcp.types import ErrorData, TextContent, Tool, INTERNAL_ERROR

from mcp_windbg.session.manager import SessionManager
from mcp_windbg.adapters.windbg_adapter import WinDbgAdapter
from mcp_windbg.models.session_models import AnalyzeHeapBlockParams
from mcp_windbg.models.response_models import TieredResponse, tiered_to_text_content

logger = logging.getLogger(__name__)


def register(
    sm: SessionManager,
    source_roots: Optional[List[str]] = None,
) -> Tuple[List[Tool], Dict[str, object]]:
    tools = [
        Tool(
            name="analyze_heap_block",
            description=(
                "Analyze a heap memory block or get heap summary. With an address, runs "
                "!heap -p -a <addr> to show allocation stack trace and block metadata. "
                "Without an address, runs !heap -s for heap summary statistics. "
                "Essential for diagnosing heap corruption (0xC0000374), use-after-free, "
                "double-free, and memory leaks."
            ),
            inputSchema=AnalyzeHeapBlockParams.model_json_schema(),
        ),
    ]

    def handle(arguments: dict) -> list[TextContent]:
        try:
            args = AnalyzeHeapBlockParams(**arguments)
            runner = sm.get_runner(
                dump_path=args.dump_path,
                connection_string=args.connection_string,
            )
            adapter = WinDbgAdapter(runner)

            if args.address:
                # Analyze specific heap block
                raw = adapter.analyze_heap_block(args.address)
                raw_text = "\n".join(raw)

                # Parse !heap -p -a output
                block_info = {"address": args.address}
                alloc_stack = []
                in_alloc_stack = False

                for line in raw:
                    # Block size
                    m = re.search(r"size:\s*(\d+)", line, re.IGNORECASE)
                    if m:
                        block_info["size"] = int(m.group(1))

                    # Block status (free/allocated)
                    m = re.search(r"(free|allocated|busy)", line, re.IGNORECASE)
                    if m:
                        block_info["status"] = m.group(1).lower()

                    # Alloc stack trace
                    if "trace" in line.lower() and "stack" in line.lower():
                        in_alloc_stack = True
                        continue
                    if in_alloc_stack:
                        # Stack frames: "  N  addr  module!func+offset"
                        if re.match(r"\s*\d+\s+[0-9a-fA-F`]+", line):
                            alloc_stack.append(line.strip())
                        elif line.strip() == "" and alloc_stack:
                            in_alloc_stack = False

                if alloc_stack:
                    block_info["alloc_stack"] = alloc_stack

                summary = f"Heap block at {args.address}"
                if "size" in block_info:
                    summary += f", size: {block_info['size']} bytes"
                if "status" in block_info:
                    summary += f", status: {block_info['status']}"

                structured_data = block_info

            else:
                # Heap summary
                raw = adapter.get_heap_summary()
                raw_text = "\n".join(raw)

                heaps = []
                for line in raw:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("0:"):
                        continue
                    # !heap -s output: "Heap Address      Reserved    Committed ..."
                    m = re.match(
                        r"([0-9a-fA-F`]+)\s+(\d+)\s+(\d+)\s+(\d+)",
                        stripped,
                    )
                    if m:
                        heaps.append({
                            "address": m.group(1),
                            "reserved": int(m.group(2)),
                            "committed": int(m.group(3)),
                            "blocks": int(m.group(4)) if len(m.groups()) > 3 else 0,
                        })

                summary = f"Heap summary: {len(heaps)} heap(s) found."
                structured_data = {
                    "heap_count": len(heaps),
                    "heaps": heaps,
                }

            structured_data["raw_output"] = raw_text[:8000]

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
                message=f"Error executing analyze_heap_block: {str(e)}\n{traceback.format_exc()}"
            ))

    return tools, {"analyze_heap_block": handle}
