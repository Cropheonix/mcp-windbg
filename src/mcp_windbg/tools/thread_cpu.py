"""analyze_thread_cpu tool — thread CPU time analysis via !runaway."""

import re
import traceback
import logging
from typing import Dict, List, Optional, Tuple

from mcp.shared.exceptions import McpError
from mcp.types import ErrorData, TextContent, Tool, INTERNAL_ERROR

from mcp_windbg.session.manager import SessionManager
from mcp_windbg.adapters.windbg_adapter import WinDbgAdapter
from mcp_windbg.models.session_models import AnalyzeThreadCpuParams
from mcp_windbg.models.response_models import TieredResponse, tiered_to_text_content

logger = logging.getLogger(__name__)


def register(
    sm: SessionManager,
    source_roots: Optional[List[str]] = None,
) -> Tuple[List[Tool], Dict[str, object]]:
    tools = [
        Tool(
            name="analyze_thread_cpu",
            description=(
                "Analyze thread CPU time using !runaway. Shows user-mode and kernel-mode "
                "CPU time for each thread, sorted by total time. Essential for diagnosing "
                "CPU spikes, infinite loops, busy-wait patterns, and identifying which "
                "thread is consuming the most CPU in hang scenarios."
            ),
            inputSchema=AnalyzeThreadCpuParams.model_json_schema(),
        ),
    ]

    def handle(arguments: dict) -> list[TextContent]:
        try:
            args = AnalyzeThreadCpuParams(**arguments)
            runner = sm.get_runner(
                dump_path=args.dump_path,
                connection_string=args.connection_string,
            )
            adapter = WinDbgAdapter(runner)
            raw = adapter.get_thread_cpu_time()
            raw_text = "\n".join(raw)

            # Parse !runaway output
            # Format:
            #  User mode time
            #   Thread       Time
            #    0:1ebc       0 days 0:00:05.123
            #    1:2a3f       0 days 0:00:00.015
            #  Kernel mode time
            #   Thread       Time
            #    0:1ebc       0 days 0:00:01.456
            threads = []
            current_section = None

            for line in raw:
                stripped = line.strip()

                # Detect section headers
                if "User mode time" in stripped:
                    current_section = "user"
                    continue
                elif "Kernel mode time" in stripped:
                    current_section = "kernel"
                    continue
                elif "Total time" in stripped:
                    current_section = "total"
                    continue

                # Parse thread entries: "  N:HHHH  0 days H:MM:SS.mmm"
                m = re.match(
                    r"(\d+):([0-9a-fA-F]+)\s+"
                    r"(\d+)\s+days\s+"
                    r"(\d+):(\d+):(\d+)(?:\.(\d+))?",
                    stripped,
                )
                if m and current_section:
                    thread_num = int(m.group(1))
                    thread_id = m.group(2)
                    hours = int(m.group(4))
                    minutes = int(m.group(5))
                    seconds = int(m.group(6))
                    ms = int(m.group(7)) if m.group(7) else 0
                    total_seconds = hours * 3600 + minutes * 60 + seconds + ms / 1000.0

                    # Find or create thread entry
                    existing = next(
                        (t for t in threads if t["thread_number"] == thread_num),
                        None,
                    )
                    if existing is None:
                        existing = {
                            "thread_number": thread_num,
                            "thread_id": thread_id,
                            "user_time_s": 0.0,
                            "kernel_time_s": 0.0,
                            "total_time_s": 0.0,
                        }
                        threads.append(existing)

                    if current_section == "user":
                        existing["user_time_s"] = total_seconds
                    elif current_section == "kernel":
                        existing["kernel_time_s"] = total_seconds
                    elif current_section == "total":
                        existing["total_time_s"] = total_seconds

            # Sort by total user+kernel time descending
            for t in threads:
                if t["total_time_s"] == 0.0:
                    t["total_time_s"] = t["user_time_s"] + t["kernel_time_s"]
            threads.sort(key=lambda t: t["total_time_s"], reverse=True)

            top_thread = threads[0] if threads else None
            summary = f"Thread CPU analysis: {len(threads)} threads."
            if top_thread and top_thread["total_time_s"] > 0:
                summary += (
                    f" Top consumer: thread #{top_thread['thread_number']}"
                    f" ({top_thread['total_time_s']:.3f}s total)"
                )

            structured_data = {
                "thread_count": len(threads),
                "threads": threads,
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
                message=f"Error executing analyze_thread_cpu: {str(e)}\n{traceback.format_exc()}"
            ))

    return tools, {"analyze_thread_cpu": handle}
