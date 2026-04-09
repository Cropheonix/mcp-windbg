"""Parser for ~ (thread list) and ~*k (all thread stacks) output."""

import re
from typing import List, Optional

from mcp_windbg.models.dump_models import ThreadInfo, ThreadListResult


# Thread list line pattern
# Current thread: ".  0  Id: XXXX.XXXX Suspend: 0 Teb: XXXXXXXX UnfStart XXXXXXXX"
# Other threads:  "   1  Id: XXXX.XXXX Suspend: 0 Teb: XXXXXXXX UnfStart XXXXXXXX"
RE_THREAD_LINE = re.compile(
    r"^\s*([.#]?)\s*(\d+)\s+Id:\s*([0-9a-fA-F]+)\.([0-9a-fA-F]+)\s+"
    r"Suspend:\s*(\d+)\s+TeB:\s*([0-9a-fA-F`]+)"
)
# Simplified thread line pattern (some CDB versions)
RE_THREAD_LINE_SIMPLE = re.compile(
    r"^\s*([.#]?)\s*(\d+)\s+Id:\s*([0-9a-fA-F]+)\.([0-9a-fA-F]+)\s+"
    r"Suspend:\s*(\d+)"
)


def parse_thread_list(lines: List[str]) -> ThreadListResult:
    """Parse ~ (thread list) output into a ThreadListResult.

    Args:
        lines: Raw output lines from ~ command.

    Returns:
        ThreadListResult with parsed thread info.
    """
    threads: List[ThreadInfo] = []
    current_thread = 0
    raw_text = "\n".join(lines)

    for line in lines:
        # Strip CDB prompt prefix (e.g., "0:000> ")
        stripped = line.lstrip()
        prompt_match = re.match(r'^\d+:\d+>\s*', stripped)
        if prompt_match:
            stripped = stripped[prompt_match.end():]

        # Try full pattern first
        m = RE_THREAD_LINE.match(stripped)
        if not m:
            m = RE_THREAD_LINE_SIMPLE.match(stripped)

        if not m:
            continue

        marker = m.group(1)
        thread_num = int(m.group(2))
        os_id = f"{m.group(3)}.{m.group(4)}"
        suspend = int(m.group(5))
        is_current = marker == "."

        if is_current:
            current_thread = thread_num

        threads.append(ThreadInfo(
            thread_number=thread_num,
            os_id=os_id,
            suspend_count=suspend,
            is_current=is_current,
        ))

    return ThreadListResult(
        threads=threads,
        current_thread=current_thread,
        total_count=len(threads),
        raw_text=raw_text,
    )
