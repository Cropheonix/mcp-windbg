"""Parser for memory dump output (db/dd/dq/du/da)."""

import re
from typing import List, Optional

from pydantic import BaseModel


class MemoryLine(BaseModel):
    """A single line of memory dump output."""
    address: str
    hex_data: str = ""
    ascii_data: Optional[str] = None


class MemoryResult(BaseModel):
    """Structured result from memory dump commands."""
    address: str = ""
    length: int = 0
    format: str = ""
    lines: List[MemoryLine] = []
    raw_text: str = ""


# Memory dump line pattern
# db format: "00000000`12340000  48 65 6c 6c 6f 20 57 6f-72 6c 64 00 00 00 00 00  Hello World......"
# dd format: "00000000`12340000  00400078 00400078 00400078 00400078"
# dq format: "00000000`12340000  00000001`40007800 00000001`40007800"
RE_MEM_LINE = re.compile(
    r"^([0-9a-fA-F`]+)\s+([\s0-9a-fA-F`\-]+?)(?:\s{2,}(.+))?$"
)


def parse_memory_output(
    lines: List[str],
    address: str = "",
    length: int = 0,
    fmt: str = "hex",
) -> MemoryResult:
    """Parse db/dd/dq/du/da output into structured result.

    Args:
        lines: Raw output lines from memory dump command.
        address: The requested address.
        length: The requested length.
        fmt: The format used (hex, dword, qword, unicode, ascii).

    Returns:
        MemoryResult with parsed memory data.
    """
    result = MemoryResult(
        address=address,
        length=length,
        format=fmt,
        raw_text="\n".join(lines),
    )

    for line in lines:
        line = line.strip()
        if not line:
            continue

        m = RE_MEM_LINE.match(line)
        if m:
            mem_line = MemoryLine(
                address=m.group(1).strip(),
                hex_data=m.group(2).strip() if m.group(2) else "",
                ascii_data=m.group(3).strip() if m.group(3) else None,
            )
            result.lines.append(mem_line)

    return result
