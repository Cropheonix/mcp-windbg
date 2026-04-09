"""Parser for .frame / dv (local variables) output."""

import re
from typing import List, Optional

from pydantic import BaseModel


class LocalVariable(BaseModel):
    """A single local variable or parameter."""
    name: Optional[str] = None
    type_name: Optional[str] = None
    address: Optional[str] = None
    value: Optional[str] = None
    is_param: bool = False


class FrameLocalsResult(BaseModel):
    """Structured result from .frame + dv output."""
    frame_number: int = 0
    frame_function: Optional[str] = None
    locals: List[LocalVariable] = []
    raw_text: str = ""


# Patterns for dv output
# dv /i: "prv param  addr = value" or "prv local  addr = value"
RE_DV_PARAM = re.compile(
    r"(?:prv|pub)\s+(param|local)\s+"
    r"([0-9a-fA-F`]+)\s*=\s*(.+)"
)
# dv /t: "type name = value" or "type name"
RE_DV_TYPED = re.compile(
    r"(\S+)\s+(\w+)\s*=\s*(.+)"
)
# dv (simple): "name = value" or just "name"
RE_DV_SIMPLE = re.compile(
    r"(\w+)\s*=\s*(.+)"
)
# .frame output
RE_FRAME_FUNC = re.compile(
    r"(?:Setting|Reseting)\s+context\s+to\s+.*?:\s*(.+?)(?:\s*$)"
)
# Alternative .frame: shows "xx N xx"
RE_FRAME_NUMBER = re.compile(
    r"^.*?(\d+).*?$"
)


def parse_frame_locals(
    frame_number: int,
    frame_lines: List[str],
    dv_lines: List[str],
) -> FrameLocalsResult:
    """Parse .frame + dv output into structured result.

    Args:
        frame_number: The frame number that was switched to.
        frame_lines: Raw output from .frame command.
        dv_lines: Raw output from dv /t /i command.

    Returns:
        FrameLocalsResult with parsed local variables.
    """
    result = FrameLocalsResult(frame_number=frame_number)
    all_text = "\n".join(frame_lines + ["---"] + dv_lines)
    result.raw_text = all_text

    # Parse frame function name
    for line in frame_lines:
        m = RE_FRAME_FUNC.search(line)
        if m:
            result.frame_function = m.group(1).strip()
            break

    # Parse local variables
    for line in dv_lines:
        line = line.strip()
        if not line:
            continue

        # Try dv /i format: "prv param  addr = value"
        m = RE_DV_PARAM.match(line)
        if m:
            var_type = m.group(1)
            result.locals.append(LocalVariable(
                name=None,
                address=m.group(2).strip(),
                value=m.group(3).strip(),
                is_param=(var_type == "param"),
            ))
            continue

        # Try typed format: "type name = value"
        m = RE_DV_TYPED.match(line)
        if m:
            result.locals.append(LocalVariable(
                name=m.group(2).strip(),
                type_name=m.group(1).strip(),
                value=m.group(3).strip(),
            ))
            continue

        # Try simple format: "name = value"
        m = RE_DV_SIMPLE.match(line)
        if m:
            result.locals.append(LocalVariable(
                name=m.group(1).strip(),
                value=m.group(2).strip(),
            ))
            continue

    return result
