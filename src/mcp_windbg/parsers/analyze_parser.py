"""Parser for !analyze -v output."""

import re
from typing import List, Optional, Tuple

from mcp_windbg.models.dump_models import (
    AnalyzeResult,
    AnalyzeFrame,
    EXCEPTION_CODE_MAP,
)


# Regex patterns for !analyze -v output
RE_EXCEPTION_CODE = re.compile(
    r"ExceptionCode:\s*(?:0x)?([0-9a-fA-F]+)\s*(?:\((.*?)\))?",
    re.IGNORECASE,
)
RE_EXCEPTION_CODE_ALT = re.compile(
    r"Exception code:\s*(?:0x)?([0-9a-fA-F]+)",
    re.IGNORECASE,
)
RE_FAULTING_MODULE = re.compile(
    r"FAULTING_MODULE:\s*([0-9a-fA-F`]+)\s+(\S+)"
)
RE_MODULE_NAME = re.compile(
    r"MODULE_NAME:\s*(\S+)",
    re.IGNORECASE,
)
RE_EXCEPTION_ADDRESS = re.compile(
    r"ExceptionAddress:\s*([0-9a-fA-F`]+)"
)
RE_PROBABLY_CAUSED = re.compile(
    r"Probably caused by:\s*(\S+)"
)
RE_SYMBOL_NAME = re.compile(
    r"SYMBOL_NAME:\s*(.+?)(?:\s*$)",
    re.IGNORECASE,
)
RE_BUCKET_ID = re.compile(
    r"BUCKET_ID:\s*(.+?)(?:\s*$)"
)
RE_FAILURE_BUCKET_ID = re.compile(
    r"FAILURE_BUCKET_ID:\s*(.+?)(?:\s*$)",
    re.IGNORECASE,
)
RE_BUCKET_ID_FUNC = re.compile(
    r"BUCKET_ID_FUNC:\s*(.+?)(?:\s*$)"
)
RE_CALL_SITE_SYMBOL = re.compile(
    r"^(\S+?)!([^\s+]+?)(?:\+0x?([0-9a-fA-F]+))?$"
)
RE_CALL_SITE_MODULE_OFFSET = re.compile(
    r"^(\S+?)(?:\+0x?([0-9a-fA-F]+))$"
)


def parse_analyze_output(lines: List[str]) -> AnalyzeResult:
    """Parse !analyze -v output into a structured AnalyzeResult.

    Args:
        lines: Raw output lines from !analyze -v command.

    Returns:
        AnalyzeResult with extracted fields. Unknown lines are skipped,
        missing fields default to None.
    """
    result = AnalyzeResult()
    result.raw_text = "\n".join(lines)

    stack_frames: list = []

    for line in lines:
        line = _strip_prompt(line)

        # Exception code
        m = RE_EXCEPTION_CODE.search(line)
        if m:
            result.exception_code = _normalize_exception_code(m.group(1))
            result.exception_type = m.group(2).strip() if m.group(2) else None
            continue

        # Alternative exception code format
        m = RE_EXCEPTION_CODE_ALT.search(line)
        if m and not result.exception_code:
            result.exception_code = _normalize_exception_code(m.group(1))
            result.exception_type = EXCEPTION_CODE_MAP.get(
                result.exception_code, None
            )
            continue

        # Faulting module
        m = RE_FAULTING_MODULE.search(line)
        if m:
            result.faulting_module_base = m.group(1).strip()
            result.faulting_module = m.group(2).strip()
            continue

        m = RE_MODULE_NAME.search(line)
        if m and not result.faulting_module:
            result.faulting_module = m.group(1).strip()
            continue

        # Exception address
        m = RE_EXCEPTION_ADDRESS.search(line)
        if m:
            result.exception_address = m.group(1).strip()
            continue

        # Probably caused by
        m = RE_PROBABLY_CAUSED.search(line)
        if m:
            result.probably_caused_by = m.group(1).strip()
            continue

        m = RE_SYMBOL_NAME.search(line)
        if m and not result.probably_caused_by:
            result.probably_caused_by = m.group(1).strip()
            continue

        # Bucket ID
        m = RE_BUCKET_ID.search(line)
        if m and not result.bucket_id:
            result.bucket_id = m.group(1).strip()
            continue

        m = RE_FAILURE_BUCKET_ID.search(line)
        if m and not result.bucket_id:
            result.bucket_id = m.group(1).strip()
            continue

        # Bucket ID function
        m = RE_BUCKET_ID_FUNC.search(line)
        if m:
            result.bucket_id_func = m.group(1).strip()
            continue

    # Build bucket hint: prefer probably_caused_by, fallback to bucket_id
    if not result.faulting_module and result.probably_caused_by:
        parsed_module, _, _ = _parse_call_site(result.probably_caused_by)
        result.faulting_module = parsed_module

    if result.probably_caused_by:
        result.bucket_hint = result.probably_caused_by
    elif result.bucket_id:
        result.bucket_hint = result.bucket_id

    # Extract stack frames from the STACK_TEXT section
    stack_section = _extract_stack_section(lines)
    if stack_section:
        for frame_number, line in enumerate(stack_section):
            frame = _parse_stack_line(line, frame_number)
            if frame:
                stack_frames.append(frame)
    result.stack_frames = stack_frames

    return result


# CDB prompt prefix pattern (e.g., "0:000> ")
RE_CDB_PROMPT = re.compile(r"^\d+:\d+>\s*")


def _strip_prompt(line: str) -> str:
    """Remove CDB prompt prefix from a line."""
    return RE_CDB_PROMPT.sub("", line)


def _extract_stack_section(lines: List[str]) -> List[str]:
    stack_lines = []
    in_stack = False
    for line in lines:
        if "STACK_TEXT:" in line:
            in_stack = True
            continue
        if in_stack:
            if line.strip() == "" or "FOLLOWUP_" in line or "MODULE_NAME:" in line:
                break
            stack_lines.append(line)
    return stack_lines


def _normalize_exception_code(code: Optional[str]) -> Optional[str]:
    """Normalize exception codes to 0x-prefixed uppercase strings."""
    if not code:
        return None

    cleaned = code.strip()
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]

    return f"0x{cleaned.upper()}"


def _parse_call_site(call_site: str) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    """Parse module/function/offset from a call-site string."""
    sym_match = RE_CALL_SITE_SYMBOL.match(call_site)
    if sym_match:
        offset = int(sym_match.group(3), 16) if sym_match.group(3) else None
        return sym_match.group(1), sym_match.group(2), offset

    module_offset_match = RE_CALL_SITE_MODULE_OFFSET.match(call_site)
    if module_offset_match:
        offset = int(module_offset_match.group(2), 16) if module_offset_match.group(2) else None
        return module_offset_match.group(1), None, offset

    return None, None, None


def _parse_stack_line(line: str, frame_number: int) -> Optional[AnalyzeFrame]:
    """Parse a single line from the STACK_TEXT section."""
    # Format: "CHILD_SP  RetAddr  : args : ... : module!function+offset"
    parts = line.strip().split()
    if len(parts) < 3:
        return None

    call_site = line.rsplit(" : ", 1)[-1].strip() if " : " in line else parts[-1]
    module, function, _ = _parse_call_site(call_site)

    if not module and not function:
        return None

    ret_addr = parts[1] if len(parts) > 1 else None

    return AnalyzeFrame(
        frame_number=frame_number,
        return_address=ret_addr,
        module=module,
        function=function,
    )
