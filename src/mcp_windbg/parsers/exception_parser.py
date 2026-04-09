"""Parser for .ecxr, .lastevent, and r (registers) output."""

import re
from typing import Dict, List, Optional

from mcp_windbg.models.dump_models import ExceptionContextResult, EXCEPTION_CODE_MAP


# .ecxr patterns
RE_EXCEPTION_RECORD_CODE = re.compile(
    r"ExceptionCode:\s*(?:0x)?([0-9a-fA-F]+)\s*(?:\((.*?)\))?",
    re.IGNORECASE,
)
RE_EXCEPTION_FLAGS = re.compile(
    r"ExceptionFlags:\s*(?:0x)?([0-9a-fA-F]+)",
    re.IGNORECASE,
)
RE_EXCEPTION_ADDRESS = re.compile(
    r"ExceptionAddress:\s*([0-9a-fA-F`]+)"
)
RE_NUM_PARAMETERS = re.compile(
    r"NumberParameters:\s*(\d+)"
)
RE_PARAMETER = re.compile(
    r"Parameter(?:\[(\d+)\]|\s+\d+)\s*:\s*([0-9a-fA-F`]+)",
    re.IGNORECASE,
)

# .lastevent patterns
RE_LAST_EVENT = re.compile(
    r"Last event:\s*(.+?)(?:\s*$)"
)
RE_LAST_EVENT_CODE = re.compile(
    r"\bcode\s+(?:0x)?([0-9a-fA-F]+)\b",
    re.IGNORECASE,
)
RE_LAST_EVENT_TYPE = re.compile(
    r"Last event:\s*(?:[0-9a-fA-F]+\.[0-9a-fA-F]+:\s*)?(.+?)\s+-\s+code\b",
    re.IGNORECASE,
)
RE_LAST_EVENT_TIME = re.compile(
    r"time:\s*(.+?)(?:\s*$)"
)

# Register patterns
RE_REGISTER_PAIR = re.compile(
    r"\b([a-z][a-z0-9]{1,3})=([0-9a-fA-F`]+)\b",
    re.IGNORECASE,
)

# Access violation specific
RE_ACCESS_VIOLATION_TYPE = re.compile(
    r"(Read|Write|Execute)\s+.*?address\s+([0-9a-fA-F`]+)",
    re.IGNORECASE,
)


def parse_exception_context(
    ecxr_lines: Optional[List[str]] = None,
    lastevent_lines: Optional[List[str]] = None,
    register_lines: Optional[List[str]] = None,
) -> ExceptionContextResult:
    """Parse exception context from multiple CDB command outputs.

    Args:
        ecxr_lines: Raw output from .ecxr command.
        lastevent_lines: Raw output from .lastevent command.
        register_lines: Raw output from r command.

    Returns:
        ExceptionContextResult with structured exception data.
    """
    result = ExceptionContextResult()
    raw_sections: List[str] = []

    # Parse .ecxr output
    if ecxr_lines:
        ecxr_text = "\n".join(ecxr_lines)
        raw_sections.append(ecxr_text)

        for line in ecxr_lines:
            for register_match in RE_REGISTER_PAIR.finditer(line):
                reg_name = register_match.group(1).lower()
                reg_val = register_match.group(2).replace("`", "")
                result.registers.setdefault(reg_name, reg_val)

            # Exception code
            m = RE_EXCEPTION_RECORD_CODE.search(line)
            if m:
                result.exception_code = _normalize_exception_code(m.group(1))
                if m.group(2):
                    result.exception_type = m.group(2).strip()
                else:
                    result.exception_type = EXCEPTION_CODE_MAP.get(
                        result.exception_code, None
                    )
                continue

            # Exception flags
            m = RE_EXCEPTION_FLAGS.search(line)
            if m:
                result.exception_flags = _normalize_exception_code(m.group(1))
                continue

            # Exception address
            m = RE_EXCEPTION_ADDRESS.search(line)
            if m:
                result.exception_address = m.group(1).strip()
                continue

            # Parameters
            m = RE_PARAMETER.search(line)
            if m:
                result.parameters.append(m.group(2).strip())
                continue

    # Parse .lastevent output
    if lastevent_lines:
        lastevent_text = "\n".join(lastevent_lines)
        raw_sections.append(lastevent_text)

        for line in lastevent_lines:
            m = RE_LAST_EVENT.search(line)
            if m:
                result.last_event = m.group(1).strip()

                event_type_match = RE_LAST_EVENT_TYPE.search(line)
                if event_type_match and not result.exception_type:
                    result.exception_type = event_type_match.group(1).strip()

                event_code_match = RE_LAST_EVENT_CODE.search(line)
                if event_code_match and not result.exception_code:
                    result.exception_code = _normalize_exception_code(event_code_match.group(1))
                    if not result.exception_type:
                        result.exception_type = EXCEPTION_CODE_MAP.get(result.exception_code)
                continue

    # If we still don't have exception info, try .lastevent for code
    if not result.exception_code and lastevent_lines:
        for line in lastevent_lines:
            m = RE_EXCEPTION_RECORD_CODE.search(line)
            if m:
                result.exception_code = _normalize_exception_code(m.group(1))
                result.exception_type = m.group(2).strip() if m.group(2) else EXCEPTION_CODE_MAP.get(
                    result.exception_code, None
                )
                break

    # Parse registers
    if register_lines:
        raw_sections.append("\n".join(register_lines))
        for line in register_lines:
            for m in RE_REGISTER_PAIR.finditer(line):
                reg_name = m.group(1).lower()
                reg_val = m.group(2).replace("`", "")
                result.registers.setdefault(reg_name, reg_val)

    if not result.exception_address:
        result.exception_address = result.registers.get("rip") or result.registers.get("eip")

    result.raw_text = "\n\n".join(section for section in raw_sections if section)

    return result


def _normalize_exception_code(code: Optional[str]) -> Optional[str]:
    """Normalize exception codes to 0x-prefixed uppercase strings."""
    if not code:
        return None

    cleaned = code.strip()
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]

    return f"0x{cleaned.upper()}"
