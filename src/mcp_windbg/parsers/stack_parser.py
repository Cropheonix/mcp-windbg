"""Parser for k/kv/kp/kn stack output."""

import re
from typing import List, Optional

from mcp_windbg.models.dump_models import StackFrame, StackResult


# Regex for k/kv stack frames
# Format: "  ##  Child-SP          RetAddr           Call Site"
# Frame:  "   0  000000XX`XXXXXXXX 000000XX`XXXXXXXX module!function+0xOFFSET"
# kv also includes: ": Args to Child : Call Site" with ": val : val : val : module!func"
RE_STACK_FRAME = re.compile(
    r"^\s*(\d+)\s+"
    r"([0-9a-fA-F`]+)\s+"
    r"([0-9a-fA-F`]+)\s+"
    r"(.+)$"
)
# Alternative kv format: "addr  addr  : args : args : args : module!func+offset"
RE_STACK_FRAME_KV = re.compile(
    r"^\s*([0-9a-fA-F`]+)\s+"
    r"([0-9a-fA-F`]+)\s+"
    r":\s+(.+)$"
)

# Module!function+offset pattern
RE_SYMBOL = re.compile(
    r"^(\S+?)!([^\s+]+?)(?:\+0x([0-9a-fA-F]+))?$"
)
RE_MODULE_OFFSET = re.compile(
    r"^(\S+?)(?:\+0x?([0-9a-fA-F]+))$"
)

# Header line pattern
RE_STACK_HEADER = re.compile(
    r"^Child-SP\s+RetAddr\s+Call Site"
)

# Qt module patterns for frame labeling
QT_MODULE_PATTERNS = [
    re.compile(r"^Qt[56]?(Core|Gui|Widgets|Network|Sql|Xml|Qml|Quick|WebEngine|OpenGL|PrintSupport|Svg|Test|Concurrent|Multimedia|MultimediaWidgets)", re.IGNORECASE),
    re.compile(r"^Qt(Core|Gui|Widgets|Network|Sql|Xml|Qml|Quick|WebEngine|OpenGL|PrintSupport|Svg|Test|Concurrent|Multimedia)", re.IGNORECASE),
]

# System module patterns
SYSTEM_MODULE_PATTERNS = [
    re.compile(
        r"^(ntdll|kernel32|kernelbase|msvcrt|ucrtbase|user32|user32l|gdi32|gdi32full|"
        r"sechost|ntmarta|advapi32|ws2_32|mswsock|crypt32|bcrypt|bcryptprimitives|"
        r"rpcrt4|combase|ole32|oleaut32|shlwapi|shell32|msvcrt|vcruntime|ucrtbase|"
        r"cryptbase|sspicli|profapi|kernel32|KERNEL32|KERNELBASE|ntdll|NTDLL)",
        re.IGNORECASE,
    ),
]


def label_frame(module: Optional[str], function: Optional[str] = None) -> str:
    """Label a frame as 'user', 'framework', or 'system'.

    Args:
        module: The module name (e.g., 'Qt6Core', 'ntdll', 'MyApp').
        function: The function name (optional, for additional heuristics).

    Returns:
        One of "user", "framework", "system".
    """
    if not module:
        return "user"

    # Check Qt/framework modules
    for pattern in QT_MODULE_PATTERNS:
        if pattern.search(module):
            return "framework"

    # Check system modules
    for pattern in SYSTEM_MODULE_PATTERNS:
        if pattern.search(module):
            return "system"

    return "user"


def parse_stack_output(
    lines: List[str],
    command: str = "kv",
) -> StackResult:
    """Parse k/kv/kp/kn stack output into a StackResult.

    Args:
        lines: Raw output lines from stack command.
        command: The stack command used (k, kv, kp, kn).

    Returns:
        StackResult with parsed frames and frame labels.
    """
    frames: List[StackFrame] = []
    raw_text = "\n".join(lines)
    frame_idx = 0

    for line in lines:
        # Skip header lines and prompt lines
        if RE_STACK_HEADER.match(line):
            continue
        if line.strip().startswith("0:"):
            continue
        if not line.strip():
            continue

        # Try numbered format first (k output)
        m = RE_STACK_FRAME.match(line)
        if m:
            frame_num = int(m.group(1))
            child_sp = m.group(2)
            ret_addr = m.group(3)
            call_site = m.group(4).strip()
            frame_idx = frame_num + 1
        else:
            # Try kv format: "addr  addr  : args : args : args : module!func+offset"
            m = RE_STACK_FRAME_KV.match(line)
            if not m:
                continue
            child_sp = m.group(1)
            ret_addr = m.group(2)
            call_site = m.group(3).strip()
            frame_num = frame_idx
            frame_idx += 1

        # Extract the last colon-separated section as call site (for kv format)
        # kv format: ": val : val : val : module!func+offset"
        colon_parts = call_site.split(" : ")
        if len(colon_parts) > 1:
            call_site = colon_parts[-1].strip()

        # Parse module!function+offset from call site
        module = None
        function = None
        offset = None
        source_file = None
        source_line = None

        # Try to extract source info (format: "module!func+0xOFF [file @ line]")
        source_match = re.search(r"\[(.+?)\s*@\s*(\d+)\]", call_site)
        if source_match:
            source_file = source_match.group(1).strip()
            try:
                source_line = int(source_match.group(2))
            except ValueError:
                pass
            call_site = call_site[:source_match.start()].strip()

        # Parse module!function+offset
        sym_match = RE_SYMBOL.match(call_site)
        if sym_match:
            module = sym_match.group(1)
            function = sym_match.group(2)
            if sym_match.group(3):
                try:
                    offset = int(sym_match.group(3), 16)
                except ValueError:
                    pass
        else:
            module_offset_match = RE_MODULE_OFFSET.match(call_site)
            if module_offset_match:
                module = module_offset_match.group(1)
                if module_offset_match.group(2):
                    try:
                        offset = int(module_offset_match.group(2), 16)
                    except ValueError:
                        pass
            elif "!" in call_site:
                parts = call_site.split("!", 1)
                module = parts[0]
                func_part = parts[1].split()[0] if parts[1] else None
                if func_part and "+" in func_part:
                    func_name, offset_str = func_part.split("+", 1)
                    function = func_name
                    if offset_str:
                        try:
                            offset = int(offset_str, 16)
                        except ValueError:
                            offset = None
                elif func_part:
                    function = func_part

        # Label frame
        frame_label_val = label_frame(module, function)
        is_user_code = frame_label_val == "user"
        is_framework = frame_label_val == "framework"
        is_system = frame_label_val == "system"

        frames.append(StackFrame(
            frame_number=frame_num,
            child_sp=child_sp,
            return_address=ret_addr,
            module=module,
            function=function,
            offset=offset,
            is_user_code=is_user_code,
            is_framework=is_framework,
            is_system=is_system,
            frame_label=frame_label_val,
            source_file=source_file,
            source_line=source_line,
        ))

    # Detect stack overflow patterns
    overflow_warning = None
    if len(frames) > 500:
        overflow_warning = f"Stack has {len(frames)} frames — likely stack overflow"

    # Detect recursion: same function repeating consecutively
    if not overflow_warning and len(frames) >= 10:
        func_seq = [f.function for f in frames[-10:]]
        if func_seq and len(set(func_seq)) <= 2 and None not in func_seq:
            overflow_warning = (
                f"Detected deep recursion pattern: {', '.join(func_seq[:3])} "
                f"... ({len(frames)} frames total)"
            )

    result = StackResult(
        frames=frames,
        total_frames=len(frames),
        command_used=command,
        raw_text=raw_text,
    )

    # Attach overflow warning to the result if detected
    if overflow_warning:
        # Store as extra metadata — consumers can check this
        result.overflow_warning = overflow_warning

    return result
