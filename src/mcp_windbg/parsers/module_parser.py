"""Parser for lm/lmv module list output."""

import re
from typing import List, Optional

from mcp_windbg.models.dump_models import ModuleInfo, ModuleListResult


# lm output line pattern
# Format: "start              end                module name"
RE_MODULE_LINE = re.compile(
    r"^\s*([0-9a-fA-F`]+)\s+([0-9a-fA-F`]+)\s+(\S+)\s+(.*)$"
)

# lmv detail patterns
RE_LMV_IMAGE_PATH = re.compile(r"Image path:\s*(.+)")
RE_LMV_IMAGE_NAME = re.compile(r"Image name:\s*(.+)")
RE_LMV_CHECKSUM = re.compile(r"Checksum:\s*(.+)")
RE_LMV_TIMESTAMP = re.compile(r"Timestamp:\s*(.+?)(?:\s|$)")
RE_LMV_SIZE = re.compile(r"Size:\s*(.+?)(?:\s|$)")
RE_LMV_SYMBOLS = re.compile(r"Symbol\s*(?:file|type):\s*(.+)", re.IGNORECASE)
RE_LMV_LOADED_SYMBOL = re.compile(r"loaded symbol", re.IGNORECASE)
RE_LMV_PDB_SYMBOL = re.compile(r"PDB:\s*(.+)", re.IGNORECASE)

# Symbol status detection in lm output
RE_SYMBOL_DEFERRED = re.compile(r"deferred", re.IGNORECASE)
RE_SYMBOL_EXPORTED = re.compile(r"exported", re.IGNORECASE)
RE_SYMBOL_LOADED = re.compile(r"(?:pdb|symbols loaded)", re.IGNORECASE)

# System module patterns (for is_user_module classification)
SYSTEM_MODULES = {
    "ntdll", "kernel32", "kernelbase", "msvcrt", "ucrtbase",
    "user32", "gdi32", "gdi32full", "advapi32", "ws2_32",
    "rpcrt4", "combase", "ole32", "oleaut32", "shlwapi",
    "shell32", "crypt32", "bcrypt", "bcryptprimitives",
    "sechost", "ntmarta", "mswsock", "profapi", "cryptbase",
    "sspicli", "vcruntime", "msvcp", "msvcp_win",
}


def _is_system_module(name: str) -> bool:
    """Check if a module is a known system module."""
    clean = name.lower()
    for ext in (".dll", ".exe", ".sys"):
        if clean.endswith(ext):
            clean = clean[: -len(ext)]
            break
    return clean in SYSTEM_MODULES


def parse_module_list(lines: List[str]) -> ModuleListResult:
    """Parse lm output into a ModuleListResult.

    Args:
        lines: Raw output lines from lm command.

    Returns:
        ModuleListResult with parsed modules and symbol warnings.
    """
    modules: List[ModuleInfo] = []
    symbol_warnings: List[str] = []
    raw_text = "\n".join(lines)

    for line in lines:
        m = RE_MODULE_LINE.match(line)
        if not m:
            continue

        base_addr = m.group(1).strip()
        end_addr = m.group(2).strip()
        name = m.group(3).strip()
        rest = m.group(4).strip() if m.group(4) else ""

        # Detect symbol status from the rest of the line
        has_symbols = None
        symbol_type = None

        if RE_SYMBOL_DEFERRED.search(rest):
            has_symbols = False
            symbol_type = "deferred"
        elif RE_SYMBOL_EXPORTED.search(rest):
            has_symbols = True
            symbol_type = "exported"
        elif RE_SYMBOL_LOADED.search(rest):
            has_symbols = True
            symbol_type = "loaded"
        elif "pdb" in rest.lower():
            has_symbols = True
            symbol_type = "pdb"

        is_user_mod = not _is_system_module(name)

        modules.append(ModuleInfo(
            base_address=base_addr,
            end_address=end_addr,
            name=name,
            has_symbols=has_symbols,
            symbol_type=symbol_type,
            is_user_module=is_user_mod,
        ))

    # Generate symbol warnings for user modules without symbols
    for mod in modules:
        if mod.is_user_module and mod.has_symbols is False:
            symbol_warnings.append(
                f"User module '{mod.name}' has no symbols loaded (status: {mod.symbol_type})"
            )

    return ModuleListResult(
        modules=modules,
        total_count=len(modules),
        symbol_warnings=symbol_warnings,
        raw_text=raw_text,
    )


def parse_module_detail(lines: List[str]) -> ModuleInfo:
    """Parse lmv m <module> output for detailed module info.

    Args:
        lines: Raw output lines from lmv m <module> command.

    Returns:
        ModuleInfo with detailed fields populated.
    """
    info = ModuleInfo()
    full_text = "\n".join(lines)

    for line in lines:
        m = RE_LMV_IMAGE_PATH.search(line)
        if m:
            info.full_path = m.group(1).strip()

        m = RE_LMV_IMAGE_NAME.search(line)
        if m:
            name = m.group(1).strip()
            if not info.name:
                info.name = name

        m = RE_LMV_CHECKSUM.search(line)
        if m:
            info.checksum = m.group(1).strip()

        m = RE_LMV_TIMESTAMP.search(line)
        if m:
            info.timestamp = m.group(1).strip()

        m = RE_LMV_SIZE.search(line)
        if m:
            size_str = m.group(1).strip()
            try:
                info.size = int(size_str, 16) if "0x" in size_str.lower() else int(size_str)
            except ValueError:
                pass

        m = RE_LMV_PDB_SYMBOL.search(line)
        if m:
            info.has_symbols = True
            info.symbol_type = "pdb"

    return info
