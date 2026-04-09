"""Symbol path construction utilities."""

import os
from typing import Optional, List


def build_symbol_path(
    custom_path: Optional[str] = None,
    source_roots: Optional[List[str]] = None,
) -> str:
    """Build a Windows symbol path string.

    The symbol path includes:
    1. Microsoft public symbol server (always)
    2. User-provided custom paths
    3. PDB directories discovered in source_roots

    Args:
        custom_path: User-provided symbol path string.
        source_roots: Source code directories to scan for PDB files.

    Returns:
        A complete _NT_SYMBOL_PATH string.
    """
    parts = []

    # Always include Microsoft public symbol server
    parts.append("SRV*https://msdl.microsoft.com/download/symbols")

    # Add custom paths
    if custom_path:
        parts.append(custom_path)

    # Scan source_roots for directories containing PDB files
    if source_roots:
        for root in source_roots:
            if not os.path.isdir(root):
                continue
            # Walk up to 2 levels deep looking for PDB files
            for dirpath, dirnames, filenames in os.walk(root):
                depth = dirpath[len(root):].count(os.sep)
                if depth > 2:
                    dirnames.clear()
                    continue
                if any(f.lower().endswith(".pdb") for f in filenames):
                    if dirpath not in parts:
                        parts.append(dirpath)

    return "*".join(parts)


def parse_symbol_path(symbol_path: str) -> List[str]:
    """Parse a symbol path string into individual components.

    Args:
        symbol_path: A _NT_SYMBOL_PATH style string (parts separated by *).

    Returns:
        List of individual path components.
    """
    return [p.strip() for p in symbol_path.split("*") if p.strip()]
