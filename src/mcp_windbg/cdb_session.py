"""Re-export shim for backward compatibility.

The CDBSession module has been moved to mcp_windbg.session.cdb_session.
This file preserves existing import paths.
"""

from mcp_windbg.session.cdb_session import (
    CDBSession,
    CDBError,
    DEFAULT_CDB_PATHS,
    PROMPT_REGEX,
    COMMAND_MARKER,
    COMMAND_MARKER_PATTERN,
)

__all__ = [
    "CDBSession",
    "CDBError",
    "DEFAULT_CDB_PATHS",
    "PROMPT_REGEX",
    "COMMAND_MARKER",
    "COMMAND_MARKER_PATTERN",
]
