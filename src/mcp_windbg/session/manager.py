"""Session management for CDB debugging sessions."""

import os
import glob
import winreg
import logging
from typing import Dict, Optional, List

from mcp_windbg.session.cdb_session import CDBSession, CDBError
from mcp_windbg.session.command_runner import CommandRunner

logger = logging.getLogger(__name__)


def get_local_dumps_path() -> Optional[str]:
    """Get the local dumps path from the Windows registry."""
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps"
        ) as key:
            dump_folder, _ = winreg.QueryValueEx(key, "DumpFolder")
            if os.path.exists(dump_folder) and os.path.isdir(dump_folder):
                return dump_folder
    except (OSError, WindowsError):
        pass

    # Default Windows dump location
    default_path = os.path.join(os.environ.get("LOCALAPPDATA", ""), "CrashDumps")
    if os.path.exists(default_path) and os.path.isdir(default_path):
        return default_path

    return None


class SessionManager:
    """Manages CDB debugging sessions with lifecycle and caching support.

    Replaces the module-level active_sessions dict with an injectable class
    that also manages CommandRunner instances for caching.
    """

    def __init__(
        self,
        cdb_path: Optional[str] = None,
        symbols_path: Optional[str] = None,
        timeout: int = 30,
        verbose: bool = False,
    ):
        self._sessions: Dict[str, CDBSession] = {}
        self._runners: Dict[str, CommandRunner] = {}
        self._cdb_path = cdb_path
        self._symbols_path = symbols_path
        self._timeout = timeout
        self._verbose = verbose

    def _session_id(
        self,
        dump_path: Optional[str] = None,
        connection_string: Optional[str] = None,
    ) -> str:
        """Create a session identifier."""
        if dump_path:
            return os.path.abspath(dump_path)
        elif connection_string:
            return f"remote:{connection_string}"
        else:
            raise ValueError("Either dump_path or connection_string must be provided")

    def get_or_create(
        self,
        dump_path: Optional[str] = None,
        connection_string: Optional[str] = None,
    ) -> CDBSession:
        """Get an existing CDB session or create a new one.

        Args:
            dump_path: Path to crash dump file.
            connection_string: Remote debugging connection string.

        Returns:
            Active CDBSession.

        Raises:
            ValueError: If neither or both parameters provided.
        """
        session_id = self._session_id(dump_path, connection_string)

        if session_id not in self._sessions or self._sessions[session_id] is None:
            try:
                session = CDBSession(
                    dump_path=dump_path,
                    remote_connection=connection_string,
                    cdb_path=self._cdb_path,
                    symbols_path=self._symbols_path,
                    timeout=self._timeout,
                    verbose=self._verbose,
                )
                self._sessions[session_id] = session
                self._runners[session_id] = CommandRunner(session)
                return session
            except Exception as e:
                from mcp.shared.exceptions import McpError
                from mcp.types import ErrorData, INTERNAL_ERROR
                raise McpError(ErrorData(
                    code=INTERNAL_ERROR,
                    message=f"Failed to create CDB session: {str(e)}"
                ))

        return self._sessions[session_id]

    def get_runner(
        self,
        dump_path: Optional[str] = None,
        connection_string: Optional[str] = None,
    ) -> CommandRunner:
        """Get the CommandRunner for a session.

        Creates the session if it doesn't exist.
        """
        session_id = self._session_id(dump_path, connection_string)
        if session_id not in self._runners:
            self.get_or_create(dump_path, connection_string)
        return self._runners[session_id]

    def unload(
        self,
        dump_path: Optional[str] = None,
        connection_string: Optional[str] = None,
    ) -> bool:
        """Unload and clean up a CDB session.

        Returns:
            True if a session was found and unloaded, False otherwise.
        """
        try:
            session_id = self._session_id(dump_path, connection_string)
        except ValueError:
            return False

        if session_id in self._sessions and self._sessions[session_id] is not None:
            try:
                self._sessions[session_id].shutdown()
            except Exception:
                pass
            finally:
                del self._sessions[session_id]
                self._runners.pop(session_id, None)
            return True

        return False

    def cleanup_all(self) -> None:
        """Close all active CDB sessions."""
        for session_id, session in list(self._sessions.items()):
            try:
                if session is not None:
                    session.shutdown()
            except Exception:
                pass
        self._sessions.clear()
        self._runners.clear()
