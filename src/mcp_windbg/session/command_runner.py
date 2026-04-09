"""Command execution with session-level caching."""

import re
import time
import logging
from typing import Dict, List, Optional, Tuple

from mcp_windbg.session.cdb_session import CDBSession, CDBError

logger = logging.getLogger(__name__)


class CommandRunner:
    """Wraps a CDBSession with caching for deterministic read-only commands.

    Only commands that produce identical output for the lifetime of a dump
    session are cached (e.g., lm, !analyze -v, .ecxr). Commands that depend
    on mutable debugger state (e.g., k after thread switch) are not cached.
    """

    # Commands whose output is deterministic for a given dump session
    CACHEABLE_COMMANDS: set = {
        "lm",
        "!analyze -v",
        ".ecxr",
        ".lastevent",
        "vertarget",
        ".time",
        "~",
        ".symfix",
        ".sympath",
        "version",
    }

    # Prefixes that indicate a thread-switch (invalidates stack/register caches)
    THREAD_SWITCH_PREFIX = re.compile(r"^~\d+\s*[sS]$")
    STACK_CACHE_PREFIXES = ("k", "r", ".ecxr", ".lastevent")
    SYMBOL_CACHE_PREFIXES = ("lm", "lmv", "!analyze -v", ".ecxr", ".lastevent", "k", "r")

    def __init__(self, session: CDBSession):
        self._session = session
        self._cache: Dict[str, Tuple[List[str], float]] = {}

    def run(
        self,
        command: str,
        timeout: Optional[int] = None,
        use_cache: bool = True,
    ) -> List[str]:
        """Execute a CDB command with optional caching.

        Args:
            command: The CDB command to execute.
            timeout: Optional timeout override.
            use_cache: Whether to use cached results if available.

        Returns:
            List of output lines from CDB.
        """
        cache_key = command.strip().lower()

        # Check cache
        if use_cache and cache_key in self._cache:
            logger.debug(f"Cache hit for: {command}")
            return self._cache[cache_key][0]

        # Execute command
        result = self._session.send_command(command, timeout=timeout)

        # Cache if applicable
        if use_cache and self._is_cacheable(command):
            self._cache[cache_key] = (result, time.time())
            logger.debug(f"Cached result for: {command}")

        return result

    def invalidate(self, command: str) -> None:
        """Invalidate cache for a specific command."""
        cache_key = command.strip().lower()
        self._cache.pop(cache_key, None)

    def invalidate_stack_caches(self) -> None:
        """Invalidate caches that depend on current thread context.

        Called after thread switch commands.
        """
        keys_to_remove = [k for k in self._cache if k.startswith(self.STACK_CACHE_PREFIXES)]
        for key in keys_to_remove:
            del self._cache[key]

    def invalidate_symbol_caches(self) -> None:
        """Invalidate caches that depend on symbol path configuration."""
        keys_to_remove = [k for k in self._cache if k.startswith(self.SYMBOL_CACHE_PREFIXES)]
        for key in keys_to_remove:
            del self._cache[key]

    def invalidate_all(self) -> None:
        """Clear all cached results."""
        self._cache.clear()

    @property
    def session(self) -> CDBSession:
        """Access the underlying CDBSession."""
        return self._session

    def _is_cacheable(self, command: str) -> bool:
        """Check if a command's output can be cached.

        Thread-switch commands also trigger stack cache invalidation.
        """
        stripped = command.strip().lower()

        if self.THREAD_SWITCH_PREFIX.match(stripped):
            return False

        # Check exact match
        if stripped in self.CACHEABLE_COMMANDS:
            return True

        # Check prefix for lmv (module details are static)
        if stripped.startswith("lmv"):
            return True

        return False
