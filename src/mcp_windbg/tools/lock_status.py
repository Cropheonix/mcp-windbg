"""get_lock_status tool — check critical section / lock status."""

import re
import traceback
import logging
from typing import Dict, List, Optional, Tuple

from mcp.shared.exceptions import McpError
from mcp.types import ErrorData, TextContent, Tool, INTERNAL_ERROR

from mcp_windbg.session.manager import SessionManager
from mcp_windbg.adapters.windbg_adapter import WinDbgAdapter
from mcp_windbg.models.session_models import GetLockStatusParams
from mcp_windbg.models.response_models import TieredResponse, tiered_to_text_content

logger = logging.getLogger(__name__)


def register(
    sm: SessionManager,
    source_roots: Optional[List[str]] = None,
) -> Tuple[List[Tool], Dict[str, object]]:
    tools = [
        Tool(
            name="get_lock_status",
            description=(
                "Check critical section and lock status using !locks -v. "
                "Shows which threads hold locks, lock counts, recursion depth, "
                "and waiting threads. Parses lock entries with owning thread info "
                "and detects potential deadlocks. "
                "Essential for diagnosing deadlocks and concurrency issues in C++ applications."
            ),
            inputSchema=GetLockStatusParams.model_json_schema(),
        ),
    ]

    def handle(arguments: dict) -> list[TextContent]:
        try:
            args = GetLockStatusParams(**arguments)
            runner = sm.get_runner(
                dump_path=args.dump_path,
                connection_string=args.connection_string,
            )
            adapter = WinDbgAdapter(runner)
            raw = adapter.get_lock_status()
            raw_text = "\n".join(raw)

            # Parse !locks -v output into structured lock entries
            # Format:
            # CritSec <address> at <address>
            # WaitersWoken    : N
            # LockCount       : N
            # RecursionCount  : N
            # OwningThread    : <thread_id>
            # EntryCount      : N
            # ContentiousCount: N
            # *** Locked
            # or
            # *** NOT Locked
            #
            # Waiter threads:
            # Thread N:HHHH  ...

            locks: List[dict] = []
            current_lock: Optional[dict] = None

            for line in raw:
                stripped = line.strip()

                # New CritSec entry
                m = re.match(
                    r"CritSec\s+([0-9a-fA-F`]+)\s+at\s+([0-9a-fA-F`]+)",
                    stripped,
                )
                if m:
                    if current_lock is not None:
                        locks.append(current_lock)
                    current_lock = {
                        "address": m.group(1),
                        "lock_count": 0,
                        "recursion_count": 0,
                        "owning_thread": None,
                        "is_locked": False,
                        "waiters": [],
                    }
                    continue

                if current_lock is None:
                    continue

                # Lock properties
                m = re.match(r"LockCount\s*:\s*(\d+)", stripped)
                if m:
                    current_lock["lock_count"] = int(m.group(1))
                    continue

                m = re.match(r"RecursionCount\s*:\s*(\d+)", stripped)
                if m:
                    current_lock["recursion_count"] = int(m.group(1))
                    continue

                m = re.match(r"OwningThread\s*:\s*([0-9a-fA-F]+)", stripped)
                if m:
                    current_lock["owning_thread"] = m.group(1)
                    continue

                # Locked status
                if re.match(r"\*\*\*\s+Locked\b", stripped):
                    current_lock["is_locked"] = True
                    continue
                if re.match(r"\*\*\*\s+NOT\s+Locked", stripped):
                    current_lock["is_locked"] = False
                    continue

                # Waiter thread line: "Thread N:HHHH ..."
                m = re.match(r"Thread\s+(\d+):([0-9a-fA-F]+)", stripped)
                if m:
                    current_lock.setdefault("waiters", []).append({
                        "thread_number": int(m.group(1)),
                        "thread_id": m.group(2),
                    })

            # Don't forget the last lock
            if current_lock is not None:
                locks.append(current_lock)

            locked_count = sum(1 for lk in locks if lk["is_locked"])
            locks_with_waiters = [lk for lk in locks if lk.get("waiters")]

            # Detect deadlock patterns: thread A holds lock X waiting for lock Y,
            # thread B holds lock Y waiting for lock X
            deadlock_warnings = []
            if locks_with_waiters:
                for lk in locks_with_waiters:
                    if lk["is_locked"] and len(lk["waiters"]) > 0:
                        deadlock_warnings.append(
                            f"Lock at {lk['address']} held by thread {lk.get('owning_thread', '?')} "
                            f"with {len(lk['waiters'])} waiter(s)"
                        )

            summary = f"Locks scanned: {len(locks)}. Locked: {locked_count}."
            if deadlock_warnings:
                summary += f" {len(deadlock_warnings)} lock(s) with waiters — potential deadlock."

            structured_data = {
                "locks_found": len(locks),
                "locked_count": locked_count,
                "locks_with_waiters": len(locks_with_waiters),
                "locks": locks,
                "deadlock_warnings": deadlock_warnings,
                "raw_output": raw_text[:8000],
            }

            response = TieredResponse(
                summary=summary,
                structured=structured_data,
                raw_excerpt=raw_text[:3000],
                raw_full=raw_text,
            )

            return [tiered_to_text_content(response, args.detail_level)]

        except McpError:
            raise
        except Exception as e:
            raise McpError(ErrorData(
                code=INTERNAL_ERROR,
                message=f"Error executing get_lock_status: {str(e)}\n{traceback.format_exc()}"
            ))

    return tools, {"get_lock_status": handle}
