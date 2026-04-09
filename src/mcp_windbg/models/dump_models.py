"""Structured output models for parsed CDB/WinDbg data."""

from typing import Dict, List, Optional

from pydantic import BaseModel


# --- Exception code mapping ---

EXCEPTION_CODE_MAP: Dict[str, str] = {
    "0xC0000005": "Access Violation",
    "0xC0000374": "Heap Corruption",
    "0xC00000FD": "Stack Overflow",
    "0xE06D7363": "C++ Exception",
    "0x80000003": "Breakpoint",
    "0x80000004": "Single Step",
    "0xC0000096": "Privileged Instruction",
    "0xC000001D": "Illegal Instruction",
    "0xC000008C": "Array Bounds Exceeded",
    "0xC000008D": "Float Denormal Operand",
    "0xC000008E": "Float Divide by Zero",
    "0xC000008F": "Float Inexact Result",
    "0xC0000090": "Float Invalid Operation",
    "0xC0000091": "Float Overflow",
    "0xC0000092": "Float Stack Check",
    "0xC0000093": "Float Underflow",
    "0xC0000094": "Integer Divide by Zero",
    "0xC0000095": "Integer Overflow",
    "0xC0000097": "Privileged Instruction",
    "0xC0000135": "DLL Not Found",
    "0xC0000139": "Entry Point Not Found",
    "0xC0000142": "DLL Initialization Failed",
    "0x40010006": "Output Debug String",
    "0x4001000A": "Debugger Breakpoint",
    "0xDEADFA11": "Application Hang",
}


# --- Analyze models ---

class AnalyzeFrame(BaseModel):
    """A single frame from !analyze -v stack output."""
    frame_number: int
    return_address: Optional[str] = None
    module: Optional[str] = None
    function: Optional[str] = None


class AnalyzeResult(BaseModel):
    """Structured result from !analyze -v output."""
    exception_code: Optional[str] = None
    exception_type: Optional[str] = None
    exception_address: Optional[str] = None
    faulting_module: Optional[str] = None
    faulting_module_base: Optional[str] = None
    probably_caused_by: Optional[str] = None
    bucket_id: Optional[str] = None
    bucket_id_func: Optional[str] = None
    bucket_hint: Optional[str] = None
    stack_frames: List[AnalyzeFrame] = []
    raw_text: str = ""


# --- Stack models ---

class StackFrame(BaseModel):
    """A single stack frame with labeling."""
    frame_number: int
    child_sp: Optional[str] = None
    return_address: Optional[str] = None
    module: Optional[str] = None
    function: Optional[str] = None
    offset: Optional[int] = None
    # Frame labeling
    is_user_code: Optional[bool] = None
    is_framework: Optional[bool] = None
    is_system: Optional[bool] = None
    frame_label: Optional[str] = None  # "user" | "framework" | "system"
    # Source info (populated when available)
    source_file: Optional[str] = None
    source_line: Optional[int] = None


class StackResult(BaseModel):
    """Structured result from k/kv/kp stack output."""
    frames: List[StackFrame] = []
    total_frames: int = 0
    command_used: str = ""
    raw_text: str = ""
    overflow_warning: Optional[str] = None


# --- Module models ---

class ModuleInfo(BaseModel):
    """Information about a loaded module."""
    base_address: Optional[str] = None
    end_address: Optional[str] = None
    name: Optional[str] = None
    full_path: Optional[str] = None
    size: Optional[int] = None
    timestamp: Optional[str] = None
    checksum: Optional[str] = None
    has_symbols: Optional[bool] = None
    symbol_type: Optional[str] = None  # "pdb", "exported", "deferred", "loaded"
    is_user_module: Optional[bool] = None


class ModuleListResult(BaseModel):
    """Structured result from lm/lmv output."""
    modules: List[ModuleInfo] = []
    total_count: int = 0
    symbol_warnings: List[str] = []
    raw_text: str = ""


# --- Exception context models ---

class ExceptionContextResult(BaseModel):
    """Structured result from .ecxr/.lastevent/r output."""
    exception_code: Optional[str] = None
    exception_type: Optional[str] = None
    exception_address: Optional[str] = None
    exception_flags: Optional[str] = None
    parameters: List[str] = []
    registers: Dict[str, str] = {}
    last_event: Optional[str] = None
    raw_text: str = ""


# --- Thread models ---

class ThreadInfo(BaseModel):
    """Information about a thread."""
    thread_number: int = 0
    os_id: Optional[str] = None
    suspend_count: int = 0
    is_current: bool = False


class ThreadListResult(BaseModel):
    """Structured result from ~ output."""
    threads: List[ThreadInfo] = []
    current_thread: int = 0
    total_count: int = 0
    raw_text: str = ""
