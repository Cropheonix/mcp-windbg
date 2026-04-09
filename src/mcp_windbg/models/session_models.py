"""Pydantic parameter models for MCP tool inputs."""

from typing import Optional, List

from pydantic import BaseModel, Field, model_validator


# --- Existing tool parameter models ---

class OpenWindbgDump(BaseModel):
    """Parameters for analyzing a crash dump."""
    dump_path: str = Field(description="Path to the Windows crash dump file")
    include_stack_trace: bool = Field(description="Whether to include stack traces in the analysis")
    include_modules: bool = Field(description="Whether to include loaded module information")
    include_threads: bool = Field(description="Whether to include thread information")


class OpenWindbgRemote(BaseModel):
    """Parameters for connecting to a remote debug session."""
    connection_string: str = Field(description="Remote connection string (e.g., 'tcp:Port=5005,Server=192.168.0.100')")
    include_stack_trace: bool = Field(default=False, description="Whether to include stack traces in the analysis")
    include_modules: bool = Field(default=False, description="Whether to include loaded module information")
    include_threads: bool = Field(default=False, description="Whether to include thread information")


class RunWindbgCmdParams(BaseModel):
    """Parameters for executing a WinDbg command."""
    dump_path: Optional[str] = Field(default=None, description="Path to the Windows crash dump file")
    connection_string: Optional[str] = Field(default=None, description="Remote connection string (e.g., 'tcp:Port=5005,Server=192.168.0.100')")
    command: str = Field(description="WinDbg command to execute")

    @model_validator(mode='after')
    def validate_connection_params(self):
        """Validate that exactly one of dump_path or connection_string is provided."""
        if not self.dump_path and not self.connection_string:
            raise ValueError("Either dump_path or connection_string must be provided")
        if self.dump_path and self.connection_string:
            raise ValueError("dump_path and connection_string are mutually exclusive")
        return self


class CloseWindbgDumpParams(BaseModel):
    """Parameters for unloading a crash dump."""
    dump_path: str = Field(description="Path to the Windows crash dump file to unload")


class CloseWindbgRemoteParams(BaseModel):
    """Parameters for closing a remote debugging connection."""
    connection_string: str = Field(description="Remote connection string to close")


class ListWindbgDumpsParams(BaseModel):
    """Parameters for listing crash dumps in a directory."""
    directory_path: Optional[str] = Field(
        default=None,
        description="Directory path to search for dump files. If not specified, will use the configured dump path from registry."
    )
    recursive: bool = Field(
        default=False,
        description="Whether to search recursively in subdirectories"
    )


class SendCtrlBreakParams(BaseModel):
    """Parameters for sending CTRL+BREAK to a CDB/WinDbg session."""
    dump_path: Optional[str] = Field(default=None, description="Path to the Windows crash dump file")
    connection_string: Optional[str] = Field(default=None, description="Remote connection string (e.g., 'tcp:Port=5005,Server=192.168.0.100')")

    @model_validator(mode='after')
    def validate_connection_params(self):
        if not self.dump_path and not self.connection_string:
            raise ValueError("Either dump_path or connection_string must be provided")
        if self.dump_path and self.connection_string:
            raise ValueError("dump_path and connection_string are mutually exclusive")
        return self


# --- New structured tool parameter models ---

class AnalyzeDumpSummaryParams(BaseModel):
    """Parameters for comprehensive dump summary analysis."""
    dump_path: str = Field(description="Path to the Windows crash dump file")
    symbol_paths: Optional[List[str]] = Field(
        default=None,
        description="Additional symbol paths to search"
    )
    source_roots: Optional[List[str]] = Field(
        default=None,
        description="Source code root directories"
    )
    detail_level: str = Field(
        default="structured",
        description="Output detail level: summary, structured, raw_excerpt, raw_full"
    )


class GetStackFramesParams(BaseModel):
    """Parameters for getting parsed stack frames."""
    dump_path: Optional[str] = Field(default=None, description="Path to the Windows crash dump file")
    connection_string: Optional[str] = Field(default=None, description="Remote connection string")
    thread_id: Optional[int] = Field(default=None, description="Thread number to switch to (omit for current thread)")
    stack_command: str = Field(default="kv", description="Stack command to use: k, kv, kp, or kn")
    detail_level: str = Field(
        default="structured",
        description="Output detail level: summary, structured, raw_excerpt, raw_full"
    )

    @model_validator(mode='after')
    def validate_connection_params(self):
        if not self.dump_path and not self.connection_string:
            raise ValueError("Either dump_path or connection_string must be provided")
        if self.dump_path and self.connection_string:
            raise ValueError("dump_path and connection_string are mutually exclusive")
        return self


class GetModulesStatusParams(BaseModel):
    """Parameters for getting module status with symbol info."""
    dump_path: Optional[str] = Field(default=None, description="Path to the Windows crash dump file")
    connection_string: Optional[str] = Field(default=None, description="Remote connection string")
    detail_level: str = Field(
        default="structured",
        description="Output detail level: summary, structured, raw_excerpt, raw_full"
    )

    @model_validator(mode='after')
    def validate_connection_params(self):
        if not self.dump_path and not self.connection_string:
            raise ValueError("Either dump_path or connection_string must be provided")
        if self.dump_path and self.connection_string:
            raise ValueError("dump_path and connection_string are mutually exclusive")
        return self


class GetExceptionContextParams(BaseModel):
    """Parameters for getting structured exception context."""
    dump_path: Optional[str] = Field(default=None, description="Path to the Windows crash dump file")
    connection_string: Optional[str] = Field(default=None, description="Remote connection string")
    detail_level: str = Field(
        default="structured",
        description="Output detail level: summary, structured, raw_excerpt, raw_full"
    )

    @model_validator(mode='after')
    def validate_connection_params(self):
        if not self.dump_path and not self.connection_string:
            raise ValueError("Either dump_path or connection_string must be provided")
        if self.dump_path and self.connection_string:
            raise ValueError("dump_path and connection_string are mutually exclusive")
        return self


# --- P0: Iterative debugging tool parameter models ---

class ListThreadsParams(BaseModel):
    """Parameters for listing threads."""
    dump_path: Optional[str] = Field(default=None, description="Path to the Windows crash dump file")
    connection_string: Optional[str] = Field(default=None, description="Remote connection string")
    include_stacks: bool = Field(
        default=False,
        description="Include brief stack trace for each thread"
    )
    detail_level: str = Field(
        default="structured",
        description="Output detail level: summary, structured, raw_excerpt, raw_full"
    )

    @model_validator(mode='after')
    def validate_connection_params(self):
        if not self.dump_path and not self.connection_string:
            raise ValueError("Either dump_path or connection_string must be provided")
        if self.dump_path and self.connection_string:
            raise ValueError("dump_path and connection_string are mutually exclusive")
        return self


class GetFrameLocalsParams(BaseModel):
    """Parameters for inspecting local variables in a specific stack frame."""
    dump_path: Optional[str] = Field(default=None, description="Path to the Windows crash dump file")
    connection_string: Optional[str] = Field(default=None, description="Remote connection string")
    frame_number: int = Field(description="Stack frame number to inspect (0 = top of stack)")
    detail_level: str = Field(
        default="structured",
        description="Output detail level: summary, structured, raw_excerpt, raw_full"
    )

    @model_validator(mode='after')
    def validate_connection_params(self):
        if not self.dump_path and not self.connection_string:
            raise ValueError("Either dump_path or connection_string must be provided")
        if self.dump_path and self.connection_string:
            raise ValueError("dump_path and connection_string are mutually exclusive")
        return self


class ReadMemoryParams(BaseModel):
    """Parameters for reading memory at a given address."""
    dump_path: Optional[str] = Field(default=None, description="Path to the Windows crash dump file")
    connection_string: Optional[str] = Field(default=None, description="Remote connection string")
    address: str = Field(description="Memory address to read (hex, e.g. '0x12345678' or '00007ff6`12340000')")
    length: int = Field(default=128, description="Number of bytes to read")
    format: str = Field(
        default="hex",
        description="Output format: hex (db), dword (dd), qword (dq), unicode (du), ascii (da)"
    )
    detail_level: str = Field(
        default="structured",
        description="Output detail level: summary, structured, raw_excerpt, raw_full"
    )

    @model_validator(mode='after')
    def validate_connection_params(self):
        if not self.dump_path and not self.connection_string:
            raise ValueError("Either dump_path or connection_string must be provided")
        if self.dump_path and self.connection_string:
            raise ValueError("dump_path and connection_string are mutually exclusive")
        return self


# --- P0: C++ deep debugging tool parameter models ---

class GetCppExceptionParams(BaseModel):
    """Parameters for inspecting C++ exception details."""
    dump_path: Optional[str] = Field(default=None, description="Path to the Windows crash dump file")
    connection_string: Optional[str] = Field(default=None, description="Remote connection string")
    detail_level: str = Field(default="structured")

    @model_validator(mode='after')
    def validate_connection_params(self):
        if not self.dump_path and not self.connection_string:
            raise ValueError("Either dump_path or connection_string must be provided")
        if self.dump_path and self.connection_string:
            raise ValueError("dump_path and connection_string are mutually exclusive")
        return self


class GetLockStatusParams(BaseModel):
    """Parameters for checking lock/critical section status."""
    dump_path: Optional[str] = Field(default=None, description="Path to the Windows crash dump file")
    connection_string: Optional[str] = Field(default=None, description="Remote connection string")
    detail_level: str = Field(default="structured")

    @model_validator(mode='after')
    def validate_connection_params(self):
        if not self.dump_path and not self.connection_string:
            raise ValueError("Either dump_path or connection_string must be provided")
        if self.dump_path and self.connection_string:
            raise ValueError("dump_path and connection_string are mutually exclusive")
        return self


class InspectCppObjectParams(BaseModel):
    """Parameters for inspecting a C++ object at a given address."""
    dump_path: Optional[str] = Field(default=None, description="Path to the Windows crash dump file")
    connection_string: Optional[str] = Field(default=None, description="Remote connection string")
    type_name: Optional[str] = Field(
        default=None,
        description="C++ type name (e.g., 'MyApp!MainWindow'). If omitted, auto-detect from symbol."
    )
    address: str = Field(
        description="Memory address of the object (hex). Use 'this' or register values from get_frame_locals."
    )
    depth: int = Field(default=1, description="Recursion depth for nested members (1=flat, 2=one level deep)")
    detail_level: str = Field(default="structured")

    @model_validator(mode='after')
    def validate_connection_params(self):
        if not self.dump_path and not self.connection_string:
            raise ValueError("Either dump_path or connection_string must be provided")
        if self.dump_path and self.connection_string:
            raise ValueError("dump_path and connection_string are mutually exclusive")
        return self


class AnalyzeThreadCpuParams(BaseModel):
    """Parameters for analyzing thread CPU time via !runaway."""
    dump_path: Optional[str] = Field(default=None, description="Path to the Windows crash dump file")
    connection_string: Optional[str] = Field(default=None, description="Remote connection string")
    detail_level: str = Field(default="structured")

    @model_validator(mode='after')
    def validate_connection_params(self):
        if not self.dump_path and not self.connection_string:
            raise ValueError("Either dump_path or connection_string must be provided")
        if self.dump_path and self.connection_string:
            raise ValueError("dump_path and connection_string are mutually exclusive")
        return self


class CheckHandlesParams(BaseModel):
    """Parameters for checking handle usage via !handle."""
    dump_path: Optional[str] = Field(default=None, description="Path to the Windows crash dump file")
    connection_string: Optional[str] = Field(default=None, description="Remote connection string")
    handle_type: Optional[str] = Field(
        default=None,
        description="Filter by handle type (e.g., 'File', 'Event', 'Mutex', 'Process', 'Thread', 'Section'). If omitted, shows summary."
    )
    detail_level: str = Field(default="structured")

    @model_validator(mode='after')
    def validate_connection_params(self):
        if not self.dump_path and not self.connection_string:
            raise ValueError("Either dump_path or connection_string must be provided")
        if self.dump_path and self.connection_string:
            raise ValueError("dump_path and connection_string are mutually exclusive")
        return self


class AnalyzeHeapBlockParams(BaseModel):
    """Parameters for analyzing a heap block or heap summary."""
    dump_path: Optional[str] = Field(default=None, description="Path to the Windows crash dump file")
    connection_string: Optional[str] = Field(default=None, description="Remote connection string")
    address: Optional[str] = Field(
        default=None,
        description="Heap block address to analyze. If omitted, returns heap summary (!heap -s)."
    )
    detail_level: str = Field(default="structured")

    @model_validator(mode='after')
    def validate_connection_params(self):
        if not self.dump_path and not self.connection_string:
            raise ValueError("Either dump_path or connection_string must be provided")
        if self.dump_path and self.connection_string:
            raise ValueError("dump_path and connection_string are mutually exclusive")
        return self
