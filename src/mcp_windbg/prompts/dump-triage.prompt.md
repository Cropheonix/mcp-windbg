Perform comprehensive analysis of a single Windows crash dump using structured debugging tools, with detailed metadata extraction, call stack analysis, and structured markdown reporting.

## WORKFLOW - Execute in this exact sequence:

### Step 1: Dump File Identification
**If no dump file path provided:**
- Ask user to provide the specific crash dump file path, use `list_windbg_dumps` to help them find available dumps.

### Step 2: Comprehensive Dump Analysis (Structured Tools)

**2a. Full dump summary (single call):**
**Tool:** `analyze_dump_summary`
- **Parameters:** `dump_path`: Provided dump file path, `detail_level`: "structured"

This runs `!analyze -v`, `.ecxr`, `r`, `lm`, and `kv` in one call, returning parsed exception code, faulting module, stack frames, modules with symbol warnings, and raw output.

**2b. Examine the crashing thread's stack in detail:**
**Tool:** `get_stack_frames`
- **Parameters:** `dump_path`: Provided dump file path, `stack_command`: "kv", `detail_level`: "structured"

Review the parsed stack frames with automatic labeling:
- `user` = your application code
- `framework` = Qt/Framework code
- `system` = OS/Runtime code

**2c. Check for C++ exception details (if exception code is 0xE06D7363):**
**Tool:** `get_cpp_exception`
- **Parameters:** `dump_path`: Provided dump file path, `detail_level`: "structured"

**2d. Get structured exception context:**
**Tool:** `get_exception_context`
- **Parameters:** `dump_path`: Provided dump file path, `detail_level`: "structured"

**2e. Check module symbol status:**
**Tool:** `get_modules_status`
- **Parameters:** `dump_path`: Provided dump file path, `detail_level`: "structured"

Review symbol warnings — missing symbols for user modules means analysis will be limited.

### Step 3: Deep Investigation (Iterative Tools)

Based on the initial analysis, selectively use these tools:

**3a. Examine other threads (if multi-threading issue suspected):**
**Tool:** `list_threads`
- **Parameters:** `dump_path`, `include_stacks`: true, `detail_level`: "structured"

**3b. Inspect local variables in a specific stack frame:**
**Tool:** `get_frame_locals`
- **Parameters:** `dump_path`, `frame_number`: (from stack trace, e.g. 0, 1, 2), `detail_level`: "structured"

**3c. Read memory at suspicious addresses:**
**Tool:** `read_memory`
- **Parameters:** `dump_path`, `address`: (hex address), `format`: "hex"|"dword"|"qword"|"unicode"|"ascii", `detail_level`: "structured"

**3d. Check for deadlocks (if hang/deadlock suspected):**
**Tool:** `get_lock_status`
- **Parameters:** `dump_path`, `detail_level`: "structured"

**3e. Inspect C++ object at an address (if object corruption suspected):**
**Tool:** `inspect_cpp_object`
- **Parameters:** `dump_path`, `address`: (hex address), `type_name`: (optional, e.g. "MyApp!MainWindow"), `detail_level`: "structured"

**3f. Analyze heap block (if heap corruption / use-after-free suspected):**
**Tool:** `analyze_heap_block`
- **Parameters:** `dump_path`, `address`: (hex address of suspected block), `detail_level`: "structured"
- Or without address for heap summary: `dump_path`, `detail_level`: "structured"

**3g. Additional commands (for anything not covered above):**
**Tool:** `run_windbg_cmd`
- Useful commands: `vertarget` (OS details), `.time` (dump timestamp), `!peb` (process environment)

**3h. Analyze thread CPU usage (if hang / CPU spike suspected):**
**Tool:** `analyze_thread_cpu`
- **Parameters:** `dump_path`, `detail_level`: "structured"

**3i. Check handle usage (if resource leak suspected):**
**Tool:** `check_handles`
- **Parameters:** `dump_path`, `detail_level`: "structured"
- Optionally filter: `handle_type`: "File" / "Event" / "Mutex" / "Section"

### Step 4: Cleanup
**Tool:** `close_windbg_dump`
- **Parameters:** `dump_path`: Provided dump file path

### Step 5: Generate Structured Analysis Report

## REQUIRED OUTPUT FORMAT:

```markdown
# Crash Dump Analysis Report
**Analysis Date:** [Current Date]
**Dump File:** [filename.dmp]
**File Path:** [Full path to dump file]

## Executive Summary
- **Crash Type:** [Exception type - Access Violation, Heap Corruption, C++ Exception, etc.]
- **Severity:** [Critical/High/Medium/Low]
- **Root Cause:** [Brief description of the identified issue]
- **Recommended Action:** [Immediate next steps]

## Dump Metadata
- **File Size:** [MB]
- **Creation Time:** [Date/Time]
- **OS Build:** [Windows version and build]
- **Platform:** [x86/x64/ARM64]
- **Process Name:** [Process name and PID]
- **Process Path:** [Full executable path]

## Crash Analysis
**Exception Details:**
- **Exception Code:** [0xC0000005, etc.]
- **Exception Type:** [Access Violation / C++ Exception / etc.]
- **Exception Address:** [0x12345678]
- **Faulting Module:** [module.dll or module.exe]
- **Faulting Symbol:** [module!function+offset]

**Call Stack Analysis:**

Frame Label     Module!Function+Offset
===== ========= ==================================================
[0]   user      MyApp!CMainWindow::OnButtonClick+0x3c
[1]   framework Qt6Widgets!QAbstractButton::clicked+0x42
[2]   framework Qt6Core!QMetaObject::activate+0x120
[3]   user      MyApp!CMainWindow::qt_static_metacall+0x18
[4]   system    USER32!DispatchMessageW+0x1a3
...

**Thread Information:**
- **Crashing Thread ID:** [Thread ID]
- **Thread Count:** [Total threads]
- **Notable Threads:** [Threads with interesting stacks or state]

## Root Cause Analysis
[Detailed explanation of what caused the crash, including:]
- **What happened:** [Technical description of the failure]
- **Why it happened:** [Analysis of contributing factors]
- **Code location:** [Specific function/line if identifiable — focus on user-labeled frames]
- **Memory state:** [Description of memory corruption, null pointers, etc.]

## Recommendations

### Immediate Actions
1. [Specific action item 1]
2. [Specific action item 2]

### Investigation Steps
1. [Follow-up analysis steps — suggest specific tools if needed]
2. [Code review recommendations]
3. [Testing scenarios to reproduce]

### Prevention Measures
1. [Code changes to prevent recurrence]
2. [Additional validation/checks needed]

## Priority Assessment
**Severity:** [Critical/High/Medium/Low]
**Justification:** [Based on impact, frequency, ease of reproduction, data loss potential]
```

## ANALYSIS GUIDELINES:

- **Focus on user-labeled frames**: These are your application code — the root cause is usually here
- **Framework frames provide context**: Qt/Framework calls show the execution path but are rarely the root cause
- **System frames are usually innocent**: ntdll/kernel32 crashes usually indicate corruption from earlier user code
- **Missing symbols = limited analysis**: If user modules have no symbols, note this and suggest obtaining PDBs
- **Exception code drives investigation**: Different exception codes require different follow-up tools
  - 0xC0000005 (Access Violation): Check memory address, inspect objects at faulting address
  - 0xC0000374 (Heap Corruption): Use analyze_heap_block, check allocation stacks
  - 0xC00000FD (Stack Overflow): Check for deep recursion in stack frames
  - 0xE06D7363 (C++ Exception): Use get_cpp_exception for type/throw info
  - 0x80000003 (Breakpoint): Likely assertion failure — check assertion message
- **Deadlock indicators**: Multiple threads waiting, get_lock_status shows locked critical sections
- **Memory leak indicators**: Growing heaps (analyze_heap_block summary), high handle counts

**Always ask follow-up questions if:**
- Dump file path is not provided or unclear
- User wants specific focus areas for analysis
- Additional investigation is needed for specific code paths
- Source code context would be helpful for understanding the crash
