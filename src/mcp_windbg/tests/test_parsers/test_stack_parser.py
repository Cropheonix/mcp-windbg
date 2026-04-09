"""Tests for stack_parser."""

import os
import pytest

from mcp_windbg.parsers.stack_parser import parse_stack_output, label_frame
from mcp_windbg.models.dump_models import StackResult, StackFrame

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), '..', 'fixtures')


def load_fixture(name: str) -> list:
    path = os.path.join(FIXTURE_DIR, name)
    if not os.path.exists(path):
        pytest.skip(f"Fixture not found: {name}")
    with open(path, 'r', encoding='utf-8') as f:
        return f.read().splitlines()


def test_label_frame_qt():
    """Test Qt module labeling."""
    assert label_frame("Qt6Core") == "framework"
    assert label_frame("Qt5Widgets") == "framework"
    assert label_frame("Qt6Gui") == "framework"
    assert label_frame("Qt6Qml") == "framework"


def test_label_frame_system():
    """Test system module labeling."""
    assert label_frame("ntdll") == "system"
    assert label_frame("kernel32") == "system"
    assert label_frame("ucrtbase") == "system"
    assert label_frame("USER32") == "system"


def test_label_frame_user():
    """Test user module labeling."""
    assert label_frame("MyApp") == "user"
    assert label_frame("DemoCrash1") == "user"
    assert label_frame("mylib") == "user"


def test_label_frame_none():
    """Test labeling with None module."""
    assert label_frame(None) == "user"
    assert label_frame("") == "user"


def test_parse_stack_basic():
    """Test basic stack parsing."""
    lines = load_fixture('kv_simple.txt')
    result = parse_stack_output(lines, "kv")

    assert isinstance(result, StackResult)
    assert result.command_used == "kv"
    assert len(result.frames) > 0
    assert result.raw_text


def test_parse_stack_frame_labels():
    """Test that frames get labeled."""
    lines = load_fixture('kv_simple.txt')
    result = parse_stack_output(lines, "kv")

    for frame in result.frames:
        assert frame.frame_label in ("user", "framework", "system")
        # Consistency check
        if frame.is_user_code:
            assert frame.frame_label == "user"
        elif frame.is_framework:
            assert frame.frame_label == "framework"
        elif frame.is_system:
            assert frame.frame_label == "system"


def test_parse_stack_module_offset_without_symbols():
    """Test parsing frames that only have module+offset call sites."""
    lines = [
        "00000008`7faffd00 00007ff7`00135730     : 00000000`00000000 00007ff7`001357a9 00000000`00000000 00000000`00000000 : DemoCrash1+0x1ee4",
    ]
    result = parse_stack_output(lines, "kv")

    assert len(result.frames) == 1
    frame = result.frames[0]
    assert frame.module == "DemoCrash1"
    assert frame.function is None
    assert frame.offset == 0x1EE4
    assert frame.frame_label == "user"


def test_parse_stack_empty():
    """Test parser with empty input."""
    result = parse_stack_output([], "kv")
    assert isinstance(result, StackResult)
    assert len(result.frames) == 0


def test_parse_stack_frame_numbers():
    """Test that frame numbers are sequential."""
    lines = load_fixture('kv_simple.txt')
    result = parse_stack_output(lines, "kv")

    if len(result.frames) > 0:
        for i, frame in enumerate(result.frames):
            assert frame.frame_number == i


def test_stack_overflow_detection():
    """Test that deep stacks trigger overflow warning."""
    # Generate 600 frames to exceed the 500-frame threshold
    lines = []
    for i in range(600):
        lines.append(
            f"  {i:3d} 00000000`{i:08x} 00000000`{i+1:08x} MyApp!RecursiveFunc+0x10"
        )
    result = parse_stack_output(lines, "kv")
    assert result.overflow_warning is not None
    assert "600 frames" in result.overflow_warning
    assert "stack overflow" in result.overflow_warning.lower()


def test_stack_recursion_detection():
    """Test that repeating function patterns trigger recursion warning."""
    # 15 frames, last 10 are all the same function (2 unique <= threshold)
    lines = []
    for i in range(15):
        lines.append(
            f"  {i:3d} 00000000`{i:08x} 00000000`{i+1:08x} MyApp!DeepRecurse+0x8"
        )
    result = parse_stack_output(lines, "k")
    assert result.overflow_warning is not None
    assert "recursion" in result.overflow_warning.lower()


def test_no_overflow_warning_normal_stack():
    """Test that normal stacks don't trigger overflow warnings."""
    lines = [
        "  0 000000XX`XXXXXXXX 000000XX`XXXXXXXX MyApp!main+0x20",
        "  1 000000XX`XXXXXXXX 000000XX`XXXXXXXX MyApp!init+0x10",
        "  2 000000XX`XXXXXXXX 000000XX`XXXXXXXX ntdll!LdrInitializeThunk+0x10",
    ]
    result = parse_stack_output(lines, "k")
    assert result.overflow_warning is None
