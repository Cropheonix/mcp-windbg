"""Tests for exception_parser."""

import os
import pytest

from mcp_windbg.parsers.exception_parser import parse_exception_context
from mcp_windbg.models.dump_models import ExceptionContextResult, EXCEPTION_CODE_MAP

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), '..', 'fixtures')


def load_fixture(name: str) -> list:
    path = os.path.join(FIXTURE_DIR, name)
    if not os.path.exists(path):
        pytest.skip(f"Fixture not found: {name}")
    with open(path, 'r', encoding='utf-8') as f:
        return f.read().splitlines()


def test_exception_code_map():
    """Test exception code mapping."""
    assert EXCEPTION_CODE_MAP["0xC0000005"] == "Access Violation"
    assert EXCEPTION_CODE_MAP["0xE06D7363"] == "C++ Exception"
    assert EXCEPTION_CODE_MAP["0xC00000FD"] == "Stack Overflow"


def test_parse_exception_basic():
    """Test basic exception context parsing."""
    ecxr_lines = load_fixture('ecxr_access_violation.txt')
    lastevent_lines = load_fixture('lastevent.txt')
    register_lines = load_fixture('registers.txt')

    result = parse_exception_context(ecxr_lines, lastevent_lines, register_lines)

    assert isinstance(result, ExceptionContextResult)
    assert result.raw_text
    assert result.exception_code == "0xC0000005"
    assert result.exception_type == "Access violation"
    assert result.exception_address == "00007ff700131ee4"
    assert result.last_event == "1bb0.251c: Access violation - code c0000005 (first/second chance not available)"


def test_parse_exception_record_details():
    """Test exception record details from structured ecxr-style lines."""
    ecxr_lines = [
        "ExceptionAddress: 00007ff700131ee4 (DemoCrash1+0x0000000000001ee4)",
        "   ExceptionCode: c0000005 (Access violation)",
        "  ExceptionFlags: 00000000",
        "   Parameter[0]: 0000000000000001",
        "   Parameter[1]: 0000000000000000",
    ]
    result = parse_exception_context(ecxr_lines=ecxr_lines)

    assert result.exception_code == "0xC0000005"
    assert result.exception_type == "Access violation"
    assert result.exception_address == "00007ff700131ee4"
    assert result.exception_flags == "0x00000000"
    assert result.parameters == ["0000000000000001", "0000000000000000"]


def test_parse_exception_registers_x86():
    """Test register parsing for x86 register output."""
    register_lines = ["eax=00000001 ebx=00000002 eip=00401000 esp=0012ff60"]
    result = parse_exception_context(register_lines=register_lines)

    assert result.registers["eax"] == "00000001"
    assert result.registers["ebx"] == "00000002"
    assert result.registers["eip"] == "00401000"
    assert result.registers["esp"] == "0012ff60"
    assert result.exception_address == "00401000"


def test_parse_exception_empty():
    """Test parser with empty input."""
    result = parse_exception_context()
    assert isinstance(result, ExceptionContextResult)
    assert result.exception_code is None
    assert len(result.registers) == 0
