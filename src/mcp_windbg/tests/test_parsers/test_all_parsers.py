"""Tests for analyze_parser."""

import os
import pytest

from mcp_windbg.parsers.analyze_parser import parse_analyze_output
from mcp_windbg.models.dump_models import AnalyzeResult

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), '..', 'fixtures')


def load_fixture(name: str) -> list:
    """Load a fixture file as list of lines."""
    path = os.path.join(FIXTURE_DIR, name)
    if not os.path.exists(path):
        pytest.skip(f"Fixture not found: {name}")
    with open(path, 'r', encoding='utf-8') as f:
        return f.read().splitlines()


def test_parse_analyze_basic():
    """Test basic !analyze -v parsing."""
    lines = load_fixture('analyze_v_access_violation.txt')
    result = parse_analyze_output(lines)

    assert isinstance(result, AnalyzeResult)
    assert result.raw_text  # Should have raw text
    assert len(result.raw_text) > 0
    assert result.exception_code == "0xC0000005"
    assert result.exception_type == "Access violation"
    assert result.faulting_module == "DemoCrash1"
    assert result.bucket_hint
    user_frames = [frame for frame in result.stack_frames if frame.module == "DemoCrash1"]
    assert len(user_frames) >= 2


def test_parse_analyze_exception_code():
    """Test exception code extraction."""
    lines = load_fixture('analyze_v_access_violation.txt')
    result = parse_analyze_output(lines)

    assert result.exception_code == "0xC0000005"
    assert result.probably_caused_by == "DemoCrash1+1ee4"
    assert result.bucket_id == "NULL_POINTER_WRITE_c0000005_DemoCrash1.exe!Unknown"


def test_parse_analyze_empty_input():
    """Test parser with empty input."""
    result = parse_analyze_output([])
    assert isinstance(result, AnalyzeResult)
    assert result.exception_code is None
    assert result.raw_text == ""


def test_parse_analyze_raw_text_preserved():
    """Test that raw text is preserved."""
    lines = load_fixture('analyze_v_access_violation.txt')
    result = parse_analyze_output(lines)
    assert result.raw_text == "\n".join(lines)
