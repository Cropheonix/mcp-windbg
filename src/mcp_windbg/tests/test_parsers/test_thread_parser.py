"""Tests for thread_parser."""

import os
import pytest

from mcp_windbg.parsers.thread_parser import parse_thread_list
from mcp_windbg.models.dump_models import ThreadListResult

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), '..', 'fixtures')


def load_fixture(name: str) -> list:
    path = os.path.join(FIXTURE_DIR, name)
    if not os.path.exists(path):
        pytest.skip(f"Fixture not found: {name}")
    with open(path, 'r', encoding='utf-8') as f:
        return f.read().splitlines()


def test_parse_thread_list_basic():
    """Test basic thread list parsing."""
    lines = load_fixture('thread_list.txt')
    result = parse_thread_list(lines)

    assert isinstance(result, ThreadListResult)
    assert result.raw_text


def test_parse_thread_list_empty():
    """Test parser with empty input."""
    result = parse_thread_list([])
    assert isinstance(result, ThreadListResult)
    assert result.total_count == 0


def test_parse_thread_list_synthetic():
    """Test parsing synthetic thread list output."""
    lines = [
        ".  0  Id: 1234.5678 Suspend: 0 TeB: 00007ff6`12340000 UnfStart 00000000`00000000",
        "   1  Id: 1234.9abc Suspend: 0 TeB: 00007ff6`12350000 UnfStart 00000000`00000000",
    ]
    result = parse_thread_list(lines)

    assert result.total_count == 2
    assert result.current_thread == 0
    assert result.threads[0].is_current is True
    assert result.threads[1].is_current is False
    assert result.threads[0].os_id == "1234.5678"
    assert result.threads[1].suspend_count == 0
