"""Tests for module_parser."""

import os
import pytest

from mcp_windbg.parsers.module_parser import parse_module_list, _is_system_module
from mcp_windbg.models.dump_models import ModuleListResult

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), '..', 'fixtures')


def load_fixture(name: str) -> list:
    path = os.path.join(FIXTURE_DIR, name)
    if not os.path.exists(path):
        pytest.skip(f"Fixture not found: {name}")
    with open(path, 'r', encoding='utf-8') as f:
        return f.read().splitlines()


def test_is_system_module():
    """Test system module identification."""
    assert _is_system_module("ntdll") is True
    assert _is_system_module("kernel32") is True
    assert _is_system_module("ucrtbase") is True
    assert _is_system_module("MyApp") is False
    assert _is_system_module("DemoCrash1") is False


def test_parse_module_list_basic():
    """Test basic module list parsing."""
    lines = load_fixture('lm_with_symbols.txt')
    result = parse_module_list(lines)

    assert isinstance(result, ModuleListResult)
    assert result.total_count > 0
    assert len(result.modules) > 0
    assert result.raw_text


def test_parse_module_list_empty():
    """Test parser with empty input."""
    result = parse_module_list([])
    assert isinstance(result, ModuleListResult)
    assert result.total_count == 0


def test_parse_module_list_has_module_info():
    """Test that modules have basic info."""
    lines = load_fixture('lm_with_symbols.txt')
    result = parse_module_list(lines)

    if result.modules:
        mod = result.modules[0]
        assert mod.name is not None
        assert mod.base_address is not None
