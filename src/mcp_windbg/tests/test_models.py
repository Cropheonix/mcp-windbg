"""Tests for response_models tiered output."""

import json
import pytest

from mcp_windbg.models.response_models import (
    TieredResponse,
    OutputTier,
    tiered_to_text_content,
)


def test_summary_tier():
    """Test summary tier returns just summary text."""
    response = TieredResponse(
        summary="Test crash summary",
        structured={"key": "value"},
    )
    result = tiered_to_text_content(response, "summary")
    assert result.text == "Test crash summary"
    assert result.type == "text"


def test_structured_tier():
    """Test structured tier returns summary + JSON."""
    response = TieredResponse(
        summary="Test summary",
        structured={"exception_code": "0xC0000005"},
    )
    result = tiered_to_text_content(response, "structured")

    assert "Test summary" in result.text
    assert "0xC0000005" in result.text
    assert "```json" in result.text


def test_raw_excerpt_tier():
    """Test raw_excerpt tier includes excerpt."""
    response = TieredResponse(
        summary="Test",
        structured={"key": "val"},
        raw_excerpt="raw output excerpt here",
    )
    result = tiered_to_text_content(response, "raw_excerpt")

    assert "raw output excerpt here" in result.text
    assert "### Raw Excerpt" in result.text


def test_raw_full_tier():
    """Test raw_full tier includes full output."""
    response = TieredResponse(
        summary="Test",
        structured={"key": "val"},
        raw_full="full raw output here",
    )
    result = tiered_to_text_content(response, "raw_full")

    assert "full raw output here" in result.text
    assert "### Full Output" in result.text


def test_structured_none():
    """Test that missing structured data is handled."""
    response = TieredResponse(summary="Just a summary")
    result = tiered_to_text_content(response, "structured")

    assert "Just a summary" in result.text
    assert "```json" not in result.text


def test_output_tier_enum():
    """Test OutputTier enum values."""
    assert OutputTier.SUMMARY == "summary"
    assert OutputTier.STRUCTURED == "structured"
    assert OutputTier.RAW_EXCERPT == "raw_excerpt"
    assert OutputTier.RAW_FULL == "raw_full"


def test_chinese_content():
    """Test that Chinese content is properly handled in JSON output."""
    response = TieredResponse(
        summary="测试崩溃分析",
        structured={"异常类型": "访问违规"},
    )
    result = tiered_to_text_content(response, "structured")

    assert "测试崩溃分析" in result.text
    assert "访问违规" in result.text
