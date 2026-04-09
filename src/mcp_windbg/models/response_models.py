"""Output tiering models for MCP tool responses."""

import json
from enum import Enum
from typing import Optional

from pydantic import BaseModel

from mcp.types import TextContent


class OutputTier(str, Enum):
    """Output detail levels for tool responses."""
    SUMMARY = "summary"           # 1-2 sentence human-readable summary
    STRUCTURED = "structured"     # Parsed JSON body
    RAW_EXCERPT = "raw_excerpt"   # Relevant 20-50 lines of raw CDB output
    RAW_FULL = "raw_full"         # Complete raw output


class TieredResponse(BaseModel):
    """A tiered response that adapts output based on requested detail level."""
    summary: str
    structured: Optional[dict] = None
    raw_excerpt: Optional[str] = None
    raw_full: Optional[str] = None


def tiered_to_text_content(response: TieredResponse, detail_level: str = "structured") -> TextContent:
    """Convert a TieredResponse to TextContent based on the requested detail level.

    Args:
        response: The tiered response to convert.
        detail_level: One of "summary", "structured", "raw_excerpt", "raw_full".

    Returns:
        TextContent with the appropriate level of detail.
    """
    if detail_level == "summary":
        return TextContent(type="text", text=response.summary)

    elif detail_level == "raw_excerpt":
        parts = [response.summary]
        if response.structured:
            parts.append("\n\n```json\n")
            parts.append(json.dumps(response.structured, indent=2, ensure_ascii=False))
            parts.append("\n```")
        if response.raw_excerpt:
            parts.append("\n\n### Raw Excerpt\n```\n")
            parts.append(response.raw_excerpt)
            parts.append("\n```")
        return TextContent(type="text", text="".join(parts))

    elif detail_level == "raw_full":
        parts = [response.summary]
        if response.structured:
            parts.append("\n\n```json\n")
            parts.append(json.dumps(response.structured, indent=2, ensure_ascii=False))
            parts.append("\n```")
        if response.raw_full:
            parts.append("\n\n### Full Output\n```\n")
            parts.append(response.raw_full)
            parts.append("\n```")
        return TextContent(type="text", text="".join(parts))

    else:  # "structured" (default)
        parts = [response.summary]
        if response.structured:
            parts.append("\n\n```json\n")
            parts.append(json.dumps(response.structured, indent=2, ensure_ascii=False))
            parts.append("\n```")
        return TextContent(type="text", text="".join(parts))
