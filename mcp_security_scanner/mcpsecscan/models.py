from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Literal
from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high", "confirmed"]

class Finding(BaseModel):
    id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence = "low"
    category: str
    cwe: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    recommendation: str

class ToolInfo(BaseModel):
    name: str
    description: str | None = None
    input_schema: dict[str, Any] = Field(default_factory=dict)

class ScanTarget(BaseModel):
    name: str
    transport: Literal["stdio", "http"]
    command: str | None = None
    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    bearer: str | None = None
    env: dict[str, str] = Field(default_factory=dict)

class ScanReport(BaseModel):
    scanner: str = "mcpsecscan"
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    target: ScanTarget
    server_info: dict[str, Any] = Field(default_factory=dict)
    tools: list[ToolInfo] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
