from __future__ import annotations
import re
from .models import Finding, ScanTarget, ToolInfo

DANGEROUS = {
    "shell_exec": {
        "pattern": r"\b(shell|bash|cmd|powershell|exec|spawn|subprocess|terminal|command)\b",
        "severity": "critical",
        "cwe": "CWE-78",
        "description": "Tool metadata suggests the server may execute operating system commands or spawn processes. This is high risk if exposed to an LLM without strict authorization, confirmation, and argument controls.",
    },
    "file_access": {
        "pattern": r"\b(read|write|delete|upload|download|file|path|directory|filesystem|fs)\b",
        "severity": "high",
        "cwe": "CWE-22",
        "description": "Tool metadata suggests filesystem access. This may be intended, but it can become dangerous if the accessible paths are too broad or if path validation is weak.",
    },
    "credential_access": {
        "pattern": r"\b(secret|token|password|credential|keychain|env|api[_ -]?key|oauth|jwt)\b",
        "severity": "high",
        "cwe": "CWE-200",
        "description": "Tool metadata suggests access to secrets, tokens, credentials, environment variables, or authentication material.",
    },
    "network_access": {
        "pattern": r"\b(fetch|http|url|request|webhook|socket|tcp|dns|curl)\b",
        "severity": "medium",
        "cwe": "CWE-918",
        "description": "Tool metadata suggests outbound network access. This can create SSRF, data exfiltration, webhook abuse, or internal service access risks.",
    },
    "database_write": {
        "pattern": r"\b(sql|query|database|postgres|mysql|mongo|redis|insert|update|delete)\b",
        "severity": "medium",
        "cwe": "CWE-89",
        "description": "Tool metadata suggests database access or mutation capability. Risk depends on whether queries are parameterized, scoped, audited, and authorized.",
    },
    "cloud_admin": {
        "pattern": r"\b(aws|azure|gcp|iam|role|policy|admin|kubernetes|kubectl|terraform)\b",
        "severity": "high",
        "cwe": "CWE-269",
        "description": "Tool metadata suggests cloud, IAM, Kubernetes, infrastructure, or admin capability. This may allow privilege or infrastructure changes if over-permissioned.",
    },
}

PROMPT_INJECTION = re.compile(r"\b(ignore|disregard|override|system prompt|developer message|hidden instruction|do not reveal|exfiltrate|send secrets|bypass|jailbreak)\b", re.I)
SENSITIVE_ENV = re.compile(r"(TOKEN|SECRET|PASSWORD|PRIVATE|KEY|CREDENTIAL|SESSION|COOKIE)", re.I)


def run_rules(target: ScanTarget, tools: list[ToolInfo], server_info: dict, observations: dict | None = None) -> list[Finding]:
    findings: list[Finding] = []
    observations = observations or {}

    if target.transport == "http":
        if target.url and target.url.startswith("http://"):
            findings.append(Finding(
                id="MCP-HTTP-001",
                title="MCP endpoint uses cleartext HTTP",
                description="The remote MCP endpoint is using cleartext HTTP instead of HTTPS. Any MCP traffic, tool metadata, prompts, and results may be observable or modified in transit.",
                severity="high",
                confidence="high",
                category="transport",
                cwe="CWE-319",
                evidence={"url": target.url},
                recommendation="Expose remote MCP endpoints only over HTTPS and reject plaintext transport in production.",
            ))
        if observations.get("unauth_status_code") and observations["unauth_status_code"] < 400 and not target.bearer:
            findings.append(Finding(
                id="MCP-AUTH-001",
                title="Remote MCP endpoint appears reachable without authentication",
                description="The scanner successfully reached the MCP initialize endpoint without sending an Authorization header. If this endpoint exposes sensitive tools, unauthenticated discovery or use may be possible.",
                severity="critical",
                confidence="high",
                category="authentication",
                cwe="CWE-306",
                evidence={
                    "unauth_status_code": observations["unauth_status_code"],
                    "www_authenticate": observations.get("unauth_www_authenticate"),
                },
                recommendation="Require authentication and authorization for remote MCP servers. Do not allow unauthenticated initialize or tools/list on internet-facing endpoints.",
            ))

    for k in target.env.keys():
        if SENSITIVE_ENV.search(k):
            findings.append(Finding(
                id="MCP-CONFIG-001",
                title="Sensitive-looking environment variable provided to MCP server",
                description="The MCP server process receives an environment variable whose name looks secret-bearing. Environment scoping issues can accidentally expose credentials to tools or subprocesses.",
                severity="medium",
                confidence="medium",
                category="configuration",
                cwe="CWE-522",
                evidence={"env_var": k},
                recommendation="Minimize server environment scope. Prefer short-lived scoped tokens and secret managers. Avoid passing broad user/session environment variables to MCP servers.",
            ))

    for tool in tools:
        text = f"{tool.name} {tool.description or ''}"
        if PROMPT_INJECTION.search(text):
            findings.append(Finding(
                id="MCP-TOOL-001",
                title="Tool metadata contains prompt-injection-like language",
                description="The tool name or description contains language commonly associated with prompt injection or tool poisoning. Tool metadata should describe behavior, not instruct the model to ignore or override policy/context.",
                severity="high",
                confidence="medium",
                category="tool-poisoning",
                cwe="CWE-94",
                evidence={"tool": tool.name, "description": tool.description},
                recommendation="Treat tool metadata as untrusted. Remove instructions that try to influence the model outside the tool contract and review the server source before enabling it.",
            ))
        for key, rule in DANGEROUS.items():
            match = re.search(rule["pattern"], text, re.I)
            if match:
                findings.append(Finding(
                    id=f"MCP-CAP-{key.upper()}",
                    title=f"Tool exposes sensitive capability: {key.replace('_',' ')}",
                    description=rule["description"],
                    severity=rule["severity"],
                    confidence="low",
                    category="capability",
                    cwe=rule["cwe"],
                    evidence={
                        "tool": tool.name,
                        "matched_keyword": match.group(0),
                        "matched_text": text[:500],
                    },
                    recommendation="Gate this tool with least privilege, user confirmation for dangerous actions, audit logging, and strict argument validation. Confirm behavior with active testing before treating this as an exploitable vulnerability.",
                ))
        findings.extend(inspect_schema(tool))
    return dedupe(findings)


def inspect_schema(tool: ToolInfo) -> list[Finding]:
    f: list[Finding] = []
    schema = tool.input_schema or {}
    props = schema.get("properties", {}) if isinstance(schema, dict) else {}
    required = set(schema.get("required", [])) if isinstance(schema, dict) else set()
    if isinstance(schema, dict) and schema.get("additionalProperties") is True:
        f.append(Finding(
            id="MCP-SCHEMA-001",
            title="Tool input schema allows arbitrary additional properties",
            description="The tool schema allows callers to provide extra fields that are not explicitly defined. This can make validation ambiguous and may allow unexpected behavior server-side.",
            severity="medium",
            confidence="medium",
            category="input-validation",
            cwe="CWE-20",
            evidence={"tool": tool.name},
            recommendation="Set additionalProperties:false and strictly validate tool arguments server-side.",
        ))
    for name, prop in props.items():
        blob = f"{name} {prop}"
        if re.search(r"\b(path|file|url|command|query|script)\b", blob, re.I) and name not in required:
            f.append(Finding(
                id="MCP-SCHEMA-002",
                title="Sensitive parameter is optional or weakly constrained",
                description="A parameter name or schema looks security-sensitive, but it is not listed as required. Optional sensitive parameters can indicate ambiguous server-side defaults or inconsistent validation.",
                severity="low",
                confidence="low",
                category="input-validation",
                cwe="CWE-20",
                evidence={"tool": tool.name, "parameter": name},
                recommendation="Make sensitive parameters explicit, typed, constrained, and validated server-side. Document safe defaults clearly.",
            ))
        if isinstance(prop, dict) and prop.get("type") == "string" and not any(k in prop for k in ["enum", "pattern", "format", "maxLength"]):
            if re.search(r"\b(command|query|path|url|script|prompt)\b", name, re.I):
                f.append(Finding(
                    id="MCP-SCHEMA-003",
                    title="High-risk string parameter lacks constraints",
                    description="A high-risk string parameter does not define common constraints such as enum, pattern, format, or maxLength. The server may still validate internally, but the MCP schema does not communicate those constraints to clients.",
                    severity="medium",
                    confidence="low",
                    category="input-validation",
                    cwe="CWE-20",
                    evidence={"tool": tool.name, "parameter": name, "schema": prop},
                    recommendation="Add allowlists, regex patterns, maxLength, format constraints, and server-side normalization for high-risk strings.",
                ))
    return f


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen = set(); out = []
    for x in findings:
        key = (x.id, str(x.evidence))
        if key not in seen:
            seen.add(key); out.append(x)
    return out
