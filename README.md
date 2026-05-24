# MCP Security Scanner

A starter security scanner for Model Context Protocol servers. It enumerates MCP tools and reports potential security risks, misconfigurations, and weak schemas.

**In Progress*. Long wishlist of improvements to come.

## Install

```powershell
pip install -e .
```

## Basic usage

From the project root:

```powershell
mcpsecscan stdio mock "python examples/mock_mcp_server.py"
```

Scan an HTTP MCP endpoint:

```powershell
mcpsecscan http localtest "http://127.0.0.1:8000/mcp"
```

Scan with bearer auth:

```powershell
mcpsecscan http mytarget "https://example.com/mcp" --bearer "TOKEN_HERE"
```

## Output formats

The scanner supports JSON, CSV, SARIF, Excel, and ZIP bundle output.

```powershell
mcpsecscan stdio mock "python examples/mock_mcp_server.py" --json report.json --csv findings.csv --sarif findings.sarif --excel findings.xlsx --zip findings-bundle.zip
```

When `--zip` is provided, generated reports are written into the ZIP only (not duplicated as standalone files in the project folder).

Defaults:

- `--out report.json` remains supported and writes a full JSON report by default.
- `--json report.json` explicitly writes JSON output.
- `--csv findings.csv` writes a spreadsheet-friendly CSV when provided.
- `--sarif findings.sarif` writes SARIF 2.1.0 when provided.
- `--excel findings.xlsx` writes a formatted Excel workbook with:
  - `Risk Summary` sheet (totals and severity breakdown)
  - `Findings` sheet (CSV-like data with a bold, colored header row)
- `--zip findings-bundle.zip` writes a ZIP containing all generated output files from the run.
  - The ZIP also includes `manifest.json` with file names, sizes, and SHA-256 checksums.

Example bash usage:

```bash
mcpsecscan http mytarget "https://example.com/mcp" \
  --json report.json \
  --csv findings.csv \
  --sarif findings.sarif \
  --excel findings.xlsx \
  --zip findings-bundle.zip
```

## GitHub Action (PR + reusable workflow)

The project includes [.github/workflows/mcp-security-scan.yml](.github/workflows/mcp-security-scan.yml).

- On pull requests to `main`, it runs a scan and publishes JSON/CSV/SARIF/Excel outputs plus a ZIP bundle artifact.
- SARIF is extracted from the ZIP bundle and uploaded via `github/codeql-action/upload-sarif` for GitHub Advanced Security code scanning ingestion.
- It can also be called as a reusable workflow (`workflow_call`) or run manually (`workflow_dispatch`) with options for:
  - transport/target settings
  - enabling/disabling JSON, CSV, SARIF, Excel, and ZIP generation
  - custom output file paths

## Finding fields

Each finding includes:

- `severity`: info, low, medium, high, critical
- `confidence`: low, medium, high, confirmed
- `category`: authentication, transport, capability, input-validation, configuration, tool-poisoning
- `description`: analyst-friendly explanation of what was detected
- `evidence`: matched tool, keyword, parameter, HTTP status, or other proof
- `recommendation`: remediation guidance
- `cwe`: related CWE where applicable

## Important note

Most current checks are heuristic. A finding such as `file_access` means the tool appears to expose that capability based on metadata. It is not automatically a confirmed vulnerability until active validation proves abuse is possible.
