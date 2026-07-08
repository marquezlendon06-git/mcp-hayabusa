# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

An MCP (Model Context Protocol) server that wraps the [Hayabusa](https://github.com/Yamato-Security/hayabusa) CLI tool to enable LLM-driven EVTX log analysis, and also serves as a detection engineering knowledge base exposing Sigma rules and ATT&CK technique mappings as browsable MCP resources.

**Goals:**
- Expose a `scan_evtx` MCP tool that runs Hayabusa against EVTX files
- Return results as structured JSON
- Support filtering by severity level (`informational`, `low`, `medium`, `high`, `critical`)
- Handle errors gracefully (missing files, Hayabusa not found, bad output, etc.)
- Expose Sigma rules as browsable MCP resources
- Expose ATT&CK technique mappings as browsable MCP resources
- Allow Claude to query detection coverage across techniques and rules
- Combine detection knowledge base context with live Hayabusa scanning

## Stack

- **Python** with the [`mcp`](https://github.com/modelcontextprotocol/python-sdk) library for the MCP server
- **Hayabusa CLI** installed locally — invoked as a subprocess

## Architecture

The server combines an MCP tool-server with an MCP resource-server:

1. `server.py` — entry point; defines the MCP server and registers both tools and resources
2. `hayabusa.py` (or similar) — subprocess wrapper that invokes the Hayabusa CLI and parses its output into structured JSON
3. The `scan_evtx` tool accepts an EVTX file path and optional severity filter, calls Hayabusa, and returns parsed results
4. Sigma rules in `rules/` are exposed as MCP resources (e.g. `sigma://<rule-id>`)
5. ATT&CK mappings in `mappings/` are exposed as MCP resources (e.g. `attck://<technique-id>`)

Hayabusa is called via `subprocess.run()` with JSON output mode (e.g., `--output-format jsonl` or `--json`). Results are parsed and filtered before being returned to the MCP client.

## Directory Structure

```
rules/       — Sigma detection rules (YAML)
mappings/    — ATT&CK technique-to-rule mappings (YAML or JSON)
hayabusa/    — Hayabusa CLI binary (downloaded by download_hayabusa.py)
server.py    — MCP server: resources (Sigma rules, ATT&CK mappings) + tools (scan_evtx)
hayabusa.py  — Subprocess wrapper for the Hayabusa CLI
```

## Setup

Run `setup.bat` from a fresh checkout. It detects a working Python interpreter,
installs dependencies, downloads the Hayabusa binary (`download_hayabusa.py`)
and ATT&CK technique mappings (`download_stix_data.py`), writes a portable
`run.bat`, and registers the server with Claude Code (`claude mcp add`).

To do it by hand instead:

```powershell
py -m pip install -r requirements.txt
py download_hayabusa.py
py download_stix_data.py
claude mcp add hayabusa "C:\path\to\mcp-hayabusa\run.bat" --scope project -e HAYABUSA_ALLOWED_DIRS="C:\path\to\mcp-hayabusa\samples"
```

Verify with `claude mcp list`. The server uses stdio transport — Claude Code
launches it as a child process; you do not run it manually.

## Running the Server

```powershell
py server.py
```

## Key Conventions

- Hayabusa lives in `./hayabusa/` (downloaded by `download_hayabusa.py`). The binary is named `hayabusa-{version}-{platform}.exe` on Windows. Use the `HAYABUSA_PATH` env var to override; otherwise glob for the exe in `./hayabusa/`
- Severity levels follow Hayabusa's built-in scale: `informational`, `low`, `medium`, `high`, `critical`
- All tool errors should be returned as MCP error responses, not Python exceptions that crash the server
