import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

import yaml

from pydantic import AnyUrl

from mcp.server import Server
from mcp.types import Resource, ResourceTemplate, TextContent, TextResourceContents, Tool

server = Server("hayabusa-mcp")

SEVERITY_LEVELS = ["informational", "low", "medium", "high", "critical"]
OUTPUT_FORMATS = ["summary", "full"]
_SUMMARY_EXCLUDE = {"ExtraFieldInfo", "RuleID"}

DEFAULT_SCAN_TIMEOUT_SECONDS = 300
DEFAULT_ALLOWED_DIRS = [Path(__file__).parent / "samples"]


def get_allowed_dirs() -> list[Path]:
    """Directories scan_evtx is permitted to read from.

    Configurable via HAYABUSA_ALLOWED_DIRS (os.pathsep-separated). Defaults to
    ./samples so the server can't be pointed at arbitrary filesystem paths.
    """
    env = os.environ.get("HAYABUSA_ALLOWED_DIRS")
    if env:
        return [Path(p).resolve() for p in env.split(os.pathsep) if p]
    return [d.resolve() for d in DEFAULT_ALLOWED_DIRS]


def _is_within_allowed(target: Path, allowed_dirs: list[Path]) -> bool:
    resolved = target.resolve()
    for root in allowed_dirs:
        if resolved == root or root in resolved.parents:
            return True
    return False


def find_hayabusa() -> Path:
    if env := os.environ.get("HAYABUSA_PATH"):
        p = Path(env)
        if p.is_file():
            return p
        raise FileNotFoundError(f"HAYABUSA_PATH set but not found: {env}")

    ext = ".exe" if sys.platform == "win32" else ""
    base = Path(__file__).parent / "hayabusa"

    stable = base / f"hayabusa{ext}"
    if stable.is_file():
        return stable

    matches = list(base.glob(f"hayabusa-*{ext}"))
    if matches:
        return matches[0]

    raise FileNotFoundError(
        f"Hayabusa binary not found in {base}. "
        "Run download_hayabusa.py or set HAYABUSA_PATH."
    )


RULES_DIR = Path(__file__).parent / "rules"
ATTCK_FILE = Path(__file__).parent / "mappings" / "attck_techniques.json"

_attck_cache: dict | None = None


def _load_rule_meta(yml_file: Path) -> dict:
    with open(yml_file, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    tags = data.get("tags") or []
    techniques = [t for t in tags if t.startswith("attack.t")]
    description = str(data.get("description", "")).strip().replace("\n", " ")
    return {
        "name": yml_file.stem,
        "title": data.get("title", ""),
        "description": description,
        "level": data.get("level", ""),
        "status": data.get("status", ""),
        "tags": tags,
        "techniques": techniques,
        "uri": f"detection://rules/{yml_file.stem}",
    }


def _iter_rules() -> list[dict]:
    if not RULES_DIR.is_dir():
        return []
    return [_load_rule_meta(f) for f in sorted(RULES_DIR.glob("*.yml"))]


def _load_attck() -> dict:
    global _attck_cache
    if _attck_cache is None:
        if not ATTCK_FILE.is_file():
            raise FileNotFoundError(
                f"ATT&CK data not found at {ATTCK_FILE}. "
                "Run: py download_stix_data.py"
            )
        _attck_cache = json.loads(ATTCK_FILE.read_text(encoding="utf-8"))
    return _attck_cache


def _sigma_tag_to_attck_id(tag: str) -> str:
    """Convert a Sigma ATT&CK tag like 'attack.t1003.001' to 'T1003.001'."""
    return tag.removeprefix("attack.").upper()


def _rules_for_technique(technique_id: str) -> list[dict]:
    """Return rules whose technique tags include the given ATT&CK ID (case-insensitive)."""
    needle = technique_id.upper()
    return [
        r for r in _iter_rules()
        if needle in [_sigma_tag_to_attck_id(t) for t in r["techniques"]]
    ]


def _coverage(rules: list[dict]) -> str:
    if len(rules) == 0:
        return "gap"
    if len(rules) == 1:
        return "partial"
    return "covered"


def _apply_filters(
    findings: list[dict],
    rule_filter: str | None,
    output_format: str,
    max_results: int | None,
) -> list[dict]:
    if rule_filter:
        needle = rule_filter.lower()
        findings = [f for f in findings if needle in f.get("RuleTitle", "").lower()]

    if output_format == "summary":
        findings = [{k: v for k, v in f.items() if k not in _SUMMARY_EXCLUDE} for f in findings]

    if max_results is not None:
        findings = findings[:max_results]

    return findings


def list_hayabusa_rules(keyword: str | None = None) -> list[dict]:
    rules_dir = Path(__file__).parent / "hayabusa" / "rules"
    if not rules_dir.is_dir():
        raise FileNotFoundError(f"Rules directory not found: {rules_dir}")

    needle = keyword.lower().replace("-", " ") if keyword else None
    results = []

    for yml_file in sorted(rules_dir.rglob("*.yml")):
        try:
            with open(yml_file, encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception:
            continue

        if not isinstance(data, dict) or "title" not in data:
            continue

        title = str(data.get("title", ""))
        description = str(data.get("description", ""))
        tags = data.get("tags") or []
        tags_str = " ".join(str(t) for t in tags)

        haystack = f"{title} {description} {tags_str}".lower().replace("-", " ")
        if needle and needle not in haystack:
            continue

        results.append({
            "title": title,
            "id": data.get("id", ""),
            "level": data.get("level", ""),
            "status": data.get("status", ""),
            "description": description,
            "tags": tags,
            "ruletype": data.get("ruletype", ""),
            "path": str(yml_file.relative_to(Path(__file__).parent)),
        })

    return results


async def run_hayabusa(evtx_path: str, min_severity: str) -> list[dict]:
    if min_severity not in SEVERITY_LEVELS:
        raise ValueError(
            f"Invalid severity '{min_severity}'. Must be one of: {', '.join(SEVERITY_LEVELS)}"
        )

    target = Path(evtx_path)
    if not target.exists():
        raise FileNotFoundError(f"EVTX path not found: {evtx_path}")

    allowed_dirs = get_allowed_dirs()
    if not _is_within_allowed(target, allowed_dirs):
        raise PermissionError(
            f"'{evtx_path}' is outside the allowed scan directories "
            f"({', '.join(str(d) for d in allowed_dirs)}). "
            "Set HAYABUSA_ALLOWED_DIRS to permit additional paths."
        )

    hayabusa = find_hayabusa()
    input_flag = "-d" if target.is_dir() else "-f"

    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".jsonl")
    os.close(tmp_fd)

    try:
        cmd = [
            str(hayabusa),
            "json-timeline",
            input_flag, str(target),
            "-L",              # JSONL: one JSON object per line, easy to parse
            "-o", tmp_path,
            "--min-level", min_severity,
            "--no-wizard",
            "-q",
            "-N",
            "--ISO-8601",
            "-C",
        ]

        timeout = float(os.environ.get("HAYABUSA_TIMEOUT_SECONDS", DEFAULT_SCAN_TIMEOUT_SECONDS))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(hayabusa.parent),
        )
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise TimeoutError(f"Hayabusa scan timed out after {timeout:.0f}s: {evtx_path}")

        if proc.returncode != 0:
            raise RuntimeError(
                f"Hayabusa exited with code {proc.returncode}: {stderr.decode().strip()}"
            )

        out = Path(tmp_path)
        if not out.exists() or out.stat().st_size == 0:
            return []

        findings = []
        with open(out, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    findings.append(json.loads(line))
        return findings

    finally:
        Path(tmp_path).unlink(missing_ok=True)


@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="scan_evtx",
            description="Scan an EVTX file with Hayabusa to detect suspicious activity",
            inputSchema={
                "type": "object",
                "properties": {
                    "evtx_path": {
                        "type": "string",
                        "description": "Path to the EVTX file or directory of EVTX files to scan"
                    },
                    "min_severity": {
                        "type": "string",
                        "enum": SEVERITY_LEVELS,
                        "description": "Minimum severity level to include",
                        "default": "medium"
                    },
                    "rule_filter": {
                        "type": "string",
                        "description": "Case-insensitive substring to match against RuleTitle (e.g. 'lateral' or 'mimikatz')"
                    },
                    "output_format": {
                        "type": "string",
                        "enum": OUTPUT_FORMATS,
                        "description": "Summary omits ExtraFieldInfo and RuleID; full returns every field",
                        "default": "summary"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of findings to return",
                        "minimum": 1
                    }
                },
                "required": ["evtx_path"]
            }
        ),
        Tool(
            name="get_hayabusa_rules",
            description="List available Hayabusa detection rules, optionally filtered by keyword. Use this to discover what rules exist before scanning.",
            inputSchema={
                "type": "object",
                "properties": {
                    "keyword": {
                        "type": "string",
                        "description": "Case-insensitive keyword to match against rule title, description, or tags (e.g. 'lateral', 'mimikatz', 't1059')"
                    }
                },
                "required": []
            }
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "get_hayabusa_rules":
        keyword = arguments.get("keyword") or None
        try:
            rules = list_hayabusa_rules(keyword)
            result = {
                "keyword": keyword,
                "total_rules": len(rules),
                "rules": rules,
            }
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
        except FileNotFoundError as e:
            return [TextContent(type="text", text=json.dumps({"error": "not_found", "message": str(e)}))]

    if name != "scan_evtx":
        raise ValueError(f"Unknown tool: {name}")

    evtx_path = arguments.get("evtx_path", "")
    min_severity = arguments.get("min_severity", "medium")
    rule_filter = arguments.get("rule_filter") or None
    output_format = arguments.get("output_format", "summary")
    max_results = arguments.get("max_results") or None

    if output_format not in OUTPUT_FORMATS:
        return [TextContent(type="text", text=json.dumps({
            "error": "invalid_argument",
            "message": f"output_format must be one of: {', '.join(OUTPUT_FORMATS)}"
        }))]

    try:
        findings = await run_hayabusa(evtx_path, min_severity)
        findings = _apply_filters(findings, rule_filter, output_format, max_results)
        result = {
            "evtx_path": evtx_path,
            "min_severity": min_severity,
            "rule_filter": rule_filter,
            "output_format": output_format,
            "total_findings": len(findings),
            "findings": findings,
        }
        return [TextContent(type="text", text=json.dumps(result, indent=2))]

    except FileNotFoundError as e:
        return [TextContent(type="text", text=json.dumps({"error": "not_found", "message": str(e)}))]
    except PermissionError as e:
        return [TextContent(type="text", text=json.dumps({"error": "forbidden", "message": str(e)}))]
    except TimeoutError as e:
        return [TextContent(type="text", text=json.dumps({"error": "timeout", "message": str(e)}))]
    except RuntimeError as e:
        return [TextContent(type="text", text=json.dumps({"error": "scan_failed", "message": str(e)}))]
    except ValueError as e:
        return [TextContent(type="text", text=json.dumps({"error": "invalid_argument", "message": str(e)}))]


@server.list_resources()
async def list_resources():
    resources = [
        Resource(
            uri=AnyUrl("detection://rules"),
            name="Detection Rules Index",
            description="Index of all available Sigma detection rules with metadata",
            mimeType="application/json",
        )
    ]
    for rule in _iter_rules():
        resources.append(Resource(
            uri=AnyUrl(rule["uri"]),
            name=rule["title"],
            description=f"[{rule['level'].upper()}] {rule['description'][:120]}",
            mimeType="text/yaml",
        ))
    return resources


@server.list_resource_templates()
async def list_resource_templates():
    return [
        ResourceTemplate(
            uriTemplate="detection://rules/by-technique/{technique_id}",
            name="Rules by ATT&CK Technique",
            description=(
                "List detection rules tagged for a given ATT&CK technique. "
                "Use the sub-technique ID form, e.g. t1003.001 or t1558.003."
            ),
            mimeType="application/json",
        ),
        ResourceTemplate(
            uriTemplate="detection://attack/techniques/{technique_id}",
            name="ATT&CK Technique Coverage",
            description=(
                "Technique name, description, and detection coverage from our Sigma rules. "
                "Returns coverage assessment: covered (2+ rules), partial (1 rule), gap (0 rules). "
                "Example: detection://attack/techniques/T1003.001"
            ),
            mimeType="application/json",
        ),
    ]


@server.read_resource()
async def read_resource(uri: AnyUrl):
    uri_str = str(uri)

    if uri_str == "detection://rules":
        rules = _iter_rules()
        payload = {"total": len(rules), "rules": rules}
        return [TextResourceContents(uri=uri, mimeType="application/json", text=json.dumps(payload, indent=2))]

    if uri_str.startswith("detection://rules/by-technique/"):
        technique_id = uri_str.removeprefix("detection://rules/by-technique/").lower()
        matched = [r for r in _iter_rules() if any(technique_id in t for t in r["techniques"])]
        payload = {"technique_id": technique_id, "total": len(matched), "rules": matched}
        return [TextResourceContents(uri=uri, mimeType="application/json", text=json.dumps(payload, indent=2))]

    if uri_str.startswith("detection://rules/"):
        rule_name = uri_str.removeprefix("detection://rules/")
        rules_dir = RULES_DIR.resolve()
        rule_file = (rules_dir / f"{rule_name}.yml").resolve()
        if not _is_within_allowed(rule_file, [rules_dir]) or not rule_file.is_file():
            raise FileNotFoundError(f"Rule not found: {rule_name}")
        return [TextResourceContents(uri=uri, mimeType="text/yaml", text=rule_file.read_text(encoding="utf-8"))]

    if uri_str.startswith("detection://attack/techniques/"):
        raw_id = uri_str.removeprefix("detection://attack/techniques/")
        technique_id = raw_id.upper()

        try:
            attck = _load_attck()
        except FileNotFoundError as exc:
            raise FileNotFoundError(str(exc)) from exc

        technique = attck.get(technique_id)
        if technique is None:
            raise FileNotFoundError(
                f"ATT&CK technique '{technique_id}' not found. "
                "Check the ID format (e.g. T1003.001) or re-run download_stix_data.py."
            )

        rules = _rules_for_technique(technique_id)
        rule_summaries = [
            {
                "name": r["name"],
                "title": r["title"],
                "level": r["level"],
                "uri": r["uri"],
            }
            for r in rules
        ]

        payload = {
            "technique": technique,
            "detection": {
                "coverage": _coverage(rules),
                "rule_count": len(rules),
                "rules": rule_summaries,
            },
        }
        return [TextResourceContents(uri=uri, mimeType="application/json", text=json.dumps(payload, indent=2))]

    raise ValueError(f"Unknown resource URI: {uri_str}")


async def main():
    from mcp.server.stdio import stdio_server
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
