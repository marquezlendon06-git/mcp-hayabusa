"""
Downloads ATT&CK STIX data and extracts technique metadata into mappings/attck_techniques.json.
Run once before starting the server:
    py download_attack_data.py
"""
import json
import re
import sys
import urllib.request
from pathlib import Path

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/master/enterprise-attack/enterprise-attack.json"
)
OUT_FILE = Path(__file__).parent / "mappings" / "attck_techniques.json"

_CITATION_RE = re.compile(r"\(Citation:[^)]+\)")


def _clean_description(text: str) -> str:
    """Return first paragraph of a STIX description, citations stripped."""
    text = _CITATION_RE.sub("", text).strip()
    first = text.split("\n\n")[0].strip()
    # Collapse any double-spaces left by citation removal
    return re.sub(r"  +", " ", first)


def main() -> None:
    print(f"Fetching ATT&CK STIX data from GitHub ...", flush=True)
    with urllib.request.urlopen(STIX_URL) as resp:
        raw = resp.read()
    print(f"Downloaded {len(raw) / 1_048_576:.1f} MB — parsing ...", flush=True)

    bundle = json.loads(raw)
    objects = bundle.get("objects", [])
    print(f"Total STIX objects: {len(objects)}", flush=True)

    techniques: dict[str, dict] = {}

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        ext_refs = obj.get("external_references", [])
        attck_ref = next(
            (r for r in ext_refs if r.get("source_name") == "mitre-attack"), None
        )
        if not attck_ref:
            continue

        attck_id: str = attck_ref.get("external_id", "")
        if not attck_id.startswith("T"):
            continue

        tactics = [
            p["phase_name"]
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]

        is_sub = bool(obj.get("x_mitre_is_subtechnique"))
        parent_id = attck_id.rsplit(".", 1)[0] if is_sub else None

        techniques[attck_id] = {
            "id": attck_id,
            "name": obj.get("name", ""),
            "description": _clean_description(obj.get("description", "")),
            "tactics": tactics,
            "is_subtechnique": is_sub,
            "parent_id": parent_id,
            "url": attck_ref.get("url", ""),
        }

    OUT_FILE.parent.mkdir(exist_ok=True)
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(techniques, f, indent=2)

    size_kb = OUT_FILE.stat().st_size / 1024
    print(f"Saved {len(techniques)} techniques -> {OUT_FILE}  ({size_kb:.0f} KB)")


if __name__ == "__main__":
    main()
