"""Smoke tests for all MCP resource endpoints."""
import sys, json, asyncio
sys.path.insert(0, ".")
from pydantic import AnyUrl
from server import (
    _iter_rules, _load_attck, _rules_for_technique, _coverage,
    _sigma_tag_to_attck_id, RULES_DIR, ATTCK_FILE, read_resource,
)

PASS = "PASS"
FAIL = "FAIL"
results = []

def check(label, condition, detail=""):
    status = PASS if condition else FAIL
    results.append((status, label, detail))
    print(f"[{status}] {label}" + (f"  — {detail}" if detail else ""))


# ── Rules directory ──────────────────────────────────────────────────────────
rules = _iter_rules()
check("rules/ directory exists", RULES_DIR.is_dir())
check("6 rules loaded", len(rules) == 6, f"got {len(rules)}")

levels = {r["name"]: r["level"] for r in rules}
check("DCSync is critical",   levels.get("cred_access_dcsync_replication_rights") == "critical")
check("LSASS dump is critical", levels.get("cred_access_lsass_dump_via_known_tools") == "critical")
check("PtH is medium",        levels.get("lateral_movement_pass_the_hash_ntlm_logon") == "medium")

# ── ATT&CK cache ─────────────────────────────────────────────────────────────
attck = _load_attck()
check("mappings/attck_techniques.json exists", ATTCK_FILE.is_file())
check("697 techniques loaded", len(attck) == 697, f"got {len(attck)}")

# ── Tag conversion ───────────────────────────────────────────────────────────
check("tag conversion t1003.001", _sigma_tag_to_attck_id("attack.t1003.001") == "T1003.001")
check("tag conversion t1550.002", _sigma_tag_to_attck_id("attack.t1550.002") == "T1550.002")

# ── Coverage logic ───────────────────────────────────────────────────────────
cases = [
    ("T1003.001", "covered",  2),
    ("T1558.003", "covered",  2),
    ("T1003.006", "partial",  1),
    ("T1550.002", "partial",  1),
    ("T1059.001", "gap",      0),
]
for tid, expected_cov, expected_count in cases:
    r = _rules_for_technique(tid)
    cov = _coverage(r)
    check(
        f"coverage {tid}",
        cov == expected_cov and len(r) == expected_count,
        f"coverage={cov!r} rules={[x['name'] for x in r]}"
    )

# ── Resource read (async) ─────────────────────────────────────────────────────
async def test_resources():
    # detection://rules index
    res = await read_resource(AnyUrl("detection://rules"))
    data = json.loads(res[0].text)
    check("detection://rules total=6", data["total"] == 6, f"got {data['total']}")

    # detection://rules/{name}
    res = await read_resource(AnyUrl("detection://rules/cred_access_dcsync_replication_rights"))
    check("detection://rules/{name} returns YAML", "DCSync" in res[0].text)

    # detection://rules/by-technique/t1003.001
    res = await read_resource(AnyUrl("detection://rules/by-technique/t1003.001"))
    data = json.loads(res[0].text)
    check("by-technique t1003.001 returns 2 rules", data["total"] == 2, f"got {data['total']}")

    # detection://attack/techniques/T1003.001
    res = await read_resource(AnyUrl("detection://attack/techniques/T1003.001"))
    data = json.loads(res[0].text)
    check("technique T1003.001 name", data["technique"]["name"] == "LSASS Memory",
          data["technique"]["name"])
    check("technique T1003.001 coverage=covered", data["detection"]["coverage"] == "covered",
          data["detection"]["coverage"])

    # detection://attack/techniques/T1003.006 (partial)
    res = await read_resource(AnyUrl("detection://attack/techniques/T1003.006"))
    data = json.loads(res[0].text)
    check("technique T1003.006 coverage=partial", data["detection"]["coverage"] == "partial",
          data["detection"]["coverage"])

    # detection://attack/techniques/T1059.001 (gap)
    res = await read_resource(AnyUrl("detection://attack/techniques/T1059.001"))
    data = json.loads(res[0].text)
    check("technique T1059.001 coverage=gap", data["detection"]["coverage"] == "gap",
          data["detection"]["coverage"])

    # 404 for unknown rule
    try:
        await read_resource(AnyUrl("detection://rules/nonexistent_rule"))
        check("unknown rule raises FileNotFoundError", False)
    except FileNotFoundError:
        check("unknown rule raises FileNotFoundError", True)

asyncio.run(test_resources())

# ── Summary ───────────────────────────────────────────────────────────────────
passed = sum(1 for s, _, _ in results if s == PASS)
failed = sum(1 for s, _, _ in results if s == FAIL)
print(f"\n{passed}/{len(results)} passed", "" if failed == 0 else f"  ({failed} FAILED)")
