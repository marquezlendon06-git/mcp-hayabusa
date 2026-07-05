"""Quick smoke test for the scan_evtx tool. Runs outside the MCP transport layer."""

import asyncio
import json
from pathlib import Path

from server import run_hayabusa

SAMPLE = Path(__file__).parent / "samples" / "Exec_sysmon_meterpreter_reversetcp_msipackage.evtx"


async def main():
    print(f"Sample : {SAMPLE.name}")
    print(f"Exists : {SAMPLE.exists()}")
    print()

    for severity in ("high", "medium", "low", "informational"):
        print(f"--- min_severity={severity} ---")
        findings = await run_hayabusa(str(SAMPLE), severity)
        print(f"Findings: {len(findings)}")
        if findings:
            print(json.dumps(findings[0], indent=2))
        print()


if __name__ == "__main__":
    asyncio.run(main())
