"""Check (or refresh) the bundled NVD sample against the live NVD API.

  python scripts/verify_nvd.py            # compare every CVE; exit 1 on any mismatch
  python scripts/verify_nvd.py --refresh  # overwrite the sample with the live NVD data

The comparison uses the same parser for the file and for the live record, so it cannot
notice a parser that picks the wrong score. `tests/test_nvd.py` pins known NVD values
independently, and a WARNING is printed for any record whose score is not NVD's own.

Needs internet access. NVD allows about 5 requests per 30 seconds without a key, so the
script waits between requests (set NVD_API_KEY to go faster).
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cyberrisk.nvd import NVD_SOURCE, metric_source, vulnerability_from_nvd  # noqa: E402

SAMPLE = ROOT / "src" / "cyberrisk" / "data" / "nvd_sample.json"
URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"


def fetch(cve_id: str, api_key: str | None) -> dict:
    headers = {"User-Agent": "cyberrisk-verify"}
    if api_key:
        headers["apiKey"] = api_key
    request = urllib.request.Request(URL.format(cve=cve_id), headers=headers)
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=60) as resp:  # noqa: S310 - fixed https endpoint
                data = json.loads(resp.read().decode())
            return data["vulnerabilities"][0]
        except urllib.error.HTTPError as exc:
            if exc.code not in (403, 429, 503) or attempt == 3:
                raise
        time.sleep(10 * (attempt + 1))
    raise AssertionError("unreachable")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--refresh", action="store_true", help="overwrite the sample with live NVD data")
    parser.add_argument("--file", type=Path, default=SAMPLE)
    args = parser.parse_args()
    api_key = os.environ.get("NVD_API_KEY")
    pause = 0.8 if api_key else 6.5

    doc = json.loads(args.file.read_text())
    mismatches = 0
    for i, item in enumerate(doc["vulnerabilities"]):
        cve_id = item["cve"]["id"]
        live = fetch(cve_id, api_key)
        mine = vulnerability_from_nvd(item["cve"])
        theirs = vulnerability_from_nvd(live["cve"])
        source = metric_source(item["cve"])
        note = "" if source == NVD_SOURCE else f"   WARNING: score taken from {source!r}, not NVD's own"
        if mine == theirs:
            print(f"OK        {cve_id}  CVSS {mine.cvss}  {mine.attack_vector}/{mine.privilege}{note}")
        else:
            mismatches += 1
            print(f"MISMATCH  {cve_id}\n   file: {mine}\n   NVD:  {theirs}")
        if args.refresh:
            doc["vulnerabilities"][i] = live
        time.sleep(pause)
    if args.refresh:
        doc["_note"] = "Refreshed from the live NVD API 2.0 by scripts/verify_nvd.py."
        args.file.write_text(json.dumps(doc, indent=1))
        print(f"refreshed {args.file}")
    print(f"\n{len(doc['vulnerabilities']) - mismatches} match, {mismatches} differ")
    return 1 if mismatches and not args.refresh else 0


if __name__ == "__main__":
    raise SystemExit(main())
