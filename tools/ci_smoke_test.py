"""Command-line smoke test: the console program, end to end, on the sample pack.

Steps, each with a known answer:
  1. --make-samples writes the demo folder and its baseline (exit 0).
  2. --full against that baseline writes HTML, JSON and CSV (exit 1, "needs attention").
     Exit 1 also comes from any file scoring 7 or more, so the exit code alone proves
     nothing about the comparison: the JSON counts are checked instead
     (1 NEW, 1 CHANGED, 1 MISSING, 5 MATCH, nothing UPDATED or KNOWN).
  3. --diff of the demo baseline with itself: nothing differs (exit 0, all counts 0).

Usage:
  python tools/ci_smoke_test.py [--exe-dir x64/Release] [--work <empty folder>]

Exit code 0 when every step matched, 1 otherwise. The script itself always ends with
an explicit exit code, so a program's expected exit 1 never leaks into the CI step
result (the old inline PowerShell failed for exactly that reason).
"""
from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import sys
import tempfile

from release_common import DEFAULT_EXE_DIR, cli_version, configure_console, log, run_program

EXPECTED_SCAN_COUNTS = {"new": 1, "changed": 1, "missing": 1, "match": 5, "updated": 0, "known": 0}
EXPECTED_DIFF_COUNTS = {"new": 0, "changed": 0, "missing": 0, "updated": 0}


class SmokeFailure(Exception):
    pass


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise SmokeFailure(message)
    log("ok: " + message)


def load_report(path: pathlib.Path) -> dict:
    expect(path.is_file(), f"{path.name} was written")
    with open(path, encoding="utf-8-sig") as handle:
        report = json.load(handle)
    expect(report.get("schema") == "phantomrecon.report/1", f"{path.name} has schema phantomrecon.report/1")
    return report


def check_counts(report: dict, expected: dict, label: str) -> None:
    counts = report.get("scan", {}).get("counts", {})
    log(f"{label} counts: {json.dumps(counts, sort_keys=True)}")
    for key, value in expected.items():
        expect(counts.get(key) == value, f"{label}: {key} = {value} (got {counts.get(key)})")


def smoke(exe_dir: pathlib.Path, work: pathlib.Path) -> None:
    cli = exe_dir / "PhantomReconCli.exe"
    expect(cli.is_file(), f"{cli} exists")
    version = cli_version(cli)
    log(f"PhantomReconCli.exe reports version {version}")

    demo = work / "samples"
    result = run_program([cli, "--make-samples", demo])
    expect(result.returncode == 0, f"--make-samples exits 0 (got {result.returncode})")
    baseline = demo / "demo_baseline.prbl"
    expect(baseline.is_file(), "the sample pack has its demo baseline")

    html, report_json, csv = work / "demo.html", work / "demo.json", work / "demo.csv"
    result = run_program([cli, "--full", demo, "--baseline", baseline, "--revocation", "off", "--report", html,
                          "--json", report_json, "--csv", csv, "--quiet"])
    if result.returncode != 1:
        log("output:\n" + result.stdout + result.stderr)
    expect(result.returncode == 1, f"--full exits 1, files need attention (got {result.returncode})")
    report = load_report(report_json)
    expect(report.get("tool", {}).get("version") == version, "the JSON report carries the program's version")
    expect(report.get("scan", {}).get("mode") == "Full Scan", "the JSON report says Full Scan")
    check_counts(report, EXPECTED_SCAN_COUNTS, "--full")
    expect(html.is_file() and html.stat().st_size > 1000, "the HTML report was written")
    expect(csv.is_file() and csv.stat().st_size > 100, "the CSV was written")

    diff_json = work / "diff.json"
    result = run_program([cli, "--diff", baseline, baseline, "--json", diff_json, "--quiet"])
    diff = load_report(diff_json)
    check_counts(diff, EXPECTED_DIFF_COUNTS, "--diff")
    # Nothing differs, so the only thing that can still ask for attention is a file
    # scoring 7 or more in the baseline itself (the sample pack has one on purpose).
    high_risk = diff.get("scan", {}).get("counts", {}).get("highRisk")
    expect(isinstance(high_risk, int), f"--diff reports a high-risk count (got {high_risk!r})")
    wanted = 1 if high_risk > 0 else 0
    expect(result.returncode == wanted,
           f"--diff of a baseline with itself exits {wanted} with {high_risk} high-risk file(s) (got {result.returncode})")


def main() -> int:
    configure_console()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--exe-dir", type=pathlib.Path, default=DEFAULT_EXE_DIR)
    parser.add_argument("--work", type=pathlib.Path, help="folder for the demo files (default: a new temp folder)")
    args = parser.parse_args()

    own_temp = args.work is None
    work = pathlib.Path(tempfile.mkdtemp(prefix="phantomrecon_smoke_")) if own_temp else args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    log(f"work folder {work}")
    try:
        smoke(args.exe_dir.resolve(), work)
    except SmokeFailure as failure:
        print(f"SMOKE TEST FAILED: {failure}", flush=True)
        return 1
    finally:
        if own_temp:
            shutil.rmtree(work, ignore_errors=True)
    print("Smoke test passed.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
