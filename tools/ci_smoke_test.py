"""Command-line smoke test: the console program, end to end, on the sample pack.

Steps, each with a known answer:
  1. --make-samples writes the demo folder and its baseline (exit 0).
  2. --full against that baseline writes HTML, JSON and CSV (exit 1, "needs attention").
     Exit 1 also comes from any file scoring 7 or more, so the exit code alone proves
     nothing about the comparison: the JSON counts are checked instead
     (1 NEW, 1 CHANGED, 1 MISSING, 5 MATCH, nothing UPDATED or KNOWN).
  3. --diff of the demo baseline with itself: nothing differs (exit 0, all counts 0).
  4. --audit --fix-script on the PC running the test (the sample pack is already there;
     the audit looks at the PC itself): both scripts are written as UTF-8 with BOM and
     CRLF line ends, the real Windows PowerShell parser accepts both with no error and
     no double-quoted string, the plan has one step per FAIL or WARNING in the JSON
     report, and the fix script run with -ListOnly lists them and changes nothing.

Usage:
  python tools/ci_smoke_test.py [--exe-dir x64/Release] [--work <empty folder>]

Exit code 0 when every step matched, 1 otherwise. The script itself always ends with
an explicit exit code, so a program's expected exit 1 never leaks into the CI step
result (the old inline PowerShell failed for exactly that reason).
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
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


# Reports what Windows PowerShell's own parser makes of a script: the number of parse
# errors and of double-quoted (expandable) strings. The plan must have neither.
PARSER_SCRIPT = "\r\n".join([
    "param([string]$Path, [string]$Out)",
    "$ErrorActionPreference = 'Stop'",
    "$tokens = $null",
    "$errors = $null",
    "$ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)",
    "$expandable = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst] }, $true))",
    "$lines = New-Object System.Collections.Generic.List[string]",
    "$lines.Add('errors=' + $errors.Count)",
    "$lines.Add('expandable=' + $expandable.Count)",
    "foreach ($e in $errors) { $lines.Add('error=' + $e.Extent.StartLineNumber + ': ' + $e.Message) }",
    "[System.IO.File]::WriteAllLines($Out, $lines)",
    "",
])


def powershell_exe() -> str:
    root = os.environ.get("SystemRoot", r"C:\Windows")
    return str(pathlib.Path(root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe")


def parse_powershell(script: pathlib.Path, work: pathlib.Path) -> dict:
    """Parse with the real parser; never runs the script."""
    parser = work / "parse_check.ps1"
    out = work / (script.stem + ".parse.txt")
    parser.write_bytes(PARSER_SCRIPT.encode("ascii"))
    result = run_program([powershell_exe(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                          "-File", parser, "-Path", script, "-Out", out], timeout=120)
    expect(result.returncode == 0 and out.is_file(),
           f"the PowerShell parser ran on {script.name} (exit {result.returncode}) {result.stdout}{result.stderr}")
    report = {"errors": None, "expandable": None, "messages": []}
    for line in out.read_text(encoding="utf-8-sig").splitlines():
        key, _, value = line.partition("=")
        if key in ("errors", "expandable"):
            report[key] = int(value)
        elif key == "error":
            report["messages"].append(value)
    for message in report["messages"]:
        log(f"parse error in {script.name}: {message}")
    return report


def check_script_file(path: pathlib.Path, work: pathlib.Path) -> str:
    """BOM, CRLF only, and a clean parse. Returns the text."""
    expect(path.is_file(), f"{path.name} was written")
    data = path.read_bytes()
    expect(data.startswith(b"\xef\xbb\xbf"), f"{path.name} starts with a UTF-8 BOM")
    expect(data.count(b"\n") > 0 and data.count(b"\n") == data.count(b"\r\n"), f"{path.name} has CRLF line ends only")
    expect(data.count(b"\r") == data.count(b"\r\n"), f"{path.name} has no lone CR")
    report = parse_powershell(path, work)
    expect(report["errors"] == 0, f"{path.name} parses with no error (got {report['errors']})")
    expect(report["expandable"] == 0, f"{path.name} has no double-quoted string (got {report['expandable']})")
    return data[3:].decode("utf-8")


def smoke_fix_script(cli: pathlib.Path, work: pathlib.Path) -> None:
    fix, audit_json = work / "fix-plan.ps1", work / "audit.json"
    undo = work / "fix-plan-undo.ps1"
    result = run_program([cli, "--audit", "--fix-script", fix, "--json", audit_json, "--quiet"])
    if result.returncode not in (0, 1):
        log("output:\n" + result.stdout + result.stderr)
    expect(result.returncode in (0, 1), f"--audit --fix-script exits 0 or 1 (got {result.returncode})")
    report = load_report(audit_json)
    # Unscored findings (Recent activity) report events, not settings; the plan leaves them out.
    problems = [f for f in report.get("findings", [])
                if f.get("status") in ("FAIL", "WARNING") and f.get("scored", True)]
    activity = [f for f in report.get("findings", []) if f.get("scored", True) is False]
    expect(bool(activity), f"audit.json marks the Recent activity findings as not scored (got {len(activity)})")
    log(f"audit: {len(problems)} scored FAIL or WARNING finding(s)")

    fix_text = check_script_file(fix, work)
    undo_text = check_script_file(undo, work)
    for name, text in (("fix", fix_text), ("undo", undo_text)):
        steps = re.findall(r"^# Step (\d+) of (\d+): (\S+) ", text, re.MULTILINE)
        expect(len(steps) == len(problems), f"the {name} script has one step per problem ({len(steps)} of {len(problems)})")
        expect(all(int(total) == len(problems) for _, total, _ in steps), f"the {name} script counts {len(problems)} steps")
        expect(sorted(s[2] for s in steps) == sorted(p["id"] for p in problems),
               f"the {name} script's steps are the audit's problems")
        gates = text.count("$answer = Read-Host 'Apply this step? [y/N]'")
        tries = len(re.findall(r"^        try \{\r?$", text, re.MULTILINE))
        expect(gates == tries, f"every {name} step that runs commands asks first ({gates} questions, {tries} steps)")
        expect("Restart-Computer" not in text, f"the {name} script never restarts the PC")

    # -ListOnly changes nothing; input is closed, so a question would read nothing and skip.
    log("run: powershell -File fix-plan.ps1 -ListOnly")
    listed = subprocess.run([powershell_exe(), "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(fix), "-ListOnly"],
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=300, encoding="utf-8",
                            errors="replace", check=False)
    expect(listed.returncode == 0, f"-ListOnly exits 0 (got {listed.returncode}) {listed.stderr}")
    if problems:
        expect(f"List only: nothing was changed. {len(problems)} step(s) listed." in listed.stdout,
               "-ListOnly lists every step and changes nothing")
        expect("Applied." not in listed.stdout and "Apply this step" not in listed.stdout, "-ListOnly asks nothing and applies nothing")
    else:
        expect("nothing to fix" in listed.stdout, "an empty plan says there is nothing to fix")


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

    smoke_fix_script(cli, work)


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
