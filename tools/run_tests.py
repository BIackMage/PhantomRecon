"""Run PhantomReconTests.exe for CI: keep a log, judge the totals, stop a hung run.

  python tools/run_tests.py [--exe x64/Release/PhantomReconTests.exe] [--log tests.log]
                            [--per-test-timeout 600] [--timeout 2400] [--unelevated]

The output goes to the console and to the log file (uploaded by the workflow when a
step fails). The run passes only when the program exits 0 AND its totals line says
at least one test passed and none failed; an empty or cut-off run is a failure.

--unelevated runs the tests with a normal-user token (see unelevated.py) and checks
that the program saw itself as not elevated. On a PC that is not elevated anyway the
same token is used, so the option behaves the same everywhere.

The test program prints the name of a test that crashes or hangs, and stops itself
after --per-test-timeout seconds on one test. --timeout is the backstop for the
whole run.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys
import threading

from release_common import DEFAULT_EXE_DIR, configure_console, log

TOTALS = re.compile(r"^(\d+) passed, (\d+) failed, (\d+) not selected, (\d+) checks failed\s*$", re.MULTILINE)
ELEVATED = re.compile(r"^Elevated: (yes|no|unknown)\s*$", re.MULTILINE)
EXIT_MEANING = {0: "all passed", 1: "a test failed", 2: "setup or arguments", 3: "a test crashed", 4: "a test hung"}


def run_normal(command: list, log_path: pathlib.Path, timeout: int) -> tuple:
    """Stream the output to the console and the log while the program runs."""
    lines = []
    with open(log_path, "w", encoding="utf-8", newline="\n") as log_file:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        def pump():
            for raw in process.stdout:
                text = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                lines.append(text)
                print(text, flush=True)
                log_file.write(text + "\n")
                log_file.flush()

        reader = threading.Thread(target=pump)
        reader.start()
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            reader.join()
            raise
        reader.join()
    return code, "\n".join(lines)


def run_restricted(command: list, log_path: pathlib.Path, timeout: int) -> tuple:
    import unelevated

    with open(log_path, "wb") as log_file:
        code = unelevated.run_unelevated(command, log_file, timeout)
    text = log_path.read_bytes().decode("utf-8", errors="replace").replace("\r\n", "\n")
    print(text, flush=True)
    return code, text


def main() -> int:
    configure_console()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--exe", type=pathlib.Path, default=DEFAULT_EXE_DIR / "PhantomReconTests.exe")
    parser.add_argument("--log", type=pathlib.Path, default=pathlib.Path("tests.log"))
    parser.add_argument("--per-test-timeout", type=int, default=600)
    parser.add_argument("--timeout", type=int, default=2400)
    parser.add_argument("--unelevated", action="store_true")
    parser.add_argument("filters", nargs="*", help="test name filters passed to the program")
    args = parser.parse_args()

    exe = args.exe.resolve()
    if not exe.is_file():
        print(f"TESTS NOT RUN: {exe} does not exist", flush=True)
        return 1
    args.log.parent.mkdir(parents=True, exist_ok=True)
    command = [str(exe), "--timeout", str(args.per_test_timeout), *args.filters]
    log(("unelevated " if args.unelevated else "") + "run: " + " ".join(command) + f" (log {args.log})")
    try:
        if args.unelevated:
            code, text = run_restricted(command, args.log, args.timeout)
        else:
            code, text = run_normal(command, args.log, args.timeout)
    except subprocess.TimeoutExpired:
        print(f"TESTS FAILED: the whole run took over {args.timeout} s and was stopped; the last RUN line in "
              f"{args.log} names the test", flush=True)
        return 1

    problems = []
    if code != 0:
        problems.append(f"exit code {code} ({EXIT_MEANING.get(code, 'unexpected')})")
    totals = TOTALS.findall(text)
    if not totals:
        problems.append("no totals line: the run did not finish")
    else:
        passed, failed, _, checks = (int(x) for x in totals[-1])
        if passed == 0:
            problems.append("no test passed")
        if failed or checks:
            problems.append(f"{failed} test(s) and {checks} check(s) failed")
    elevated = ELEVATED.findall(text)
    if args.unelevated and elevated != ["no"]:
        problems.append(f"expected a run without administrator rights, the program reported {elevated}")
    if problems:
        print("TESTS FAILED: " + "; ".join(problems), flush=True)
        return 1
    print(f"Tests passed ({totals[-1][0]} tests, elevated: {elevated[0] if elevated else 'not reported'}).", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
