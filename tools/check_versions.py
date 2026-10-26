"""Check that every place that states the version agrees.

  python tools/check_versions.py [--exe x64/Release/PhantomReconCli.exe] [--no-exe]

Compares PHANTOMRECON_VERSION_W in Version.h, the "Version X.Y.Z." line in README.md
and, unless --no-exe, what the built PhantomReconCli.exe says with --version.
Exit 0 when they match, 1 when they do not.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

from release_common import DEFAULT_EXE_DIR, cli_version, configure_console, header_version, log, readme_version


def main() -> int:
    configure_console()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--exe", type=pathlib.Path, default=DEFAULT_EXE_DIR / "PhantomReconCli.exe")
    parser.add_argument("--no-exe", action="store_true", help="only compare the source files (docs-only CI)")
    args = parser.parse_args()

    try:
        found = {"Version.h": header_version(), "README.md": readme_version()}
        if not args.no_exe:
            found[args.exe.name + " --version"] = cli_version(args.exe)
    except (OSError, ValueError, RuntimeError) as error:
        print(f"VERSION CHECK FAILED: {error}", flush=True)
        return 1
    for where, version in found.items():
        log(f"{where}: {version}")
    if len(set(found.values())) != 1:
        print("VERSION CHECK FAILED: " + ", ".join(f"{k} says {v}" for k, v in found.items()), flush=True)
        return 1
    print(f"Versions agree: {next(iter(found.values()))}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
