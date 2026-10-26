"""Check a release tag before anything is packaged.

  RELEASE_TAG=v1.2.3 python tools/check_release_tag.py [--exe x64/Release/PhantomReconCli.exe]

The tag is read from the RELEASE_TAG environment variable, never from the command
line, so a tag name can never become part of a shell command. It must be exactly
v<major>.<minor>.<patch> or v<major>.<minor>.<patch>-rc.<n> (case-sensitive: "V1.0.0"
and "vv1.0.0" are refused), and its version must equal what the built program says
with --version, what Version.h says, and the README's "Version X.Y.Z." line.
A release candidate (-rc.N) is checked against the X.Y.Z part.

Outputs for later steps (GITHUB_OUTPUT): version, prerelease (true/false).
"""
from __future__ import annotations

import argparse
import pathlib
import sys

from release_common import (DEFAULT_EXE_DIR, cli_version, configure_console, header_version, log, readme_version,
                            set_output, tag_from_environment)


def main() -> int:
    configure_console()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--exe", type=pathlib.Path, default=DEFAULT_EXE_DIR / "PhantomReconCli.exe")
    parser.add_argument("--tag-variable", default="RELEASE_TAG")
    args = parser.parse_args()

    try:
        tag = tag_from_environment(args.tag_variable)
        sources = {"Version.h": header_version(), "README.md": readme_version(),
                   "PhantomReconCli.exe --version": cli_version(args.exe)}
    except (OSError, ValueError, RuntimeError) as error:
        print(f"TAG CHECK FAILED: {error}", flush=True)
        return 1
    log(f"tag {tag.tag}: version {tag.version}, prerelease {tag.prerelease}")
    wrong = {where: v for where, v in sources.items() if v != tag.core}
    if wrong:
        print(f"TAG CHECK FAILED: tag {tag.tag} needs version {tag.core}, but "
              + ", ".join(f"{k} says {v}" for k, v in wrong.items()), flush=True)
        return 1
    set_output("version", tag.version)
    set_output("prerelease", "true" if tag.prerelease else "false")
    print(f"Tag {tag.tag} matches the program version {tag.core}.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
