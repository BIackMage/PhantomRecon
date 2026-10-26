"""Shared pieces of the build and release scripts in this folder.

One home for: where the programs are, how a release tag must look, what the release
files are called, how to read the version, and how a script hands a value to the next
GitHub Actions step. The workflows in .github/workflows call the scripts; none of them
re-derives any of this.

Nothing here talks to the network.
"""
from __future__ import annotations

import os
import pathlib
import re
import subprocess
import sys
from dataclasses import dataclass

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_EXE_DIR = ROOT / "x64" / "Release"
REPO_URL = "https://github.com/BIackMage/PhantomRecon"

# v1.2.3 or v1.2.3-rc.4. Nothing else: no "vv1.2.3", no "V1.2.3", no trailing text.
TAG_PATTERN = re.compile(r"v(?P<version>(?P<core>\d+\.\d+\.\d+)(?:-rc\.(?P<rc>\d+))?)")
VERSION_H_PATTERN = re.compile(r'^#define\s+PHANTOMRECON_VERSION_W\s+L"([^"]+)"\s*$', re.MULTILINE)
CLI_VERSION_PATTERN = re.compile(r"^Phantom Recon (\S+)\s*$")
README_VERSION_PATTERN = re.compile(r"^Version (\d+\.\d+\.\d+)\. ", re.MULTILINE)


def log(message: str) -> None:
    """Debug line for the CI log, prefixed like the C++ trace lines."""
    print(f"[tools] {message}", flush=True)


def configure_console() -> None:
    """Never crash on a character the console code page cannot show (cp1252 on Windows)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError):
            pass


@dataclass(frozen=True)
class ReleaseTag:
    tag: str          # "v1.2.3-rc.1"
    version: str      # "1.2.3-rc.1"
    core: str         # "1.2.3"
    prerelease: bool  # True for -rc.N


def parse_tag(tag: str) -> ReleaseTag:
    """Strict, case-sensitive parse of a release tag. Raises ValueError when it does not fit."""
    match = TAG_PATTERN.fullmatch(tag)
    if not match:
        raise ValueError(f"release tag must look like v1.2.3 or v1.2.3-rc.1, got {tag!r}")
    return ReleaseTag(tag=tag, version=match.group("version"), core=match.group("core"),
                      prerelease=match.group("rc") is not None)


def tag_from_environment(variable: str = "RELEASE_TAG") -> ReleaseTag:
    """The tag comes in through an environment variable, never pasted into a command line."""
    value = os.environ.get(variable, "")
    if not value:
        raise ValueError(f"environment variable {variable} is not set")
    return parse_tag(value)


def header_version(root: pathlib.Path = ROOT) -> str:
    text = (root / "Version.h").read_text(encoding="utf-8")
    found = VERSION_H_PATTERN.findall(text)
    if len(found) != 1:
        raise ValueError(f"Version.h must define PHANTOMRECON_VERSION_W exactly once, found {len(found)}")
    return found[0]


def readme_version(root: pathlib.Path = ROOT) -> str:
    text = (root / "README.md").read_text(encoding="utf-8")
    found = README_VERSION_PATTERN.findall(text)
    if len(found) != 1:
        raise ValueError(f"README.md must have exactly one 'Version X.Y.Z.' line, found {len(found)}")
    return found[0]


def run_program(args: list, timeout: int = 600, cwd: pathlib.Path | None = None) -> subprocess.CompletedProcess:
    """Run a program, capture its output as UTF-8 text, never through a shell."""
    log("run: " + " ".join(str(a) for a in args))
    return subprocess.run([str(a) for a in args], capture_output=True, timeout=timeout, cwd=cwd,
                          encoding="utf-8", errors="replace", check=False)


def cli_version(cli: pathlib.Path) -> str:
    """The version PhantomReconCli.exe reports about itself (`--version`)."""
    result = run_program([cli, "--version"], timeout=60)
    if result.returncode != 0:
        raise RuntimeError(f"{cli.name} --version exited with {result.returncode}: {result.stdout}{result.stderr}")
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    match = CLI_VERSION_PATTERN.fullmatch(lines[0]) if len(lines) == 1 else None
    if not match:
        raise RuntimeError(f"unexpected --version output: {result.stdout!r}")
    return match.group(1)


def zip_name(version: str) -> str:
    return f"PhantomRecon-{version}-x64.zip"


def symbols_zip_name(version: str) -> str:
    return f"PhantomRecon-{version}-x64-symbols.zip"


def checksum_name(file_name: str) -> str:
    return file_name + ".sha256"


def set_output(name: str, value: str) -> None:
    """Hand a value to later steps (GITHUB_OUTPUT). Outside Actions, just print it."""
    if "\n" in value or "\r" in value:
        raise ValueError(f"output {name} must be one line")
    target = os.environ.get("GITHUB_OUTPUT")
    if target:
        with open(target, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(f"{name}={value}\n")
    log(f"output {name}={value}")
