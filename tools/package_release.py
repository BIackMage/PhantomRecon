"""Build the release files from programs that were already built and tested.

  RELEASE_TAG=v1.2.3 python tools/package_release.py [--exe-dir x64/Release] [--out dist]

Writes into --out (emptied first):
  PhantomRecon-<version>-x64.zip            the programs, LICENSE, README.md, docs/FINDINGS.md
  PhantomRecon-<version>-x64.zip.sha256     "<hash>  <name>" with a Unix line end (sha256sum -c)
  PhantomRecon-<version>-x64-symbols.zip    the .pdb files, to read crash dumps from this build
  PhantomRecon-<version>-x64-symbols.zip.sha256
  manifests/...                             winget manifests (not for release candidates)

The README in the zip is the repository README with every relative link to a file
that is not in the zip turned into a link to that file at this tag on GitHub, so no
link in the zip points at nothing. The zip is reproducible: entries are sorted and
carry the commit time (or SOURCE_DATE_EPOCH) instead of the build time.

Outputs for later steps (GITHUB_OUTPUT): zip, zip_sha256, symbols.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import sys
import time
import zipfile

import make_winget_manifest
from release_common import (DEFAULT_EXE_DIR, REPO_URL, ROOT, checksum_name, configure_console, log, run_program,
                            set_output, symbols_zip_name, tag_from_environment, zip_name)

PROGRAMS = ("PhantomRecon.exe", "PhantomReconCli.exe")
SYMBOLS = ("PhantomRecon.pdb", "PhantomReconCli.pdb")
REPO_FILES = ("LICENSE", "README.md")
LINK = re.compile(r"(!?\[[^\]]*\]\()([^)\s]+)(\))")


class PackageError(Exception):
    pass


def build_time() -> tuple:
    """Commit time of HEAD, or SOURCE_DATE_EPOCH, as a zip time stamp (UTC)."""
    value = os.environ.get("SOURCE_DATE_EPOCH")
    if not value:
        result = subprocess.run(["git", "log", "-1", "--format=%ct", "HEAD"], cwd=ROOT, capture_output=True,
                                text=True, check=False)
        value = result.stdout.strip() if result.returncode == 0 else ""
    seconds = int(value) if value.isdigit() else 315532800   # 1980-01-01, the earliest zip time
    return time.gmtime(max(seconds, 315532800))[:6]


def is_relative_link(target: str) -> bool:
    return not (re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target) or target.startswith(("#", "/", "//")))


def rewrite_readme(text: str, packaged: set, tag: str) -> str:
    """Point relative links to files outside the zip at the tagged file on GitHub."""
    def replace(match: re.Match) -> str:
        target = match.group(2)
        if not is_relative_link(target):
            return match.group(0)
        path = target.split("#", 1)[0]
        normal = path[2:] if path.startswith("./") else path
        if normal in packaged:
            return match.group(0)
        if not (ROOT / normal).exists():
            raise PackageError(f"README.md links to {target}, which is not in the repository")
        url = f"{REPO_URL}/blob/{tag}/{target[2:] if target.startswith('./') else target}"
        log(f"README link {target} -> {url}")
        return match.group(1) + url + match.group(3)

    return LINK.sub(replace, text)


def check_links(text: str, packaged: set) -> None:
    for match in LINK.finditer(text):
        target = match.group(2)
        if not is_relative_link(target):
            continue
        path = target.split("#", 1)[0]
        normal = path[2:] if path.startswith("./") else path
        if normal not in packaged:
            raise PackageError(f"the packaged README still links to {target}, which is not in the zip")


def write_zip(path: pathlib.Path, files: dict, stamp: tuple) -> None:
    """files maps the name inside the zip to the source path."""
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=stamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            info.create_system = 0
            archive.writestr(info, pathlib.Path(files[name]).read_bytes())
    log(f"wrote {path} ({path.stat().st_size} bytes, {len(files)} files)")


def write_checksum(path: pathlib.Path) -> str:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    target = path.with_name(checksum_name(path.name))
    target.write_bytes(f"{digest}  {path.name}\n".encode("ascii"))   # LF only: older sha256sum -c rejects CR
    log(f"wrote {target}: {digest}")
    return digest


def package(exe_dir: pathlib.Path, out: pathlib.Path) -> None:
    tag = tag_from_environment()
    missing = [n for n in PROGRAMS + SYMBOLS if not (exe_dir / n).is_file()]
    missing += [n for n in REPO_FILES if not (ROOT / n).is_file()]
    if missing:
        raise PackageError("missing: " + ", ".join(missing))

    # The output folder is emptied: never let that be the repository or a folder above it.
    if out == ROOT or out in ROOT.parents or (out / ".git").exists():
        raise PackageError(f"refusing to empty {out}: choose a separate output folder")
    if out.exists():
        shutil.rmtree(out)
    stage = out / "stage"
    (stage / "docs").mkdir(parents=True)

    files = {}
    for name in PROGRAMS:
        files[name] = exe_dir / name
    files["LICENSE"] = ROOT / "LICENSE"
    findings = stage / "docs" / "FINDINGS.md"
    result = run_program([exe_dir / "PhantomReconCli.exe", "--findings-md", findings], timeout=120)
    if result.returncode != 0 or not findings.is_file():
        raise PackageError(f"--findings-md exited {result.returncode}: {result.stdout}{result.stderr}")
    files["docs/FINDINGS.md"] = findings

    packaged = set(files) | {"README.md"}
    readme = rewrite_readme((ROOT / "README.md").read_text(encoding="utf-8"), packaged, tag.tag)
    check_links(readme, packaged)
    staged_readme = stage / "README.md"
    staged_readme.write_bytes(readme.encode("utf-8"))
    files["README.md"] = staged_readme

    stamp = build_time()
    main_zip = out / zip_name(tag.version)
    write_zip(main_zip, files, stamp)
    digest = write_checksum(main_zip)
    symbols_zip = out / symbols_zip_name(tag.version)
    write_zip(symbols_zip, {name: exe_dir / name for name in SYMBOLS}, stamp)
    write_checksum(symbols_zip)

    # What went in is what was meant to go in.
    with zipfile.ZipFile(main_zip) as archive:
        names = sorted(archive.namelist())
        if names != sorted(files):
            raise PackageError(f"zip holds {names}, expected {sorted(files)}")
        if archive.testzip() is not None:
            raise PackageError("the zip failed its own CRC check")
        check_links(archive.read("README.md").decode("utf-8"), set(names))

    if tag.prerelease:
        log("release candidate: no winget manifests")
    else:
        make_winget_manifest.write_manifests(tag.version, digest, out / "manifests")
    shutil.rmtree(stage)

    set_output("zip", str(main_zip))
    set_output("zip_sha256", digest)
    set_output("symbols", str(symbols_zip))


def main() -> int:
    configure_console()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--exe-dir", type=pathlib.Path, default=DEFAULT_EXE_DIR)
    parser.add_argument("--out", type=pathlib.Path, default=ROOT / "dist")
    args = parser.parse_args()
    try:
        package(args.exe_dir.resolve(), args.out.resolve())
    except (PackageError, OSError, ValueError) as error:
        print(f"PACKAGING FAILED: {error}", flush=True)
        return 1
    print("Release files written to", args.out, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
