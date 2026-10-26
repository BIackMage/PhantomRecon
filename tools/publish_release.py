"""Create the GitHub release for a tag as a DRAFT, with the files from package_release.py.

  RELEASE_TAG=v1.2.3 GH_TOKEN=... python tools/publish_release.py [--dist dist] [--dry-run]

Nothing is published to users by this script. The release is a draft: the maintainer
downloads the zip, checks it, starts PhantomRecon.exe on a real desktop, and only then
presses Publish on GitHub.

Running it again for the same tag (the Release workflow's "Run workflow" button with
that tag) replaces an existing DRAFT, so a fixed build can be uploaded before
publishing. A release that is already published is never touched: that needs a new
version, because people may already have checked its SHA-256.

A tag with -rc.N becomes a pre-release and is never marked as the latest release.
The tag is read from RELEASE_TAG, never from the command line. Uses the GitHub CLI
(gh), which reads GH_TOKEN; --dry-run prints what would be done and calls nothing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile

from release_common import (REPO_URL, ROOT, ReleaseTag, checksum_name, configure_console, log, symbols_zip_name,
                            tag_from_environment, zip_name)


class PublishError(Exception):
    pass


def release_notes(tag: ReleaseTag, zip_file: str, digest: str, symbols_file: str) -> str:
    """Only what is specific to this release; everything else is in the README, so the
    two cannot drift apart."""
    lines = [f"Phantom Recon {tag.version} for 64-bit Windows 10 and 11."]
    if tag.prerelease:
        lines.append("This is a release candidate for testing. It is not the latest release.")
    lines += [
        "",
        f"What it does, how to use it and which files it writes: README.md in the zip, or {REPO_URL}/blob/{tag.tag}/README.md",
        "",
        "Nothing leaves the PC unless you turn it on: certificate revocation checks go online only when revocation "
        "checking is set to Online (never in portable mode), and the optional AI panel sends text only after you turn "
        "it on, and asks first before sending to any server other than this PC.",
        "",
        f"SHA-256 of {zip_file}: {digest}",
        "",
        "The programs are not code-signed, so Windows SmartScreen may warn on first run. The SHA-256 above shows that "
        "your download is complete and unchanged from the file on this page; it does not prove who built it.",
        "",
        f"{symbols_file} holds the debug symbols of this exact build. It is only needed to read a crash dump.",
    ]
    return "\n".join(lines) + "\n"


def assets(dist: pathlib.Path, tag: ReleaseTag) -> tuple:
    main_zip = dist / zip_name(tag.version)
    symbols = dist / symbols_zip_name(tag.version)
    files = [main_zip, dist / checksum_name(main_zip.name), symbols, dist / checksum_name(symbols.name)]
    missing = [f.name for f in files if not f.is_file()]
    if missing:
        raise PublishError("missing release files: " + ", ".join(missing))
    recorded = files[1].read_text(encoding="ascii").split()[0]
    digest = hashlib.sha256(main_zip.read_bytes()).hexdigest()
    if recorded != digest:
        raise PublishError(f"{files[1].name} says {recorded}, the zip hashes to {digest}")
    return files, digest


def gh(args: list, dry_run: bool, check: bool = True) -> subprocess.CompletedProcess:
    command = ["gh", *[str(a) for a in args]]
    repo = os.environ.get("GITHUB_REPOSITORY")
    if repo:
        command += ["--repo", repo]
    log("gh: " + " ".join(command))
    if dry_run:
        return subprocess.CompletedProcess(command, 1, "", "dry run")
    result = subprocess.run(command, capture_output=True, encoding="utf-8", errors="replace", check=False, cwd=ROOT)
    if check and result.returncode != 0:
        raise PublishError(f"{' '.join(command[:3])} failed ({result.returncode}): {result.stderr.strip()}")
    return result


def existing_release(tag: ReleaseTag, dry_run: bool):
    """None when the tag has no release yet, else its isDraft flag."""
    result = gh(["release", "view", tag.tag, "--json", "isDraft,isPrerelease,url"], dry_run, check=False)
    if result.returncode != 0:
        return None
    info = json.loads(result.stdout)
    log(f"existing release: {info}")
    return bool(info.get("isDraft"))


def publish(dist: pathlib.Path, dry_run: bool) -> None:
    tag = tag_from_environment()
    files, digest = assets(dist, tag)
    notes = release_notes(tag, files[0].name, digest, files[2].name)
    print("Release notes:\n" + notes, flush=True)

    draft = existing_release(tag, dry_run)
    if draft is False:
        raise PublishError(f"{tag.tag} is already published; it is left as it is. Release a new version instead.")
    if draft is True:
        log(f"replacing the earlier draft for {tag.tag}")
        gh(["release", "delete", tag.tag, "--yes"], dry_run)

    with tempfile.TemporaryDirectory(prefix="phantomrecon_notes_") as temp:
        notes_file = pathlib.Path(temp) / "notes.md"
        notes_file.write_text(notes, encoding="utf-8", newline="\n")
        args = ["release", "create", tag.tag, *files, "--draft", "--verify-tag", "--title",
                f"Phantom Recon {tag.version}", "--notes-file", notes_file]
        if tag.prerelease:
            args += ["--prerelease", "--latest=false"]
        gh(args, dry_run)
    print(f"Draft release for {tag.tag} {'would be ' if dry_run else ''}created. Check it, then publish it on GitHub.",
          flush=True)


def main() -> int:
    configure_console()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dist", type=pathlib.Path, default=ROOT / "dist")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        publish(args.dist.resolve(), args.dry_run)
    except (PublishError, OSError, ValueError) as error:
        print(f"PUBLISH FAILED: {error}", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
