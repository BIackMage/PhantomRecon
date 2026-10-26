"""Write a winget manifest for a published Phantom Recon release.

The release workflow uploads PhantomRecon-<version>-x64.zip and a .sha256 file.
This script turns that into the three YAML files winget-pkgs expects, so the
package can be submitted with `wingetcreate submit` or a pull request to
microsoft/winget-pkgs.

Usage:
  python tools/make_winget_manifest.py 1.0.0 <sha256-of-zip> [--out manifests]

The zip is a portable package: winget unpacks it and puts PhantomReconCli.exe on
the PATH as "phantomrecon". Nothing is installed as a service and nothing runs
at startup.
"""
import argparse
import pathlib
import re
import sys

PUBLISHER = "BIackMage"
PACKAGE = "PhantomRecon"
IDENTIFIER = f"{PUBLISHER}.{PACKAGE}"
REPO = "https://github.com/BIackMage/PhantomRecon"
MANIFEST_VERSION = "1.6.0"


def check_inputs(version: str, sha256: str) -> None:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        sys.exit(f"version must look like 1.2.3, got {version!r}")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", sha256):
        sys.exit("sha256 must be 64 hex characters (see the .sha256 file on the release)")


def version_manifest(version: str) -> str:
    return (
        f"PackageIdentifier: {IDENTIFIER}\n"
        f"PackageVersion: {version}\n"
        f"DefaultLocale: en-US\n"
        f"ManifestType: version\n"
        f"ManifestVersion: {MANIFEST_VERSION}\n"
    )


def locale_manifest(version: str) -> str:
    return (
        f"PackageIdentifier: {IDENTIFIER}\n"
        f"PackageVersion: {version}\n"
        f"PackageLocale: en-US\n"
        f"Publisher: {PUBLISHER}\n"
        f"PublisherUrl: https://github.com/{PUBLISHER}\n"
        f"PackageName: Phantom Recon\n"
        f"PackageUrl: {REPO}\n"
        f"License: PolyForm Noncommercial 1.0.0\n"
        f"LicenseUrl: {REPO}/blob/main/LICENSE\n"
        f"ShortDescription: Defensive Windows security audit and file-change watch, offline.\n"
        f"Description: |-\n"
        f"  Phantom Recon checks about fifty Windows security settings, scores them from 0 to 100\n"
        f"  and shows the exact fix and how to undo it. It also records the programs on a PC you\n"
        f"  trust and later shows what is new, changed or missing. Everything runs on the PC.\n"
        f"Tags:\n"
        f"  - security\n"
        f"  - audit\n"
        f"  - hardening\n"
        f"  - integrity\n"
        f"  - defensive\n"
        f"ReleaseNotesUrl: {REPO}/releases/tag/v{version}\n"
        f"ManifestType: defaultLocale\n"
        f"ManifestVersion: {MANIFEST_VERSION}\n"
    )


def installer_manifest(version: str, sha256: str) -> str:
    url = f"{REPO}/releases/download/v{version}/PhantomRecon-{version}-x64.zip"
    return (
        f"PackageIdentifier: {IDENTIFIER}\n"
        f"PackageVersion: {version}\n"
        f"InstallerType: zip\n"
        f"NestedInstallerType: portable\n"
        f"NestedInstallerFiles:\n"
        f"  - RelativeFilePath: PhantomReconCli.exe\n"
        f"    PortableCommandAlias: phantomrecon\n"
        f"MinimumOSVersion: 10.0.17763.0\n"
        f"Installers:\n"
        f"  - Architecture: x64\n"
        f"    InstallerUrl: {url}\n"
        f"    InstallerSha256: {sha256.upper()}\n"
        f"ManifestType: installer\n"
        f"ManifestVersion: {MANIFEST_VERSION}\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("version")
    parser.add_argument("sha256")
    parser.add_argument("--out", default="manifests")
    args = parser.parse_args()
    check_inputs(args.version, args.sha256)

    folder = pathlib.Path(args.out) / PUBLISHER[0].lower() / PUBLISHER / PACKAGE / args.version
    folder.mkdir(parents=True, exist_ok=True)
    files = {
        f"{IDENTIFIER}.yaml": version_manifest(args.version),
        f"{IDENTIFIER}.locale.en-US.yaml": locale_manifest(args.version),
        f"{IDENTIFIER}.installer.yaml": installer_manifest(args.version, args.sha256),
    }
    for name, text in files.items():
        path = folder / name
        path.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {path}")
    print("Check with: winget validate --manifest", folder)
    return 0


if __name__ == "__main__":
    sys.exit(main())
