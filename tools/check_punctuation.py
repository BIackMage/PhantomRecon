"""Find (and optionally fix) typographic punctuation in the repository's text files.

The project keeps source and docs to ASCII punctuation (see CLAUDE.md): long dashes,
curly quotes and arrows break PowerShell on the maintainer's machine and look wrong in
the console program's output. It also rejects UTF-16 text files, which Git's line-ending
conversion corrupts on checkout.

Usage:
  python tools/check_punctuation.py          report, exit 1 when anything is found
  python tools/check_punctuation.py --fix    rewrite the files with ASCII replacements
"""
import pathlib
import subprocess
import sys

REPLACEMENTS = {
    chr(0x2014): "-",    # em dash
    chr(0x2013): "-",    # en dash
    chr(0x2212): "-",    # minus sign
    chr(0x2018): "'",    # left single quote
    chr(0x2019): "'",    # right single quote
    chr(0x201C): '"',    # left double quote
    chr(0x201D): '"',    # right double quote
    chr(0x2192): "->",   # right arrow
    chr(0x2190): "<-",   # left arrow
    chr(0x2026): "...",  # ellipsis
    chr(0x00A0): " ",    # no-break space
}
TEXT_SUFFIXES = {".cpp", ".h", ".md", ".rc", ".txt", ".py", ".yml", ".yaml", ".props", ".vcxproj", ".sln", ".gitignore",
                 ".gitattributes"}


def tracked_files(root: pathlib.Path):
    # -z: NUL-separated raw names. Without it git quotes and escapes any name with a
    # non-ASCII letter ("docs/caf\303\251.md"), the path does not exist, and the file
    # was silently skipped.
    out = subprocess.run(["git", "ls-files", "-z", "-co", "--exclude-standard"], cwd=root, capture_output=True,
                         check=True).stdout
    for raw in out.split(b"\0"):
        if not raw:
            continue
        path = root / raw.decode("utf-8", errors="surrogateescape")
        if path.suffix.lower() in TEXT_SUFFIXES or path.name in TEXT_SUFFIXES:
            yield path


def main() -> int:
    # The Windows console is often cp1252; a file name or line with a letter it
    # cannot show must not crash the check halfway through.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError):
            pass
    fix = "--fix" in sys.argv
    root = pathlib.Path(__file__).resolve().parent.parent
    problems = 0
    for path in tracked_files(root):
        if not path.is_file():
            continue
        raw = path.read_bytes()
        rel = path.relative_to(root)
        if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
            # .gitattributes converts line endings byte by byte, which corrupts UTF-16
            # on checkout (a resource script lost its menus and window name this way).
            print(f"{rel}: UTF-16 text file; save it as UTF-8 or ASCII")
            problems += 1
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            print(f"{rel}: not valid UTF-8")
            problems += 1
            continue
        bom = text.startswith(chr(0xFEFF))
        body = text[1:] if bom else text
        found = [(i + 1, line) for i, line in enumerate(body.split("\n")) if any(ch in line for ch in REPLACEMENTS)]
        if not found:
            continue
        problems += len(found)
        for line_no, line in found[:5]:
            shown = "".join(f"<U+{ord(c):04X}>" if c in REPLACEMENTS else c for c in line.strip())
            print(f"{rel}:{line_no}: {shown[:140]}")
        if len(found) > 5:
            print(f"{rel}: ... {len(found) - 5} more line(s)")
        if fix:
            for bad, good in REPLACEMENTS.items():
                body = body.replace(bad, good)
            path.write_bytes(((chr(0xFEFF) if bom else "") + body).encode("utf-8"))
            print(f"{rel}: fixed")
    if problems and not fix:
        print(f"{problems} problem(s) found. --fix replaces typographic punctuation; UTF-16 files must be re-saved.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
