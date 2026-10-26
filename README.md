# Phantom Recon

[![Build and test](https://github.com/BIackMage/PhantomRecon/actions/workflows/build.yml/badge.svg)](https://github.com/BIackMage/PhantomRecon/actions/workflows/build.yml)

Phantom Recon checks a Windows PC for security problems and tells you, in plain words,
how to fix each one. It also records the programs on a PC you trust, and later shows
you what is new, changed or missing.

It runs entirely on the PC. No account, no cloud, no agent, no service, no install.
Nothing is sent anywhere unless you turn on the optional AI panel and point it at a
server yourself.

It is a defensive tool. It looks at the PC it runs on and changes nothing. Every fix is
shown for you to run yourself, with the command to undo it.

Version 1.0.0. Windows 10 and 11, 64-bit.

## What it does

### Security audit: 51 checks, one score

The audit runs when the program starts and scores the PC from 0 to 100. Each problem
comes with what it means, the exact fix, and how to undo the fix.

| Area | What is checked |
|------|-----------------|
| Malware protection | Real-time protection, Tamper Protection, cloud protection, definition age, exclusions, Attack Surface Reduction rules, SmartScreen, Controlled folder access |
| Updates and software | Windows Update health, known-vulnerable or end-of-life programs (7-Zip, WinRAR, PuTTY, VLC and more) |
| Platform hardening | BitLocker, TPM, Secure Boot, UAC, AutoPlay, Windows Script Host, PowerShell 2.0, Office macros |
| Credential protection | LSA protection, Credential Guard, Guest and Administrator accounts, local accounts, password and lockout policy |
| Services and privileges | Unquoted service paths, service programs normal users can change, AlwaysInstallElevated, folders where a planted DLL would load, leftover setup files with passwords, Group Policy Preference passwords, Print Spooler |
| Network exposure | Firewall, listening programs, LLMNR, NetBIOS, mDNS, SMB signing, SMBv1, Remote Desktop, WinRM, Remote Registry, WPAD, hosts file, DNS servers, trusted root certificates |
| Persistence | 13 kinds of autostart location (Run keys to WMI subscriptions and COM), scheduled tasks |
| Running programs | Programs pretending to be Windows, started from Downloads or Temp, or changed since your baseline |
| Logging and audit | Audit policy per subcategory, event log sizes, PowerShell logging |

Each check is mapped to MITRE ATT&CK techniques and CIS Controls v8 where the mapping is
honest. [docs/FINDINGS.md](docs/FINDINGS.md) lists every check with its fix.

### File watch: baseline, then compare

- **Take Baseline** records every program and script in one or more folders: hashes,
  signature, version, and about forty more facts per file.
- **Full Scan** compares folders with the baseline. **Fast Scan** does the same for
  installed programs only.
- Every file comes back as MATCH, NEW, CHANGED or MISSING. Files changed by a signed
  Microsoft update show as UPDATED, and new files on your own known-good list as KNOWN,
  so Patch Tuesday does not bury the real changes.
- **Compare Two Baselines** shows what changed between two snapshots without scanning.

### File analysis, without running anything

Every program and script gets a risk score from 0 to 10, built from:

- Authenticode and Windows catalog signatures, certificate chain, revocation status, and
  signs of a copied or broken signature
- Program header facts: imports that malware also uses, packing, writable code, build
  date in the future, checksum mismatch, code that runs before the start point, data
  appended after the program, odd debug paths
- Where the file came from: the browser's download mark (Mark of the Web) and hidden
  NTFS data streams
- Script lines worth a look: encoded commands, download-and-run, Defender tampering
- Import hash and fuzzy hash, so a small patch looks different from a replaced file

A finding is a reason to look, not proof of harm. Double-click a row to read what each
finding means.

### Reports

- **HTML**: one self-contained page, light and dark, with copy buttons on every fix
- **JSON**: a versioned schema (`phantomrecon.report/1`) for other tools
- **MITRE ATT&CK Navigator layer**: the techniques your findings relate to
- **CSV**: every scan row, UTF-8, opens in Excel
- Optional: hide your user, computer and domain names before saving or sending

### Optional AI panel

The panel on the right edge can explain a file, a scan or the audit using any
OpenAI-compatible chat server. The default address is a model on your own PC
(`http://localhost:1234`). Names are hidden before anything is sent, long text goes in
parts, and the program asks before sending to any other address.

## Download and run

1. Download the zip from [Releases](https://github.com/BIackMage/PhantomRecon/releases)
   and check its SHA-256 against the one on the release page.
2. Unzip it anywhere, for example a USB stick.
3. Run `PhantomRecon.exe`.

The programs are not code-signed (a signing certificate costs money this project does
not have), so Windows SmartScreen may warn the first time. The SHA-256 check shows that
your download is complete and is the same file as the one on the release page. It does
not prove who built that file: it is only as trustworthy as the release page itself.

### First steps

1. The audit runs on its own. Press **F6** for the findings and their fixes.
2. Want to see the file watch work first? **Help > Create Sample Pack** writes a few
   harmless demo files and a demo baseline, then scans them. Expect 1 NEW, 1 CHANGED
   and 1 MISSING file.
3. On a day you trust the PC: **Scans > Take Baseline**, for example of
   `C:\Program Files`.
4. Later: **Scans > Full Scan** or **Fast Scan**. Filter to "Needs review" and
   double-click anything you do not recognise.
5. **Reports > Save HTML Report** for something you can read later or hand to someone.

Run it as a normal user for the normal-user view. Run it as administrator to see every
service, task and process.

### Keyboard

| Key | Does |
|-----|------|
| F5 | Run the audit again |
| F6 | Findings and fixes |
| Enter, double-click | Details of the selected row |
| Ctrl+C | Copy the selected file's full path |
| Ctrl+F | Search the results |
| Ctrl+E | Export the rows you can see to CSV |
| Esc | Cancel the scan |

You can also drop a `.csv` (saved results) or `.prbl` (baseline) file on the window, or
pass one on the command line.

### Command line

`PhantomReconCli.exe` does everything without a window, for scripts, scheduled runs and
remote management tools:

```powershell
# Audit with an HTML report
PhantomReconCli.exe --audit --report audit.html

# Baseline now, compare later
PhantomReconCli.exe --baseline-scan "C:\Program Files"
PhantomReconCli.exe --full "C:\Program Files" --report changes.html --csv changes.csv

# Weekly Fast Scan as one visible, removable scheduled task
PhantomReconCli.exe --schedule-weekly
```

Exit code 0 means nothing needs attention, 1 means something does, 2 means an error.
`PhantomReconCli.exe --help` lists every option.

### Portable mode

Run from a USB drive, pass `--portable`, or put a file named `portable.flag` next to the
program. Everything is then written next to the program, no scheduled task is ever
created, and certificate revocation never goes online.

## Files it writes

All next to the program unless you choose another folder in **File > Settings**:

| File | What it is |
|------|------------|
| `phantom_recon_baseline.prbl` | The baseline (binary, with an integrity check) |
| `phantom_recon_settings.ini` | Your settings |
| `phantom_recon_scoring.ini` | Every scoring weight, written with defaults on first run; edit to tune |
| `security_audit_report.txt` | Plain text of the last audit |
| `phantom_recon_persistence.snapshot` | Autostart entries seen last time, so new ones stand out |
| `phantom_recon_revocation_cache.txt` | Certificate revocation answers, kept for a day |
| `known_good_sha256.txt` | Optional: SHA-256 hashes you trust, one per line |
| `reports\` | Reports and scan CSVs |

## Build from source

Requirements: Visual Studio 2022 or later with "Desktop development with C++" (v143
tools) and a Windows 10 or 11 SDK. No other libraries.

```powershell
msbuild PhantomRecon.sln /p:Configuration=Release /p:Platform=x64
.\x64\Release\PhantomReconTests.exe
```

| Project | Builds |
|---------|--------|
| `PhantomRecon.Core` | The engine, as a static library. No windows. |
| `PhantomRecon` | `PhantomRecon.exe`, the Windows app |
| `cli\PhantomRecon.Cli` | `PhantomReconCli.exe`, the console program |
| `tests\PhantomRecon.Tests` | `PhantomReconTests.exe`, the automated tests |

GitHub Actions builds and tests every push to any branch and every pull request; a
change to documentation only gets the text checks. The tests run twice, as
administrator and as a normal user, followed by a command-line smoke test and a check
that the window program starts and closes. A version tag (`v1.0.0`, or `v1.0.0-rc.1`
for a release candidate) runs all of that, then makes a draft release with the zip,
its debug symbols and their SHA-256 files for the maintainer to check and publish; the
winget manifests are kept with the workflow run. Every workflow step is a Python script
in `tools/`, so the same checks run on a PC.

The rules for changing the code are in [CLAUDE.md](CLAUDE.md). They apply to people too.

## Contributing

Issues and pull requests are welcome. Keep each change small and in the module it
belongs to, add a test for engine changes, and do not add third-party dependencies
without opening an issue first.

This project stays defensive. Changes that read other programs' memory, act on other
machines, or help evade security tools will not be accepted.

[docs/IDEAS.md](docs/IDEAS.md) tracks what is built and what is left.

## License

PolyForm Noncommercial 1.0.0. See [LICENSE](LICENSE).

In plain words: anyone may use, study, change and share this software for free, for any
noncommercial purpose. Nobody may sell it, sell a changed version of it, or charge for a
product or service built on it. Companies may run it internally. Companies may not bill
clients for it.

This is a source-available license, not an OSI-approved open source license, because
OSI licenses must allow commercial use and this one does not, on purpose.
