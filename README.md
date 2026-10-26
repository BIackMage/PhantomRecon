# Phantom Recon

Phantom Recon is a defensive Windows endpoint auditing tool. It takes a snapshot of the
executables on a machine, scores each one for risk, checks the host for common hardening
gaps, and later tells you exactly what changed.

It is a single native Win32 executable. It needs no agent, no service, no cloud account
and no network connection. Everything it writes stays on the machine you run it on.

Status: version 0.7, pre-release. Windows 10 and 11, x64. See [ROADMAP.md](ROADMAP.md)
for what is done and what is planned.

## What it does

### File analysis
For every executable it finds (28 extension types: PE binaries, installers, scripts,
shortcuts) it records:

- Path, size, MD5 and SHA-256
- Authenticode signature result, signer, issuer, root CA, thumbprint
- Stolen or cloned signature indicators (hash mismatch, untrusted root, self-signed, expired)
- Version and company name from the version resource
- Read-only and hidden attributes, owner, allow and deny ACE counts
- Shannon entropy of the whole file

### Malware risk score (0 to 10)
Static analysis of PE files. No execution, no sandbox.

- Import table parsing for 32-bit and 64-bit PE
- 80 or more suspicious API imports in 10 categories, each with a weight
- Packer detection: 12 known packer families, section names, entry-point bytes,
  per-section entropy, RWX sections, virtual-to-raw size ratio
- Signature anomaly and packing bumps feed one composite score
- Every weight is overridable in `phantom_recon_scoring.ini`, written next to the exe on
  first run

### Baseline comparison
- **Baseline Scan** walks a folder tree on a known-clean machine and saves a `.prbl`
  snapshot with an integrity footer.
- **Full Scan** walks the same tree later and marks every file MATCH, NEW, CHANGED or
  MISSING, with the exact fields that changed and the risk score delta.
- **Fast Scan** does the same for installed programs only, found through the registry
  Uninstall keys.
- Results go to a CSV you choose and to an in-app list view with colour-coded rows.

### Host posture audit
Runs at startup and writes `security_audit_report.txt` next to the exe. Checks include:

- Unquoted service paths and writable service executables
- AlwaysInstallElevated
- Leftover unattended-install files that may hold credentials
- Credential Guard (LsaIso) running
- LLMNR, NBT-NS, mDNS, SMB signing, WPAD auto-detect
- Scheduled tasks, startup programs, PowerShell logging and execution policy
- Windows Firewall profiles, audit policy proxies, Windows Update state

### Optional AI triage sidebar
A slide-out panel can send a file's scan facts, a scan summary or the audit summary to
any OpenAI-compatible chat endpoint and show the reply.

- Off by default in the sense that nothing is sent until you press a button.
- The default endpoint is `http://localhost:1234`, so data stays on the machine.
- If you point it at a remote server in File > Settings, scan data including file
  paths will leave the machine. Do not do that on a host you do not own.

## Build

Requirements:

- Visual Studio 2022 or later with the "Desktop development with C++" workload
- Windows 10 SDK or later

Steps:

1. Open `PhantomRecon.sln`.
2. Pick the `x64` platform and `Debug` or `Release`.
3. Build. The exe lands in `x64\Debug\` or `x64\Release\`.

Command line, from a Developer PowerShell:

```powershell
msbuild PhantomRecon.sln /p:Configuration=Release /p:Platform=x64
```

No third-party libraries. Everything links against the Windows SDK: WinTrust, Crypt32,
BCrypt, WinHTTP, Shlwapi, Comctl32, Version.

## Run

1. Start `PhantomRecon.exe`. The posture audit runs on its own and fills the left panel.
2. Scans > Baseline Scan on a clean machine. Pick a root folder and a CSV path.
3. Later, Scans > Full Scan or Fast Scan on the same root. Compare the CSV.
4. File > Open Baseline, Import Baseline and Export Baseline move `.prbl` files around.
5. File > Open Scan Results loads an old CSV back into the list.

Files written next to the exe:

| File | Purpose |
|------|---------|
| `phantom_recon_baseline.prbl` | The active baseline |
| `phantom_recon_scoring.ini` | Scoring weights, created with defaults on first run |
| `phantom_recon_settings.ini` | AI sidebar endpoint and model |
| `security_audit_report.txt` | Full text of the last posture audit |

Run it as a normal user for a normal-user view of writable paths. Run it elevated to
read every service binary and every scheduled task.

## Layout

| File | Role |
|------|------|
| `PhantomRecon.cpp` | Entry point, window class, message dispatcher and handlers |
| `MainCommands.cpp` | One function per menu and button command |
| `ScanEngine.cpp` | File analysis driver, directory walk, CSV writer, scan thread |
| `AppState.h` | The one struct that holds all application state |
| `AppMessages.h` | Messages background threads post to the UI, and their payloads |
| `BackgroundWorker.cpp` | Joinable thread pool used by every background job |
| `SystemInfo.cpp` | Computer, CPU, RAM and disk text |
| `FileAnalysis.cpp` | Signatures, certificate chain, version info, attributes, DACL, entropy |
| `MalwareScoring.cpp` | PE import parsing, packer detection, composite score |
| `ScoringConfig.cpp` | INI load and default write for all weights |
| `Baseline.cpp` | `.prbl` read and write, in-memory lookup, comparison |
| `RegistryEnumerator.cpp` | Installed-program discovery for Fast Scan |
| `SecurityChecks.cpp` | Core posture checks and report writer |
| `SecurityChecksExtra.cpp` | Tasks, startup, PowerShell, firewall, audit policy, updates |
| `HashUtils.cpp` | MD5 and SHA-256 |
| `GuiComponents.cpp` | Progress bar, results list view, file dialogs, CSV parser |
| `AiSidebar.cpp`, `LLMClient.cpp` | Optional triage panel and HTTP client |
| `SettingsDialog.cpp`, `DarkMode.cpp` | Settings dialog, dark theme |

Rules for changing the code are in [CLAUDE.md](CLAUDE.md). They apply to people too.

## Contributing

Issues and pull requests are welcome. Keep changes small and in the module they belong
to. Do not add third-party dependencies without opening an issue first.

Looking for something to build? [docs/IDEAS.md](docs/IDEAS.md) lists what would help most,
in order. [ROADMAP.md](ROADMAP.md) has the long-range plan.

## License

PolyForm Noncommercial 1.0.0. See [LICENSE](LICENSE).

In plain words: anyone may use, study, change and share this software for free, for any
noncommercial purpose. Nobody may sell it, sell a changed version of it, or charge for a
product or service built on it. Companies may run it internally. Companies may not bill
clients for it. If you want to use it commercially, you do not have permission.

This is a source-available license, not an OSI-approved open source license, because
OSI licenses must allow commercial use and this one does not on purpose.
