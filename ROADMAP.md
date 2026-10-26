# Phantom Recon - Product Roadmap

> Endpoint reconnaissance, baseline integrity, and security posture assessment.

**Current version: 1.0.0 (2026-10-26). Phase 1 checkboxes verified against source on 2026-10-26.**

Phase 1, the standalone tool, is complete. The 1.0 work list from July is done:

1. ~~Fix the cancelled-scan partial save and bogus MISSING sweep (1.4)~~ done 2026-08-29.
2. ~~Gate the AI sidebar behind an explicit send-consent prompt (1.7)~~ done 2026-10-25.
3. ~~Certificate revocation checking (1.1)~~ done 2026-10-26.
4. ~~Scoring config validation and hot-reload (1.2)~~ done 2026-10-26.
5. ~~GPP cpassword, DLL search order, local account checks (1.5)~~ done 2026-10-26.
6. ~~Real scheduled-task and audit-policy checks (1.5)~~ done 2026-10-26.
7. ~~Summary report, determinate progress bar, sortable and filterable results (1.4, 1.6)~~ done 2026-10-26.

What is left is tracked item by item in [docs/IDEAS.md](docs/IDEAS.md).

**Direction (changed 2026-10-25):** Phantom Recon is free, source-available software under
the PolyForm Noncommercial license, and it stays a defensive, offline, standalone tool for
the PC it runs on (see CLAUDE.md). The July direction (a sellable consultant report, then
an enterprise agent, server and paid tiers) is withdrawn. Phases 2, 3 and 6 below are
**not planned**: they need an agent, a server or a subscription, which the project's scope
rules out. They are kept for history. Phases 4 and 5 are partly done where they fit the
standalone tool; the done items are ticked.

---

## Deployment Modes

| Mode | Interface | Baseline Source | Tasking | Output |
|------|-----------|-----------------|---------|--------|
| **Standalone** | Full Win32 GUI window | Local file on disk | User-initiated via menu | Local CSV + reports |
| **Enterprise** | System tray + GUI (permission-gated) | Centralized server (signed) | Server-issued (scheduled or human) | Server, or server + local (configurable) |

Both modes share the same scan engine, analysis modules, and security checks.
Enterprise is the same executable - just a different startup mode and event source.

---

## Phase 1 - Scan Engine (Standalone) `DONE`

Core scanning and analysis capabilities running as a local GUI application.

### 1.1 File Analysis Engine `DONE`
- [x] Recursive drive scanning (28 executable extension types):
    - [x] PE binaries: .exe, .dll, .com, .scr, .sys, .drv, .cpl, .ocx
    - [x] Installers: .msi, .msp, .mst
    - [x] Shell scripts: .bat, .cmd, .ps1, .psm1, .psd1
    - [x] VBScript / JScript (WSH): .vbs, .vbe, .js, .jse, .wsf, .wsh, .wsc
    - [x] HTML Application: .hta
    - [x] Legacy / shortcut: .pif, .lnk, .inf, .reg
- [x] File metadata: path, size, MD5 hash
- [x] Shannon entropy calculation (whole-file)
- [x] Authenticode signature verification (WinVerifyTrust)
- [x] Embedded vs catalog signature detection (CryptQueryObject PKCS7_SIGNED_EMBED)
- [x] Certificate chain analysis (CertGetCertificateChain - trust status, root CA, issuer,
      thumbprint, serial number, validity dates)
- [x] Stolen signature detection:
    - [x] SigThief / hash mismatch (TRUST_E_BAD_DIGEST - file content doesn't match signed hash)
    - [x] Certificate cloning (untrusted root CA, POSSIBLE_CLONE warning)
    - [x] Self-signed certificate detection (chain length == 1)
    - [x] Expired / revoked certificate detection
- [x] SHA-256 hashing (alongside MD5):
    - [x] Compute SHA-256 for every scanned file (dual hash: MD5 for baseline compat, SHA-256 for external lookups)
          - `ComputeFileSHA256` (BCrypt) in HashUtils.cpp
    - [x] Store in BaselineEntry and CSV output (baseline format v2 adds the field; v1 files load with empty SHA-256)
    - [x] SHA-256 diff participates in baseline comparison (Baseline::CompareEntry)
    - [x] SHA-256 in every report (HTML, JSON, CSV) and copyable from the results list, so it
          can be checked against a vendor's published hash or a reputation service by hand
    - [ ] Consider deprecating MD5 in future versions (collision-prone, not cryptographically secure)
          - kept: older baselines and the import hash format both use it
- [x] Certificate revocation checking (CRL / OCSP):
    - [x] For signed binaries: check certificate revocation status beyond expiry
    - [x] Revocation through WinVerifyTrust's chain checks: Off, Windows cache only (default,
          no network), or Online (CRL and OCSP through Windows)
    - [x] Cache revocation results per certificate thumbprint for 24 hours
          (`phantom_recon_revocation_cache.txt`)
    - [x] Offline: "Unknown (offline)" instead of a guess; portable mode never goes online
    - [x] Revoked certificate adds +2.0 to malware score (`[revocation]` in the scoring INI)
    - [x] Explicitly distrusted certificate detection
- [x] Windows catalog signatures: files signed through a security catalog (most of Windows)
      report as signed, with the catalog's signer; Store (MSIX) package files as package-signed
- [x] Signer-location cross-check (non-Microsoft signer in System32/SysWOW64/WinSxS)
- [x] Signed-in-suspicious-directory warning (temp, downloads, AppData\Local\Temp)
- [x] Known trusted root CA thumbprint verification (10 major CAs: Microsoft, DigiCert,
      GlobalSign, VeriSign, Comodo/Sectigo, Let's Encrypt, Symantec)
- [x] File version info via VS_FIXEDFILEINFO (Major.Minor.Build.Revision)
- [x] Developer/company name via StringFileInfo CompanyName (with language/codepage lookup)
- [x] File attributes: read-only, hidden (via GetFileAttributesW)
- [x] File permissions: DACL owner resolution (SID to account name) + ACE allow/deny count
      (via GetNamedSecurityInfoW)

### 1.2 Malware Scoring Engine `DONE`
- [x] PE import table parsing (full 32-bit and 64-bit support):
    - [x] DOS header validation (MZ magic)
    - [x] PE signature validation (PE\0\0)
    - [x] Optional header magic detection (PE32 vs PE32+)
    - [x] Section header parsing with RVA-to-file-offset translation
    - [x] Import descriptor table walking (OriginalFirstThunk + FirstThunk)
    - [x] Ordinal import detection (high-bit flagged thunks skipped)
    - [x] Hint/Name table reading for function name extraction
- [x] 80+ suspicious API detection across 10 categories:
    - [x] Injection: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, QueueUserAPC,
          NtCreateThreadEx, RtlCreateUserThread, SetThreadContext, NtUnmapViewOfSection (11 APIs)
    - [x] Memory manipulation: VirtualAlloc, VirtualProtect, VirtualProtectEx, HeapCreate (4 APIs)
    - [x] Dynamic resolution: GetProcAddress, LoadLibrary[Ex][A/W], LdrLoadDll (6 APIs)
    - [x] Credential theft: OpenProcessToken, AdjustTokenPrivileges, DuplicateTokenEx,
          ImpersonateLoggedOnUser, LogonUser[A/W], LsaEnumerateLogonSessions (7 APIs)
    - [x] Execution: CreateProcess[A/W], ShellExecute[A/W/ExW], WinExec, system (7 APIs)
    - [x] Persistence: RegSetValueEx[A/W], RegCreateKeyEx[A/W], CreateService[A/W] (6 APIs)
    - [x] Network: URLDownloadToFile[A/W], InternetOpen[A/W], InternetOpenUrl[A/W],
          HttpOpenRequestA, HttpSendRequestA, WSAStartup, connect, send, recv (12 APIs)
    - [x] Evasion: IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess,
          OutputDebugStringA, SetUnhandledExceptionFilter, Sleep (6 APIs)
    - [x] Crypto: CryptEncrypt/Decrypt, CryptGenKey, CryptDeriveKey, CryptAcquireContext[A/W],
          BCryptEncrypt/Decrypt (8 APIs)
    - [x] Filesystem: DeleteFile[A/W], MoveFileEx[A/W], SetFileAttributes[A/W] (6 APIs)
- [x] Weighted scoring per API (0.0-1.0 weight based on suspiciousness)
- [x] Category diversity bonus (more categories flagged = higher score)
- [x] Packing/encryption detection:
    - [x] 12 known packer families: UPX, ASPack, Themida, VMProtect, Enigma, PECompact,
          MPRESS, Petite, MEW, NSPack, ConfuserEx (.NET), SmartAssembly (.NET)
    - [x] Known packer section name matching (UPX0, UPX1, .vmp0, .Themida, .petite, etc.)
    - [x] Entry point byte pattern matching (UPX: 0x60 0xBE PUSHAD+MOV, ASPack: 0x60 0xE8 0x03)
    - [x] Per-section entropy analysis (first 4KB sampled per section)
    - [x] High-entropy code section detection (>7.0 = likely packed/encrypted)
    - [x] High-entropy data section detection (>7.2 = encrypted data or compressed resource)
    - [x] RWX section detection (Read+Write+Execute - almost never legitimate)
    - [x] Virtual/raw size ratio analysis (>10x = runtime unpacking)
    - [x] Empty executable section detection (zero raw data + executable flag = unpack target)
    - [x] Entry point section analysis (EP not in .text = suspicious)
    - [x] Low import count indicator (<=5 imports suggests packed, real imports resolved at runtime)
    - [x] Packing confidence score (0.0-1.0, threshold at 0.4 for "packed" classification)
- [x] Composite malware score (0.0-10.0 scale):
    - [x] Entropy factor: 0-2.5 points (scaled by threshold: >6.5=0.5, >6.8=1.0, >7.0=2.0, >7.5=2.5)
    - [x] Signature factor: 0-2.0 points (unsigned = +2.0)
    - [x] Hidden attribute: 0-1.0 points
    - [x] Suspicious location: 0-1.0 points (temp/downloads directories)
    - [x] Import analysis: 0-3.5 points (weighted API sum * 0.4 + category diversity * 0.15)
    - [x] Signature anomaly bumps: hash mismatch +3.0, untrusted chain +1.5
    - [x] Packing bumps: packed +1.5, RWX sections +1.0
    - [x] Hard cap at 10.0
- [x] **Configurable scoring weights** (all weights are overridable) - ScoringConfig.h/.cpp:
    - [x] Scoring config file (INI) loaded at startup - `phantom_recon_scoring.ini`
    - [x] Per-API weight overrides (change any of the 80+ API weights) - `[api_weights]` section
    - [x] Per-category max score overrides (import_score_cap, score_cap)
    - [x] Composite score formula weights (unsigned/hidden/temp-dir penalties, import multiplier,
          category diversity bonus) - `[scoring_weights]`
    - [x] Packing confidence threshold override (default 0.4) - `[packing]`
    - [x] Entropy threshold overrides (4 threshold/score levels) - `[entropy_thresholds]`
    - [x] Signature anomaly bump overrides (hash mismatch, untrusted chain, packing, RWX) - `[anomaly_bumps]`
    - [x] Standalone: config file in application directory, editable by user
    - [x] Default config ships with current values - auto-written on first run when the file is absent
    - [ ] Enterprise: scoring config distributed from server (per agent group)
          - not planned (no server; see Direction)
    - [x] Config validation: negatives become 0, NaN and infinity fall back to the default,
          and the problems are listed (`ScoringConfig::Validate`)
    - [x] Hot-reload: the INI is re-read at the start of every scan
    - [x] New sections for origin, header, script and revocation findings

### 1.3 Security Posture Audit `DONE`
- [x] Unquoted service binary paths:
    - [x] SCM enumeration (OpenSCManager + EnumServicesStatusExW)
    - [x] ImagePath extraction with intelligent exe path parsing (.exe/.sys/.dll)
    - [x] Detection of unquoted paths containing spaces (privilege escalation via path interception)
- [x] Writable service executables:
    - [x] SCM enumeration of all Win32 services
    - [x] GENERIC_WRITE access test on each service binary (CreateFileW probe)
    - [x] Reports which services have writable executables (binary planting vector)
- [x] AlwaysInstallElevated:
    - [x] HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer check
    - [x] HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer check
    - [x] Both must be set to 1 for exploitability (FAIL vs WARNING for partial)
- [x] Unattended install files (credential exposure):
    - [x] 11 common paths checked: C:\unattend.xml, C:\unattend.txt,
          C:\Windows\Panther\unattend.xml, C:\Windows\Panther\Unattend\unattend.xml,
          C:\Windows\Panther\unattended.xml, C:\Windows\System32\sysprep\sysprep.xml,
          C:\Windows\System32\sysprep\sysprep.inf, C:\Windows\System32\sysprep\unattend.xml,
          C:\Windows\system32\sysprep.inf, C:\Windows\inf\autoUnattend.xml,
          C:\Windows\Setup\Scripts\unattend.xml
    - [x] PathFileExistsW check on each
- [x] Credential Guard / LsaISO.exe:
    - [x] CreateToolhelp32Snapshot + Process32FirstW/NextW enumeration
    - [x] Case-insensitive search for lsaiso.exe
    - [x] PASS if running (Mimikatz protection active), WARNING if not
- [x] LLMNR:
    - [x] HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast
    - [x] PASS if explicitly 0, FAIL if enabled or not configured (defaults to enabled)
- [x] NBT-NS (per network adapter):
    - [x] HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces enumeration
    - [x] Per-adapter NetbiosOptions check (0=DHCP default, 1=enabled, 2=disabled)
    - [x] Reports count of enabled vs disabled adapters
- [x] mDNS:
    - [x] HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableMDNS
    - [x] PASS if 0, FAIL if enabled or not configured (defaults enabled on Win10+)
- [x] SMB signing (client-side):
    - [x] LanmanWorkstation\Parameters\RequireSecuritySignature (must be 1)
    - [x] Falls back to check EnableSecuritySignature (enabled but not required = still vulnerable)
- [x] Proxy auto-detect (WPAD):
    - [x] HKCU Internet Settings\Connections\DefaultConnectionSettings byte flag analysis
    - [x] Byte offset 8, bit 0x08 = auto-detect enabled
- [x] Security audit report:
    - [x] Full text report to file with per-check name/status/detail
    - [x] Compact UI summary with pass/fail/warn/err counts
    - [x] Report header: "Phantom Recon Security Audit Report"

### 1.4 Scan Modes `DONE`
- [x] **Baseline Scan** - Full recursive drive scan that saves a ground-truth snapshot.
      Only to be run on a verified clean system after a clean install or known-good update.
      Produces a binary baseline file (.prbl) with MD5 integrity footer.
      (Server signing is Phase 2.5 - local baselines are unsigned by design in standalone.)
- [x] **Full Scan** - Full recursive drive scan that compares every file against the
      saved baseline. Flags files as NEW (not in baseline), CHANGED (different
      MD5/SHA-256/size/signature/score), or MISSING (in baseline but gone from disk).
- [x] **Fast Scan** - Scans only installed programs enumerated from the Windows
      registry (HKLM + HKCU Uninstall keys, 64-bit and WoW6432Node). Compares
      against baseline. Faster than full scan for routine checks.
- [x] Baseline file format: binary "PRBL" with version header, entry count,
      creation timestamp, and MD5 integrity footer. Currently at version 2 (v1 files
      are read and upgraded in memory).
- [x] Baseline stores all analysis fields (full BaselineEntry) so comparison reports
      can show before/after detail for any changed field.
- [x] In-memory baseline: std::unordered_map keyed by lowercase normalized path for O(1) lookup.
- [x] Path normalization: lowercase + single backslashes for consistent matching.
- [x] Baseline save only on complete scan (no partial baselines if cancelled).
      Fixed 2026-08-29: StartScanInBackground now checks cancelScanRequested after
      ScanDirectory returns. A cancelled Baseline Scan writes nothing and leaves the existing
      .prbl untouched, and reports "Baseline Scan Cancelled" instead of "Baseline saved".
- [x] Cancelled Full Scan and Fast Scan no longer run the MISSING sweep.
      Fixed 2026-08-29 (same root cause): every baseline entry the cancelled scan never
      reached was still unseen, so GetUnseenEntries reported the whole untouched remainder
      as MISSING. Both modes now skip the sweep and report "Cancelled (partial results)".
- [x] Full/Fast scan loads baseline into memory before scanning begins.
- [x] Full/Fast scan comparison columns in CSV: Baseline Status (MATCH/NEW/CHANGED/MISSING),
      Change Details (what fields differ), Risk Delta (malware score difference).
- [x] MISSING file detection: after scan loop, iterate baseline entries not seen on disk
      (Baseline::GetUnseenEntries, appended to CSV for both Full and Fast scans).
- [x] Comparison summary report: the HTML and JSON reports carry counts per status, the
      rows with what changed and the score change, and the ATT&CK techniques seen; the
      operation panel shows the counts when a scan ends
- [x] Baseline format v3: catalog signer, revocation, import hash, fuzzy hash, download mark,
      streams, header facts, script findings, ATT&CK ids, known-good flag; v1 and v2 load
- [x] UPDATED (changed by a Microsoft-signed file) and KNOWN (new but Microsoft-signed or on
      the local known-good list) so updates do not bury real changes
- [x] Fast Scan's MISSING sweep only covers the program folders it scanned
- [x] Compare two baselines without scanning (File > Compare Two Baselines, `--diff`)
- [x] Exclusions: folder names, full paths or single files, and file types
- [x] Baseline warning dialog before a Baseline Scan ("Only run this on a verified clean system!")
      and a Yes/No overwrite confirmation on baseline import.
- [x] Stale-baseline warning (>30 days) with continue/abort prompt on Full and Fast Scan,
      and on File > Open Baseline.
- [x] Fast Scan registry enumeration (RegistryEnumerator.h/.cpp):
    - [x] HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall (64-bit programs)
    - [x] HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall (32-bit on 64-bit)
    - [x] HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall (per-user installs)
    - [x] Extract paths from: InstallLocation, DisplayIcon, UninstallString
    - [x] Deduplicate paths before scanning
    - [x] Scan each install directory for target file extensions (depth-limited, default 3 levels)
    - [x] Single-file analysis for DisplayIcon exe paths

### 1.5 Additional Security Checks `DONE`

Every check is a row in `CheckCatalog.cpp` (title, severity, ATT&CK, CIS, explanation, fix,
undo) and a function in a `SecurityChecks<Topic>.cpp` file; the audit has 51. The full list
is generated into [docs/FINDINGS.md](docs/FINDINGS.md).

- [x] Group Policy Preferences (GPP) check `gpp.cpassword`:
    - [x] Search SYSVOL for Groups.xml, Services.xml, Scheduledtasks.xml, DataSources.xml,
          Printers.xml, Drives.xml containing cpassword attributes
    - [ ] Decrypt cpassword - not doing: reporting the file is enough for the defender to
          remove it, and the tool does not recover credentials
    - [x] Report the source file path
    - [x] Applicable to domain-joined machines with access to SYSVOL (N/A otherwise)
- [x] DLL search order `dll.hijack` - partly:
    - [ ] Enumerate DLL search paths for each running process
    - [x] Writable directories on the system PATH, which privileged programs fall back to
    - [ ] Known applications that load DLLs from the current directory
    - [x] Service program folders writable by normal users
- [x] Scheduled task analysis `persist.tasks`:
    - [x] Enumerate all scheduled tasks via the COM Task Scheduler API, nested folders included
    - [x] Task actions: programs in user-writable or drop folders, encoded or downloading
          command lines (strong and weak signals; weak ones ignored for Windows' own tasks)
    - [x] Task triggers (logon, boot, recurring) shown with each finding
    - [x] Run-as account and highest privileges
    - [x] Tasks pointing to missing programs
- [x] Persistence sweep `persist.sweep`: Run and RunOnce, Startup folders, Winlogon Shell and
      Userinit, IFEO debuggers, AppInit DLLs, WMI event subscriptions, LSA packages, print
      monitors, shell extensions, COM overrides, Office add-ins, browser extensions and
      services; new entries since the last audit and baseline cross-check
- [x] Startup program enumeration (now part of `persist.sweep`):
    - [x] HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    - [x] HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    - [x] HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
    - [x] HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
    - [x] HKLM\SOFTWARE\WoW6432Node\...\Run (32-bit on 64-bit)
    - [x] Shell:Startup folder contents (per-user CSIDL_STARTUP and all-users CSIDL_COMMON_STARTUP)
    - [x] Winlogon\Shell and Winlogon\Userinit registry values
    - [x] Cross-reference startup entries against baseline (detect new persistence)
- [x] PowerShell execution policy and logging `ps.logging`:
    - [x] Check if ScriptBlockLogging is enabled
    - [x] Check if Module Logging is enabled
    - [x] Check if Transcription is enabled
    - [x] Report the transcription output path
    - [x] Check execution policy (Restricted, AllSigned, RemoteSigned, Unrestricted, Bypass)
    - [x] Check for Constrained Language Mode (via __PSLockdownPolicy env var)
- [x] Windows Firewall status `fw.profiles` (COM `INetFwPolicy2`):
    - [x] Domain / Private / Public profile status (enabled/disabled), FAIL if any is off
    - [x] Default inbound action per profile
    - [x] Count of rules
- [x] Audit policy configuration `audit.subcategories` and `audit.policy`:
    - [x] Advanced vs legacy audit policy in use (SCENoApplyLegacyAuditPolicy)
    - [x] Security event log max size (warns below 64 MB)
    - [x] CrashOnAuditFail state
    - [x] PowerShell Operational log channel enabled
    - [x] Per-subcategory auditing state through `AuditQuerySystemPolicy`
    - [x] A recommended minimum (logon, process creation, account and policy changes and
          more), with success and failure wanted per subcategory
- [x] Windows Update status `wu.status`:
    - [x] wuauserv service state
    - [x] Last successful install time (Auto Update\Results\Install\LastSuccessTime)
    - [x] Automatic updates disabled by policy (NoAutoUpdate) -> FAIL
    - [x] Pending reboot detection (RebootRequired key)
    - [x] WSUS vs Windows Update source
    - [ ] Pending updates count - needs the Windows Update Agent search, which can take
          minutes and wake the update service; the last-install age stands in for it
- [x] Local account security `acct.*`:
    - [x] Enumerate local accounts (enabled/disabled, last logon, password age)
    - [x] Default/built-in accounts that should be disabled (Guest, DefaultAccount)
    - [x] Password policy (min length, lockout threshold, maximum age)
    - [x] Whether the built-in Administrator is enabled or renamed
- [x] Platform hardening `hard.*`, `lsa.*`: BitLocker, TPM, Secure Boot, UAC, AutoPlay, Windows
      Script Host, PowerShell 2.0, Office macros, LSA protection, Credential Guard
- [x] Microsoft Defender `def.*`: real-time, tamper, cloud, definitions, exclusions, ASR,
      SmartScreen, Controlled folder access; steps aside when another antivirus is active
- [x] Network `net.*`, `cert.roots`: listening programs, SMBv1, RDP and NLA, WinRM, Remote
      Registry, hosts file, DNS servers, trusted roots against Microsoft's root program
- [x] Software `sw.outdated`: known-vulnerable and end-of-life programs, plus a user rules file
- [x] Running programs `proc.image`: Windows names in the wrong folder, wrong parents, Office
      starting a shell, drop folders, signatures, baseline hash. Nothing reads another
      program's memory.

### 1.6 GUI & UX `DONE`
- [x] Win32 GUI with "This PC", "Current operation" and "Hardening score" panels; resizable,
      everything follows the window size
- [x] Real-time scan status: current file path, files processed count, executables found count
- [x] Cancel scan support (thread-safe std::atomic<bool> flag), Cancel button and Esc
- [x] CSV export with full analysis columns (44 columns, UTF-8 with BOM, RFC 4180 quoting)
- [x] System info panel: computer name, Windows version, processor, RAM, disk space
- [x] Security audit summary in system info panel (auto-runs on startup, F5 to rerun)
- [x] Hardening score shown large, coloured, with pass, warning and fail counts
- [x] Findings window (F6): every check with status, explanation, fix and undo, copy buttons
- [x] Getting Started window on first run, with a "show at startup" box
- [x] Scan mode selection (menu-driven, no separate dialog):
    - [x] Scans menu with Take Baseline / Full Scan / Fast Scan entries
    - [x] Folder picker per scan (modern IFileOpenDialog folder picker)
    - [x] Confirmation warning for Baseline before the scan starts
    - [x] Output CSV path selector per scan, defaulting to the reports folder
    - [ ] Multi-drive selection in one scan (one root folder per run; run one scan per drive)
    - [x] Baseline file path selector: File > Settings, or File > Open Baseline for the session
- [x] Progress bar - determinate:
    - [x] Files are counted first (respecting exclusions), then the bar shows real progress
    - [x] Percentage completion in the operation info panel
    - [x] Time taken shown when the scan ends
    - [ ] Estimated time remaining while it runs
- [x] Results viewer (virtual list over `ResultsModel`, any number of rows):
    - [x] Columns: file, status, score, signature, packing, size, developer, version,
          ATT&CK, SHA-256, full path
    - [x] Colour-coded rows by score and status, in light and dark
    - [x] Load previous results from disk: File > Open Scan Results, drag and drop, or the
          command line
    - [x] Sortable by any column (click header to sort, click again to reverse)
    - [x] Double-click or Enter for the detail window (every field, each finding explained)
    - [x] Filter by status and score (needs review, new, changed, missing, score 7+, 4+)
    - [x] Search by name, path, signer or SHA-256
    - [x] Export the filtered view to CSV (Ctrl+E)
    - [x] Right-click menu: details, copy path, copy SHA-256, open location, ask the AI
- [x] Baseline management UI:
    - [x] View loaded baseline info: creation date, entry count, age in days, source path
    - [x] Load baseline via file dialog (File > Open Baseline - sets it active)
    - [x] Import baseline (copies to the active path, with overwrite confirmation)
    - [x] Export current baseline to a chosen path
    - [x] Baseline age warning (>30 days since creation) on open, Full Scan, and Fast Scan
    - [x] Active baseline name in the operation panel ("not taken yet" when missing); the
          integrity check runs on every load and a damaged file is refused with a message
- [x] Reports menu: HTML, JSON, ATT&CK Navigator layer, hide names, open the reports folder
- [x] Help > Create Sample Pack: harmless demo files and a demo baseline, scanned at once
- [x] Scans > Weekly Fast Scan: one visible user-level scheduled task, on and off

### 1.7 AI Triage Assistant `DONE`

Shipped in March 2026, not previously in this roadmap. An OpenAI-compatible LLM client plus a
slide-out sidebar that sends scan context to a networked model for analyst-facing triage.

- [x] LLM client (LLMClient.h/.cpp):
    - [x] OpenAI-compatible /v1/chat/completions over WinHTTP
    - [x] Blocking and async (callback-on-background-thread) request paths
    - [x] Configurable endpoint, model, max tokens, temperature (default 0.3 for factual output)
    - [x] TestConnection probe and last-error reporting
    - [x] Global singleton (`GetLLMClient()`)
- [x] Prompt builders:
    - [x] Per-file triage prompt (path, score, signature, packing, suspicious imports,
          signature warnings, packing indicators, entropy)
    - [x] Whole-scan summary prompt (totals, high-risk count, NEW/CHANGED/MISSING counts)
    - [x] Security audit analysis prompt
- [x] Sidebar UI (AiSidebar.h/.cpp):
    - [x] WS_EX_TOOLWINDOW popup flush to the main window's right edge, animated slide in/out
    - [x] Toggle tab on the main window edge; tracks WM_MOVE / WM_SIZE
    - [x] Chat display, input field, send button, connection status label
    - [x] Quick actions: Triage File, Scan Summary, Security Audit
- [x] Default endpoint is `http://localhost:1234` (local only). LLMConfig in LLMClient.h is the single
      source of the default; AppSettings in SettingsDialog.h copies it, so the two cannot drift (2026-10-25).
- [x] Consent gate (2026-10-25): before the first send to an endpoint that is not on this
      machine, the sidebar names the endpoint, says file paths will leave the host, and asks.
      One approval per session. Local (loopback) endpoints never prompt.
- [x] Redaction (2026-10-26): user, computer and domain names are replaced before every
      message, even to localhost (on by default, a setting)
- [x] Size cap: each message is cut to a set length (default 12,000 characters); the audit
      findings go in parts, one reply per part
- [x] Triage sends every field the scan recorded, with the plain explanation of each finding
- [x] Plain-language connection errors ("Could not connect to the AI server...")
- [ ] Local-endpoint-only enforcement option - the consent prompt covers this; a hard block
      would stop people using a model on another PC they own

### 1.8 Settings & Theming `DONE`

Also shipped in March 2026 and not previously in this roadmap.

- [x] Modal settings dialog (SettingsDialog.h/.cpp): LLM endpoint, model, max tokens,
      temperature, Test Connection button with status feedback, Save/Cancel
- [x] Settings persisted to `phantom_recon_settings.ini`, applied to the LLM singleton on load
- [x] File > Settings menu entry
- [x] Theme module (Theme.h/.cpp, replaced DarkMode): light and dark palettes, WM_CTLCOLOR*
      handlers, themed list views, progress bar, check boxes and title bars
- [x] Applied to every window: main, settings, findings, details, AI panel, dialogs
- [x] Settings for scan behavior (2026-10-26): Scanning tab with exclusions, default folder,
      baseline file, reports folder, revocation, Fast Scan depth, fuzzy hashing
- [x] Theme follows the system light/dark preference, live (WM_SETTINGCHANGE), or is set to
      dark or light in the Appearance tab
- [x] AI tab: redaction and message size; Appearance tab: Getting Started, audit at startup,
      hiding names in reports

---

### 1.9 Command line, tests and releases `DONE`

- [x] `PhantomReconCli.exe`: audit, baseline, full, fast and diff scans, sample pack,
      findings document, weekly task; HTML, JSON, Navigator, CSV and text output; exit
      codes 0 (clean), 1 (needs attention), 2 (error)
- [x] Engine split into a static library (`PhantomRecon.Core`) shared by the app, the
      console program and the tests
- [x] Automated tests (`PhantomReconTests.exe`): hashes, PE parsing, fuzzy hashing,
      baselines, comparison, the scan engine on the sample pack, CSV, the results model,
      the catalog, the score, every audit check, reports, redaction and the helpers
- [x] GitHub Actions: build with warnings as errors, tests, a command-line smoke test,
      ASCII punctuation check; tagged releases with a SHA-256; a winget manifest script
- [ ] Code signing - needs a certificate

---

## Phase 2 - Enterprise Agent `NOT PLANNED`

Not planned: an agent that takes orders from a server is outside the project's scope (see
Direction at the top). Kept for history.

Same executable, dual-mode. Enterprise mode starts minimized to the system tray and
connects to a centralized server for tasking. The full GUI window is still there -
it just starts hidden and can be opened by authorized users.

### 2.1 System Tray & Window Behavior
- [ ] System tray icon (Shell_NotifyIcon / NOTIFYICONDATA) with right-click context menu:
    - [ ] "Open Phantom Recon" - shows the main GUI window (permission-gated)
    - [ ] "Status" - submenu showing: current mode, last scan time, server connection status
    - [ ] "About" - version info, agent ID, enrollment status
    - [ ] "Exit" - admin only; standard users cannot exit the agent
- [ ] Tray icon overlays for status indication:
    - [ ] Green shield: idle, last scan clean
    - [ ] Yellow shield: idle, last scan had warnings (NEW/CHANGED files)
    - [ ] Red shield: idle, last scan had critical findings (high malware scores)
    - [ ] Spinning/animated: scan in progress
    - [ ] Gray shield: disconnected from server
- [ ] Enterprise mode: window created but hidden on startup (ShowWindow SW_HIDE)
- [ ] Tray icon double-click or "Open" menu item calls ShowWindow(SW_SHOW) + SetForegroundWindow
- [ ] WM_CLOSE in enterprise mode: ShowWindow(SW_HIDE) instead of DestroyWindow
- [ ] WM_DESTROY only on explicit "Exit" from admin or system shutdown
- [ ] Toast notifications (Shell_NotifyIcon NIF_INFO balloons, or Win10+ toast API):
    - [ ] "Scan complete: X files scanned, Y new, Z changed, W missing"
    - [ ] "Critical: file scored 9.2/10 - [filename]"
    - [ ] "Baseline update received from server"
    - [ ] "Server connection lost - operating in cached mode"
- [ ] Mode selection:
    - [ ] Command-line flag: `--enterprise` for enterprise mode, default is standalone
    - [ ] Configuration file (phantom_recon.conf) with mode setting
    - [ ] Enterprise installer pre-configures the config file with server details
    - [ ] Registry key alternative: HKLM\SOFTWARE\PhantomRecon\Mode

### 2.2 Enterprise Permission Model
- [ ] **Admin users** - Full access:
    - [ ] Open GUI window with all panels visible
    - [ ] Trigger any scan mode manually (Baseline, Full, Fast)
    - [ ] View all scan results, comparison reports, security audit
    - [ ] Modify local agent settings (output path, scan exclusions)
    - [ ] View and manage local baseline cache
    - [ ] Force check-in to server
    - [ ] View server connection details and agent enrollment info
- [ ] **Standard users** - View-only (if admin policy allows):
    - [ ] Open GUI window in read-only mode
    - [ ] View last scan results and security audit summary
    - [ ] View current scan progress (if a scan is running)
    - [ ] Cannot trigger scans, modify settings, or access baseline
    - [ ] Menu items for restricted actions are grayed out (EnableMenuItem MF_GRAYED)
- [ ] **Locked down** - No GUI access:
    - [ ] Tray icon visible with status color only
    - [ ] Double-click and "Open" menu item do nothing (or show "Access restricted" toast)
    - [ ] Agent runs silently, all tasking from server only
- [ ] Permission enforcement:
    - [ ] Agent config includes permission_level field (admin/user/locked), set by server
    - [ ] On GUI open attempt: check config permission level first
    - [ ] If server unreachable: fall back to local group membership check
          (SID S-1-5-32-544 Administrators group via CheckTokenMembership)
    - [ ] Admin override: local admin can always access GUI regardless of server config
          (safety valve - never fully lock out the machine admin)

### 2.3 Agent-Server Communication
- [ ] Protocol design:
    - [ ] TLS 1.3 over TCP (WinHTTP or Schannel for native Windows TLS)
    - [ ] JSON message format for commands and results (lightweight, debuggable)
    - [ ] Binary transfer for baseline files (length-prefixed, chunked for large files)
    - [ ] Message types: HEARTBEAT, TASK, RESULT, BASELINE_PUSH, CONFIG_UPDATE, ALERT
- [ ] Agent enrollment:
    - [ ] First-run enrollment: agent sends machine info (hostname, OS version, IP, MAC,
          domain membership, installed software summary) to server
    - [ ] Server returns: agent ID (UUID), TLS client certificate, initial config
    - [ ] Enrollment requires a one-time enrollment key (prevents unauthorized agents)
    - [ ] Re-enrollment if agent ID is revoked or certificate expires
- [ ] Configuration at install time:
    - [ ] Server IP/hostname
    - [ ] Server port (default: 7443)
    - [ ] Enrollment key (one-time use, generated by server admin)
    - [ ] TLS CA certificate for server verification (pinned or enterprise CA)
    - [ ] Can be provided via: installer MSI properties, config file, or registry
- [ ] Heartbeat / check-in:
    - [ ] Configurable interval (default: 60 seconds, server can adjust per agent)
    - [ ] Heartbeat payload: agent ID, current status (idle/scanning/error), uptime,
          last scan timestamp, pending result count
    - [ ] Server response: acknowledged, or piggyback a task command
    - [ ] Missed heartbeat detection: server marks agent as "offline" after N missed beats
    - [ ] Agent-side: if server unreachable, back off exponentially (60s -> 120s -> 240s -> max 30min)
    - [ ] Reconnection: on successful reconnect, send queued results and request pending tasks
- [ ] Task receipt and execution:
    - [ ] Server pushes task in heartbeat response or via dedicated task channel
    - [ ] Task structure: task_id (UUID), task_type (BASELINE/FULL_SCAN/FAST_SCAN/SECURITY_AUDIT),
          parameters (target drives, scan exclusions, baseline version), priority, deadline
    - [ ] Agent acknowledges task receipt, updates status to "scanning"
    - [ ] Agent calls the same functions as standalone:
          StartScanInBackground(mode, ...) or RunSecurityAuditInBackground(...)
    - [ ] Task cancellation: server can send CANCEL command, agent sets cancelScanRequested
    - [ ] Task queuing: if agent is already scanning, queue the task (FIFO, max queue depth 5)
- [ ] Result reporting:
    - [ ] On scan completion: serialize results to JSON and send to server
    - [ ] Results include: all CSV columns per file, comparison data, security audit results
    - [ ] Large result sets: chunked upload (max 1MB per chunk), server reassembles
    - [ ] Compression: gzip the JSON payload before sending (typical 5-10x reduction)
    - [ ] Retry on failure: exponential backoff, local result cache until confirmed received
    - [ ] Server acknowledges receipt with result_id, agent can discard local cache
- [ ] Offline operation:
    - [ ] If server unreachable, agent continues scheduled scans using cached config
    - [ ] Results stored locally in a queue directory (encrypted at rest)
    - [ ] On reconnection, queued results sent in chronological order
    - [ ] Cached baseline used for comparison (last known good from server)

### 2.4 Enterprise Output Modes
- [ ] **Server only** (default for enterprise):
    - [ ] Scan results sent to server, no local CSV or report files written
    - [ ] Minimizes disk footprint on endpoint
    - [ ] Local result queue is temporary (deleted after server confirms receipt)
    - [ ] Security audit results: sent to server only, not written to local file
    - [ ] Baseline file: cached locally (required for comparison) but stored in
          protected directory with restricted ACLs
- [ ] **Server + local storage**:
    - [ ] Everything from "server only" PLUS local file output identical to standalone
    - [ ] CSV files, comparison reports, security audit reports written to configured path
    - [ ] Useful for environments requiring local forensic artifacts
    - [ ] Useful for compliance requirements that mandate local logging
- [ ] Configuration:
    - [ ] Output mode set server-side per agent or per agent group
    - [ ] Pushed to agent as part of config during enrollment or config update
    - [ ] Local storage path configurable (default: %ProgramData%\PhantomRecon\output\)
    - [ ] Local storage retention policy: keep last N scans, or keep for N days, or unlimited
    - [ ] Disk usage cap: if local storage exceeds configured limit, oldest results purged

### 2.5 Server-Managed Baselines
- [ ] Baseline workflow:
    - [ ] Sys admin creates baseline on a golden image / known-clean reference machine
    - [ ] Baseline uploaded to centralized server
    - [ ] Server signs the baseline with its private key (RSA-2048 or Ed25519)
    - [ ] Server distributes signed baseline to enrolled agents (push or pull model)
    - [ ] Agent verifies server signature before accepting baseline
- [ ] Baseline integrity:
    - [ ] Server embeds its signature in the .prbl file footer (after the MD5 checksum)
    - [ ] Agent has the server's public key (received during enrollment)
    - [ ] On baseline load: verify MD5 integrity checksum, then verify server signature
    - [ ] Reject unsigned baselines in enterprise mode (only server-signed accepted)
    - [ ] Reject baselines with invalid signatures (tampering detection)
    - [ ] Log and alert on any baseline rejection (possible MCA activity)
- [ ] Baseline versioning:
    - [ ] Each baseline has a version number (monotonically increasing, set by server)
    - [ ] Server tracks which version each agent has
    - [ ] Agent reports its baseline version in heartbeat
    - [ ] Server can push updated baseline when new version is available
    - [ ] Agent will not downgrade baseline version (prevents rollback attacks)
- [ ] Standalone override:
    - [ ] In standalone mode, local baselines are accepted without server signature
    - [ ] If an enterprise agent loses server connectivity, it continues using its
          last valid cached baseline (does not fall back to unsigned)

### 2.6 Anti-Tampering (Enterprise)
- [ ] Agent binary integrity:
    - [ ] On startup: compute own binary hash and compare against expected value
    - [ ] Expected hash stored in protected registry key or TPM-backed storage
    - [ ] If mismatch: alert to server (if reachable), log locally, continue running
          but flag all results as "agent integrity compromised"
- [ ] Configuration protection:
    - [ ] Config file encrypted with machine-specific key (DPAPI or similar)
    - [ ] Server signs config updates; agent verifies before applying
    - [ ] Config file ACL: readable only by SYSTEM and local Administrators
    - [ ] Config change detection: hash check on every read
- [ ] Baseline protection:
    - [ ] Baseline file stored in %ProgramData%\PhantomRecon\baselines\ with restricted ACLs
    - [ ] Server signature required (see 2.5)
    - [ ] File system watcher (ReadDirectoryChangesW) for tamper detection on baseline file
    - [ ] If baseline is modified externally: reject it, alert server, request fresh copy
- [ ] Process protection:
    - [ ] Agent runs as a Windows service (auto-start, recovery options)
    - [ ] Service recovery: restart on failure (1st: immediate, 2nd: 30s, 3rd: 60s)
    - [ ] Anti-kill: service configured with failure actions, monitored by server via heartbeat
    - [ ] If agent process is killed: server detects missed heartbeats, alerts admin
- [ ] Tamper alerting:
    - [ ] All tamper events logged locally (encrypted log file)
    - [ ] Tamper events sent to server as priority ALERT messages
    - [ ] Alert types: binary modified, config modified, baseline modified, process killed,
          service stopped, agent downgraded

### 2.7 Enterprise Installer
- [ ] MSI installer package:
    - [ ] Silent install support (/quiet /norestart)
    - [ ] Installer properties for server config: SERVER_HOST, SERVER_PORT, ENROLLMENT_KEY
    - [ ] Installs agent as Windows service (auto-start)
    - [ ] Creates protected directories (%ProgramData%\PhantomRecon\)
    - [ ] Sets appropriate ACLs on install directory and data directories
    - [ ] Registers system tray application to start with user logon
    - [ ] Uninstall requires admin privileges
- [ ] Group Policy deployment:
    - [ ] MSI compatible with GPO software deployment
    - [ ] ADMX template for PhantomRecon policy settings
    - [ ] Registry-based configuration for domain environments
- [ ] SCCM / Intune deployment:
    - [ ] Detection rules for deployment verification
    - [ ] Configuration baselines for compliance monitoring

---

## Phase 3 - Centralized Server `NOT PLANNED`

Not planned: a server is outside the project's scope (see Direction at the top). Kept for
history.

The management server for enterprise Phantom Recon deployments.
Provides centralized tasking, result aggregation, baseline management, and fleet visibility.

### 3.1 Server Architecture
- [ ] Technology stack:
    - [ ] Backend: Python (FastAPI or Flask) - aligns with project scripting preference
    - [ ] Database: PostgreSQL for structured data (agents, tasks, results, baselines)
    - [ ] File storage: local filesystem or S3-compatible for baseline files and raw results
    - [ ] Message queue: Redis or RabbitMQ for task distribution (optional, direct DB polling works)
    - [ ] Frontend: Web dashboard (React or plain HTML/JS - TBD)
- [ ] API design:
    - [ ] REST API for dashboard and external integrations
    - [ ] WebSocket or long-poll endpoint for agent communication
    - [ ] All endpoints authenticated (API key for agents, session token for dashboard users)
    - [ ] Rate limiting per agent and per dashboard user
- [ ] Data model:
    - [ ] Agents table: agent_id, hostname, os_version, ip, mac, domain, enrollment_date,
          last_heartbeat, status, baseline_version, config_version, agent_version
    - [ ] Agent groups table: group_id, name, description, config (scan schedule, output mode,
          permission level, baseline version)
    - [ ] Tasks table: task_id, agent_id, task_type, parameters, status (pending/running/completed/
          failed/cancelled), created_at, started_at, completed_at, result_id
    - [ ] Results table: result_id, task_id, agent_id, scan_type, total_files, new_count,
          changed_count, missing_count, match_count, highest_score, created_at
    - [ ] Result details table: result_id, file_path, baseline_status, malware_score,
          risk_delta, all analysis fields (normalized from CSV columns)
    - [ ] Baselines table: baseline_id, version, created_by, created_at, file_size,
          entry_count, signature_hash, storage_path
    - [ ] Security audit results table: result_id, agent_id, check_name, status, detail,
          created_at
    - [ ] Alerts table: alert_id, agent_id, alert_type, severity, message, created_at,
          acknowledged_by, acknowledged_at
    - [ ] Audit log table: log_id, user_id, action, target, detail, timestamp

### 3.2 Agent Management
- [ ] Agent dashboard:
    - [ ] Table of all enrolled agents with sortable columns
    - [ ] Status indicators: online (green), offline (yellow >5min), dead (red >1hr)
    - [ ] Last heartbeat timestamp, last scan timestamp, baseline version
    - [ ] Quick actions: trigger scan, push baseline, update config, revoke agent
    - [ ] Agent detail view: full machine info, scan history, alert history
- [ ] Agent groups:
    - [ ] Create groups (e.g., "Workstations", "Servers", "Finance Dept", "IT Admin")
    - [ ] Assign agents to groups (an agent can be in multiple groups)
    - [ ] Group-level configuration: scan schedule, output mode, permission level
    - [ ] Group-level tasking: "scan all agents in group X"
    - [ ] Group-level baseline assignment: all agents in a group get the same baseline
- [ ] Agent lifecycle:
    - [ ] Enrollment approval workflow (auto-approve or manual approval)
    - [ ] Agent decommission (revoke enrollment, remove from fleet)
    - [ ] Agent version tracking and upgrade push
    - [ ] Certificate rotation (automated renewal before expiry)

### 3.3 Task Management
- [ ] Scheduled scans:
    - [ ] Cron-style scheduling (e.g., "Full Scan every Sunday 2am", "Fast Scan daily 6am")
    - [ ] Schedules assigned per agent group
    - [ ] Staggered execution: randomize start time within a window to avoid fleet-wide I/O spike
    - [ ] Maintenance windows: only scan during specified hours
    - [ ] Recurring security audits (e.g., weekly)
- [ ] Manual task dispatch:
    - [ ] Select individual agents or agent groups
    - [ ] Choose task type: Baseline, Full Scan, Fast Scan, Security Audit
    - [ ] Set parameters: target drives, scan exclusions, priority
    - [ ] "Scan now" button with confirmation
    - [ ] Bulk operations: "run security audit on all agents"
- [ ] Task monitoring:
    - [ ] Real-time task status dashboard (pending, running, completed, failed)
    - [ ] Progress tracking per agent (files scanned, percentage if available)
    - [ ] Task cancellation from dashboard
    - [ ] Task history with filtering by agent, type, date range, status
    - [ ] Failed task retry (manual or automatic)

### 3.4 Baseline Management
- [ ] Baseline creation workflow:
    - [ ] Upload .prbl file from golden image machine
    - [ ] Server validates format and integrity checksum
    - [ ] Server signs the baseline with its private key
    - [ ] Assign a version number (auto-increment)
    - [ ] Store in server-side file storage
- [ ] Baseline distribution:
    - [ ] Push baseline to specific agents or agent groups
    - [ ] Agents download baseline on next heartbeat (pull model) or immediate push
    - [ ] Progress tracking: which agents have received the new baseline
    - [ ] Rollback: push a previous baseline version if needed (but agent won't downgrade
          version number - requires a new version with old content)
- [ ] Baseline comparison:
    - [ ] Server-side baseline diff: compare two baseline versions to see what changed
    - [ ] Useful for validating that a new baseline is correct before fleet-wide push
    - [ ] Show added/removed/changed files between baseline versions

### 3.5 Results & Reporting
- [ ] Fleet-wide dashboard:
    - [ ] Aggregate security posture score across all agents
    - [ ] Heat map: agents color-coded by worst finding (green/yellow/red)
    - [ ] Top-N agents with highest malware scores
    - [ ] Top-N most common NEW files across fleet (potential threat spreading)
    - [ ] Top-N most common CHANGED files (potential supply chain compromise)
    - [ ] Security audit compliance percentage (% of agents passing each check)
- [ ] Individual agent results:
    - [ ] Scan history timeline with drill-down
    - [ ] File-level detail for any scan result
    - [ ] Baseline comparison detail (before/after for changed files)
    - [ ] Security audit history with trend (was this check passing last week?)
- [ ] Alert management:
    - [ ] Alert rules engine:
        - [ ] Malware score threshold (e.g., score > 7 on any file -> critical alert)
        - [ ] NEW file count threshold (e.g., > 50 new files -> suspicious)
        - [ ] Specific file name or path patterns (e.g., mimikatz.exe, procdump.exe)
        - [ ] Security audit failures (e.g., AlwaysInstallElevated FAIL -> alert)
        - [ ] Agent tamper events (binary modified, service stopped)
        - [ ] Agent offline for > N minutes
        - [ ] Baseline rejection (signature invalid)
    - [ ] Alert delivery:
        - [ ] In-dashboard notification bell with unread count
        - [ ] Email notifications (SMTP integration)
        - [ ] Webhook notifications (Slack, Teams, PagerDuty, generic HTTP POST)
        - [ ] Syslog forwarding (CEF or LEEF format for SIEM integration)
    - [ ] Alert lifecycle: new -> acknowledged -> investigating -> resolved
    - [ ] Alert suppression rules (don't alert on known-good patterns)
- [ ] Historical trending:
    - [ ] Baseline drift over time (graph: NEW/CHANGED/MISSING counts per scan)
    - [ ] Malware score distribution over time
    - [ ] Security audit compliance trend per check
    - [ ] Agent fleet growth/churn over time
- [ ] Export & reporting:
    - [ ] PDF executive summary report (fleet health, top findings, compliance score)
    - [ ] CSV bulk export (all scan results for a date range)
    - [ ] Scheduled report generation (weekly/monthly executive summary via email)
    - [ ] Per-agent detailed report (all findings for one machine)
    - [ ] Compliance report (security audit results mapped to frameworks: CIS, NIST, STIG)

### 3.6 Access Control & Security
- [ ] Role-based access control (RBAC):
    - [ ] **Server Admin**: full access - manage agents, baselines, tasks, users, server config
    - [ ] **Analyst**: view all results, trigger scans, manage alerts, export reports.
          Cannot manage users, server config, or sign baselines.
    - [ ] **Viewer**: read-only access to dashboards and reports. Cannot trigger actions.
    - [ ] **API-only**: service account for SIEM/SOAR integration (scoped API key)
    - [ ] Custom roles: configurable permission sets (optional, future)
- [ ] Authentication:
    - [ ] Local accounts (username + bcrypt password hash)
    - [ ] LDAP / Active Directory integration (domain auth)
    - [ ] SAML / OIDC SSO integration (Okta, Azure AD, etc.)
    - [ ] Multi-factor authentication (TOTP - Google Authenticator, Authy)
    - [ ] Session management: configurable timeout, concurrent session limit
- [ ] Audit logging:
    - [ ] Every user action logged: login, logout, task creation, baseline upload,
          config change, alert acknowledgment, report export, agent revocation
    - [ ] Log includes: user, timestamp, action, target, source IP, detail
    - [ ] Audit log is append-only (cannot be deleted by any user)
    - [ ] Audit log export for external archival
- [ ] Server hardening:
    - [ ] TLS-only (no plaintext HTTP)
    - [ ] CSRF protection on all state-changing endpoints
    - [ ] Input validation and parameterized queries (SQL injection prevention)
    - [ ] Rate limiting on authentication endpoints (brute force prevention)
    - [ ] Secrets management: private signing key encrypted at rest, loaded into memory only
    - [ ] Database connection encryption

### 3.7 Network Security Checks (Fleet-wide)
- [ ] WPAD DNS entry verification:
    - [ ] Server queries internal DNS for "wpad" record
    - [ ] If no WPAD record exists: flag as risk (attacker can register it)
    - [ ] If WPAD record exists: verify it points to legitimate corporate proxy
    - [ ] Cross-reference with per-agent WPAD check results
- [ ] Private VLAN compliance:
    - [ ] Agent-side: periodic ARP scan or ping sweep of local subnet
    - [ ] Report which peer workstations are reachable
    - [ ] Server aggregates: identify environments where workstations can talk to each other
    - [ ] Flag environments lacking private VLANs (lateral movement risk)
    - [ ] Whitelist expected peer communication (e.g., print servers, file shares)
- [ ] Group Policy compliance aggregation:
    - [ ] Aggregate per-agent security audit results across the fleet
    - [ ] Dashboard: "85% of agents have LLMNR disabled, 15% do not"
    - [ ] Drill down to non-compliant agents per check
    - [ ] Track compliance improvement over time
    - [ ] Export compliance matrix (agents × checks)

### 3.8 Server Deployment
- [ ] Docker container:
    - [ ] Dockerfile for server + dependencies
    - [ ] docker-compose.yml with PostgreSQL + Redis + server
    - [ ] Volume mounts for persistent data (DB, baselines, certificates)
- [ ] Bare metal / VM:
    - [ ] Installation script (Python venv + systemd service or Windows service)
    - [ ] Configuration wizard for initial setup (DB connection, TLS cert, admin account)
- [ ] High availability (future):
    - [ ] Stateless server design (all state in DB) - horizontal scaling via load balancer
    - [ ] Database replication (PostgreSQL streaming replication or managed DB)
    - [ ] Baseline file storage on shared filesystem or object storage

### 3.9 Fleet-Wide Binary Approval & Reputation
- [ ] NEW file server query (agent -> enterprise server):
    - [ ] When agent detects a file with BaselineStatus=NEW during Full/Fast scan:
        - [ ] Before reporting as unknown, query enterprise server: "have you seen hash X?"
        - [ ] Request payload: SHA-256 hash, file size, signer, version, original filename
        - [ ] Server responds with one of: APPROVED, DENIED, UNKNOWN, PENDING_REVIEW
    - [ ] Agent behavior per server response:
        - [ ] APPROVED -> treat as known-good, lower malware score, mark as "fleet-approved" in CSV
        - [ ] DENIED -> treat as known-bad, raise malware score (+5.0), immediate alert
        - [ ] UNKNOWN -> report as NEW (current behavior), submit metadata to server for review
        - [ ] PENDING_REVIEW -> report as NEW with note "awaiting admin review"
    - [ ] Caching: agent caches server responses locally (TTL configurable, default 24h)
    - [ ] Offline fallback: if server unreachable, treat as UNKNOWN (don't block scan progress)
- [ ] Fleet-wide binary visibility (server-side):
    - [ ] Server aggregates all NEW file reports from all agents
    - [ ] Dashboard: "Binary X (hash Y) was seen on 47 of 200 agents in the last 24 hours"
    - [ ] Deployment pattern detection:
        - [ ] Same hash appearing on many agents in a short window -> likely software deployment
        - [ ] Same hash appearing on one agent only -> targeted drop or user-installed
        - [ ] Gradual spread across agents over days -> possible lateral movement / worm behavior
    - [ ] Auto-classification heuristics:
        - [ ] Signed by trusted vendor + appeared on >N agents + low malware score -> auto-suggest APPROVED
        - [ ] Unsigned + high entropy + appeared on 1 agent only -> auto-suggest DENIED
        - [ ] Heuristics are suggestions only - admin must confirm (no auto-approve by default)
- [ ] Admin approval workflow:
    - [ ] Binary review queue: list of UNKNOWN binaries awaiting admin decision
    - [ ] Per-binary detail view: hash, size, signer, version, malware score, agent count,
          first seen timestamp, spread pattern, YARA matches (if any), VT results (if integrated)
    - [ ] Admin actions:
        - [ ] **Approve** - marks binary as known-good across the entire fleet
        - [ ] **Deny** - marks binary as known-bad, triggers alert on all agents that have it
        - [ ] **Approve for group** - approve only for specific agent groups (e.g., "IT Admin" group
              gets dev tools approved, but "Finance" group does not)
        - [ ] **Defer** - leave as UNKNOWN, request more info (trigger deeper scan on one agent)
    - [ ] Approval metadata: who approved, when, reason/justification (audit trail)
    - [ ] Approval can be revoked: admin can change APPROVED -> DENIED if new intel emerges
    - [ ] Bulk approve: select multiple binaries from same vendor/deployment and approve in batch
- [ ] Fleet approval database:
    - [ ] Server maintains hash -> approval status mapping (SHA-256 keyed)
    - [ ] Includes: hash, approval status, approved_by, approved_at, signer, version, notes
    - [ ] Versioned: each approval change creates a new version (full audit history)
    - [ ] Agents sync approval database periodically (delta updates via heartbeat)
    - [ ] Approval database is separate from baseline - baseline = per-machine ground truth,
          approval database = fleet-wide binary reputation
- [ ] Approval propagation:
    - [ ] When admin approves binary X on one machine's alert:
        - [ ] Server updates fleet approval database
        - [ ] All agents with binary X in their next scan: status changes from NEW -> APPROVED
        - [ ] Agents that already reported binary X: server retroactively updates their results
        - [ ] New agents encountering binary X: immediate APPROVED response on query
    - [ ] Time-bounded approvals (optional):
        - [ ] "Approve for 90 days" - auto-expire, re-queue for review
        - [ ] Useful for temporary tools, contractor software, penetration testing tools
- [ ] Integration with baseline workflow:
    - [ ] When building a new baseline: auto-populate APPROVED binaries from fleet approval DB
    - [ ] Baseline + approval DB = complete trust model (baseline is per-machine, approval is fleet-wide)
    - [ ] On Full/Fast scan: check baseline first (O(1) local), then check approval DB (O(1) local cache),
          then query server (network, only for cache misses)
    - [ ] Lookup priority: baseline MATCH -> fleet APPROVED -> server query -> UNKNOWN

---

## Phase 4 - Threat Intelligence & External Integration `PARTLY DONE`

Status 1.0.0: ATT&CK mapping (4.4) and most of the static analysis (4.7) are done. 4.3 is
covered offline by the outdated-software check (a reviewed table of vulnerable versions and
end-of-life products, plus a user rules file); no CVE database is queried. Anything that
sends hashes or files to an online service (4.1) stays out until it can be strictly opt-in
with a prompt per use.

### 4.1 VirusTotal Integration
- [ ] Hash lookup (most common, lowest API cost):
    - [ ] On scan completion: batch all unique MD5/SHA256 hashes
    - [ ] Query VT API v3 /files/{hash} for each hash
    - [ ] Rate limiting: free API = 4 requests/min, premium = 1000/min
    - [ ] Cache VT results locally (hash -> result, TTL configurable, default 7 days)
    - [ ] Store: detection count, detection names, first_seen, last_analysis_date, reputation
    - [ ] Display in results: "VT: 5/72 detections" alongside malware score
- [ ] File upload (for unknown files):
    - [ ] If hash not found in VT: optionally upload the file for analysis
    - [ ] Only upload files above a configurable malware score threshold (e.g., >5.0)
    - [ ] Max file size for upload (VT limit: 650MB, practical limit: 32MB for speed)
    - [ ] Upload requires explicit opt-in (privacy concern - files leave the network)
    - [ ] Enterprise mode: upload decision controlled by server policy
    - [ ] Standalone mode: prompt user before uploading
- [ ] VT API key management:
    - [ ] Standalone: user enters API key in settings, stored encrypted (DPAPI)
    - [ ] Enterprise: API key configured server-side, agents proxy VT requests through server
          (single API key for the fleet, server handles rate limiting and caching)
    - [ ] Support for no API key (VT integration disabled, no external calls)
- [ ] VT enrichment in reports:
    - [ ] CSV column: VT Detections (e.g., "12/72"), VT Link (permalink to VT report)
    - [ ] Comparison reports: flag files where VT detections increased since baseline
    - [ ] Alert rule: "VT detections > 0 on any NEW file" -> immediate alert
- [ ] VT intelligence (premium API features):
    - [ ] Behavior reports (sandbox analysis results)
    - [ ] YARA livehunt results for matching files
    - [ ] Community comments and tags
    - [ ] Related samples (similar files by content or behavior)

### 4.2 YARA Rule Integration
- [ ] YARA engine embedding:
    - [ ] Link libyara into Phantom Recon (static or dynamic)
    - [ ] Compile YARA rules at scan startup (or cache compiled rules)
    - [ ] Scan each file against all loaded rules
    - [ ] Report: rule name, tags, metadata, matched strings
- [ ] Rule management:
    - [ ] Standalone: load .yar files from a configured directory
    - [ ] Enterprise: server distributes YARA rule packages to agents
    - [ ] Rule versioning: agents report which rule version they have
    - [ ] Built-in rule pack: common malware families, packers, exploits
    - [ ] Custom rules: analyst writes rules in server dashboard, pushes to fleet
- [ ] YARA in scoring:
    - [ ] YARA match contributes to malware score (configurable weight per rule)
    - [ ] Rules tagged "critical" automatically flag file as score 10.0
    - [ ] Rules tagged "informational" noted but don't affect score
- [ ] Performance:
    - [ ] YARA scan adds ~10-50ms per file depending on rule count
    - [ ] Optional: only YARA-scan files above a malware score threshold
    - [ ] Optional: only YARA-scan PE files (skip .bat, .cmd, etc.)

### 4.3 CVE & Version Intelligence
- [ ] Software version -> CVE lookup:
    - [ ] For each scanned file with version info: query a CVE database
    - [ ] Match by: developer name + product name + version (from PE version resource)
    - [ ] Data sources: NVD (National Vulnerability Database) API, or local mirror
    - [ ] Report: CVE ID, severity (CVSS score), description, published date
    - [ ] Flag files with known critical CVEs (CVSS >= 9.0)
- [ ] Update availability check:
    - [ ] For identified software: check if a newer version exists
    - [ ] Compare installed version against latest known version
    - [ ] Data source: NVD, vendor advisories, or curated update database
    - [ ] Report: "Adobe Reader 2021.007 installed, 2024.002 available (fixes CVE-2023-XXXX)"
- [ ] CVE in scoring:
    - [ ] Known critical CVE adds +2.0 to malware score (vulnerable software = risk)
    - [ ] Known exploited CVE (CISA KEV) adds +3.0
    - [ ] Outdated software with no known CVEs: informational note only

### 4.4 MITRE ATT&CK Mapping `DONE (standalone)`

Status 1.0.0: every import, packing, header, origin, script and signature finding and every
audit check carries technique ids, shown in the list, the detail window, the CSV, the HTML
and JSON reports, and a Navigator layer (`--navigator`, Reports menu). Where the shipped
mapping differs from the plan below: RegSetValueEx maps to T1112 (Modify Registry, the
honest reading of the API alone); NtCreateThreadEx maps to T1055; GetProcAddress and
LoadLibrary map to T1106 only; CryptGenKey maps to T1486 only. The technique table holds
id and name, not tactics or detection guidance. The Navigator layer export is done for
the standalone tool; the fleet-wide items stay with the withdrawn server phases.
- [x] Data model:
    - [x] ATT&CK technique database embedded in agent (JSON or compiled lookup table)
    - [ ] Updated periodically from server (enterprise) or manual update (standalone)
    - [ ] Covers Enterprise ATT&CK matrix (Windows platform focus) - the table holds only the
          techniques the findings point to, about eighty, not the whole matrix
    - [ ] Each technique entry: ID, name, tactic(s), description, detection guidance
- [x] Technique tagging at the source:
    - [x] Add `techniqueId` field to `SuspiciousImport` struct (data change, not code change)
    - [x] Add `techniqueId` field to `SecurityCheckResult` struct
    - [x] Add `techniqueIds` vector to `PackingAnalysisResult`
    - [x] Each detection artifact tagged at creation time, carried through to reporting
- [x] Import table -> ATT&CK mappings (per-API):
    - [x] VirtualAllocEx / WriteProcessMemory / CreateRemoteThread -> T1055 (Process Injection)
    - [x] CreateRemoteThreadEx / NtCreateThreadEx -> T1055.003 (Thread Execution Hijacking)
    - [x] QueueUserAPC / NtQueueApcThread -> T1055.004 (Asynchronous Procedure Call)
    - [x] NtUnmapViewOfSection -> T1055.012 (Process Hollowing)
    - [x] SetThreadContext -> T1055.003 (Thread Execution Hijacking)
    - [x] GetProcAddress / LoadLibrary* / LdrLoadDll -> T1106 (Native API), T1129 (Shared Modules)
    - [x] OpenProcessToken / AdjustTokenPrivileges -> T1134 (Access Token Manipulation)
    - [x] DuplicateTokenEx -> T1134.001 (Token Impersonation/Theft)
    - [x] ImpersonateLoggedOnUser -> T1134.001
    - [x] LsaEnumerateLogonSessions -> T1003 (OS Credential Dumping)
    - [x] CreateProcess* / ShellExecute* / WinExec -> T1106 (Native API)
    - [x] system() -> T1059.003 (Windows Command Shell)
    - [x] RegSetValueEx* / RegCreateKeyEx* -> T1547.001 (Registry Run Keys)
    - [x] CreateService* -> T1543.003 (Windows Service)
    - [x] URLDownloadToFile* -> T1105 (Ingress Tool Transfer)
    - [x] InternetOpen* / HttpOpenRequest* / HttpSendRequest* -> T1071.001 (Web Protocols)
    - [x] WSAStartup / connect / send / recv -> T1095 (Non-Application Layer Protocol)
    - [x] IsDebuggerPresent / CheckRemoteDebuggerPresent -> T1622 (Debugger Evasion)
    - [x] NtQueryInformationProcess -> T1622 / T1082 (System Information Discovery)
    - [x] CryptEncrypt / BCryptEncrypt -> T1486 (Data Encrypted for Impact)
    - [x] CryptGenKey / CryptDeriveKey -> T1027 (Obfuscated Files) / T1486
    - [x] DeleteFile* -> T1070.004 (File Deletion)
    - [x] SetFileAttributes* -> T1564.001 (Hidden Files and Directories)
- [x] Security audit -> ATT&CK mappings:
    - [x] Unquoted service paths -> T1574.009 (Path Interception by Unquoted Path)
    - [x] Writable service executables -> T1574.010 (Services File Permissions Weakness)
    - [x] AlwaysInstallElevated -> T1218.007 (System Binary Proxy Execution: Msiexec)
    - [x] Unattended install files -> T1552.001 (Credentials In Files)
    - [x] Credential Guard disabled -> T1003.001 (LSASS Memory) - environment is vulnerable
    - [x] LLMNR enabled -> T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)
    - [x] NBT-NS enabled -> T1557.001
    - [x] mDNS enabled -> T1557 (Adversary-in-the-Middle)
    - [x] SMB signing not required -> T1557.001 (enables relay after poisoning)
    - [x] WPAD auto-detect enabled -> T1557.001 / T1090.001 (Internal Proxy)
    - [x] (Future) Startup programs -> T1547.001 (Registry Run Keys / Startup Folder)
    - [x] (Future) Scheduled tasks -> T1053.005 (Scheduled Task)
    - [x] (Future) PowerShell logging disabled -> T1059.001 (PowerShell) - blind spot
    - [x] (Future) Firewall disabled -> T1562.004 (Disable or Modify System Firewall)
    - [x] (Future) Audit policy gaps -> T1562.002 (Disable Windows Event Logging)
- [x] Packing / static analysis -> ATT&CK mappings:
    - [x] Packed binary detected -> T1027.002 (Software Packing)
    - [x] High-entropy sections -> T1027 (Obfuscated Files or Information)
    - [x] RWX sections -> T1055 (Process Injection - self-modifying code)
    - [x] Entry point in non-.text section -> T1027.002
    - [x] Low import count -> T1027.002 / T1106 (dynamic API resolution)
    - [x] UPX/Themida/VMProtect detected -> T1027.002 (specific packer noted)
    - [ ] (Future) YARA match -> technique depends on rule metadata tag
    - [x] (Future) Embedded executable in resources -> T1027.009 (Embedded Payloads)
    - [ ] (Future) Suspicious strings (PowerShell commands) -> T1059.001
- [x] Signature analysis -> ATT&CK mappings:
    - [x] Hash mismatch (SigThief) -> T1553.002 (Code Signing - stolen signature)
    - [x] Untrusted root / cert cloning -> T1553.002 (Code Signing - forged certificate)
    - [x] Self-signed certificate -> T1587.002 (Develop Capabilities: Code Signing Certs)
    - [x] Signer-location mismatch -> T1036.005 (Match Legitimate Name or Location)
    - [x] Signed in temp directory -> T1036 (Masquerading)
- [x] ATT&CK reporting - standalone:
    - [x] Per-file: list of mapped technique IDs and names
    - [x] CSV columns: "ATT&CK Techniques" (comma-separated IDs)
    - [x] Summary report section: technique frequency table
    - [x] Top-N most prevalent techniques across all scanned files
- [ ] ATT&CK reporting - enterprise (server):
    - [ ] Fleet-wide technique heat map (which techniques are seen across all agents)
    - [ ] Per-agent technique coverage (what can this agent detect?)
    - [ ] Technique trend over time (is T1055 appearing more frequently?)
    - [ ] Tactic-level summary: "Execution: 12 detections, Defense Evasion: 45 detections"
    - [x] ATT&CK Navigator layer export:
        - [x] JSON format compatible with MITRE ATT&CK Navigator (navigator.mitre-engenuity.org)
        - [x] Color-coded by: detection count (gradient), or binary detected/not-detected
        - [ ] Separate layers for: "what we detect" vs "what we found" vs "gaps"
        - [x] Exportable for inclusion in customer reports and presentations
    - [ ] Technique-to-finding drill-down: click a technique -> see all files/agents that triggered it

### 4.5 MITRE D3FEND Mapping (Defensive Techniques)
- [ ] Map Phantom Recon capabilities to D3FEND:
    - [ ] File hashing (MD5 + SHA-256) -> D3-FH (File Hashing)
    - [ ] Signature verification -> D3-CoA (Certificate Analysis)
    - [ ] Certificate chain analysis -> D3-CoA (Certificate Analysis)
    - [ ] PE import table scanning -> D3-SFA (Static File Analysis)
    - [ ] Entropy calculation -> D3-EFA (Emulated File Analysis) / D3-SFA
    - [ ] Packing/encryption detection -> D3-SFA (Static File Analysis)
    - [ ] Malware scoring -> D3-DA (Dynamic Analysis) - composite risk assessment
    - [ ] Baseline comparison -> D3-FCI (File Content Integrity Monitoring)
    - [ ] YARA scanning (future) -> D3-SFA (Static File Analysis)
    - [ ] VirusTotal lookup (future) -> D3-FHRA (File Hash Reputation Analysis)
    - [ ] String extraction (future) -> D3-SFA
    - [ ] Security audit checks -> D3-SHD (System Configuration Hardening)
    - [ ] Startup/persistence enumeration (future) -> D3-PSA (Process Spawn Analysis)
    - [ ] Process ancestry (future) -> D3-PCA (Process Creation Analysis)
    - [ ] Network IOC matching (future) -> D3-DNSDL (DNS Denylisting)
- [ ] D3FEND gap analysis:
    - [ ] For each ATT&CK technique detected: which D3FEND countermeasures apply?
    - [ ] Which of those countermeasures does Phantom Recon implement?
    - [ ] Gap = ATT&CK technique has D3FEND countermeasure that we don't implement
    - [ ] Report: "T1055 (Process Injection) is countered by D3-PSA (Process Spawn Analysis).
          Status: NOT IMPLEMENTED. Recommendation: Enable Phase 4.8 process ancestry monitoring."
    - [ ] Priority ranking: gaps for most prevalent/critical techniques ranked first
- [ ] D3FEND coverage score:
    - [ ] "Phantom Recon implements X of Y applicable D3FEND techniques"
    - [ ] Broken down by D3FEND category: Detect, Isolate, Deceive, Evict, Harden
    - [ ] Standalone report section
    - [ ] Enterprise dashboard widget
- [ ] D3FEND in recommendations:
    - [ ] Each gap links to a specific Phantom Recon feature or config change
    - [ ] "To close this gap, enable [feature] in Phase [N]" or "configure [setting]"
    - [ ] Prioritized by: risk reduction impact × implementation effort

### 4.6 IOC Feed Ingestion
- [ ] Hash-based IOC feeds:
    - [ ] Import lists of known-bad MD5/SHA1/SHA256 hashes
    - [ ] Sources: STIX/TAXII feeds, CSV imports, MISP, OpenCTI
    - [ ] On scan: check each file hash against IOC hash list (O(1) lookup via hash set)
    - [ ] Match = immediate alert + score override to 10.0
- [ ] File name / path IOC feeds:
    - [ ] Known malware filenames (e.g., mimikatz.exe, procdump.exe, psexec.exe)
    - [ ] Known suspicious paths (e.g., C:\Users\Public\*.exe)
    - [ ] Regex pattern matching on file paths
- [ ] Network IOC feeds (future, if network scanning added):
    - [ ] Known C2 IP addresses and domains
    - [ ] DNS query analysis against IOC domain lists
- [ ] IOC management:
    - [ ] Standalone: load IOC files from local directory
    - [ ] Enterprise: server distributes IOC packages to agents
    - [ ] IOC expiry: auto-remove IOCs older than configurable TTL
    - [ ] IOC source tracking: which feed provided which IOC

### 4.7 Enhanced Static Analysis `PARTLY DONE`

Status 1.0.0: program header anomalies, overlay, TLS callbacks, debug paths, alternate data
streams with Mark of the Web, script analysis, ssdeep and imphash in baseline comparison,
and right-to-left override names are done. PowerShell's Start-Process and New-Object are
left out of the script rules on purpose: nearly every script uses them. String extraction,
resources, .NET metadata, Office macros, manifests, TLSH, icons and the C2 and credential
string rules are not built.
- [ ] String extraction and analysis:
    - [ ] Extract ASCII and Unicode strings from PE files (min length configurable, default 6)
    - [ ] Flag suspicious strings: URLs (http/https), IP addresses (regex match),
          registry paths, file paths to system directories, base64-encoded blobs,
          PowerShell commands, cmd.exe invocations, known malware mutex names
    - [ ] String entropy analysis: high-entropy strings may be encrypted C2 config
    - [ ] Report: top suspicious strings per file, with context
- [ ] Resource section analysis:
    - [ ] Enumerate PE resource directory entries
    - [ ] Detect embedded executables in resources (MZ header in resource data)
    - [ ] Detect embedded scripts (VBS, JS, PS1) in resources
    - [ ] Calculate entropy per resource (encrypted payload detection)
    - [ ] Resource language mismatch (Chinese resources in a "Microsoft" signed binary)
- [ ] .NET assembly analysis:
    - [x] Detect .NET binaries (CLI header present)
    - [ ] Extract assembly name, version, target framework
    - [ ] Detect known .NET obfuscators: ConfuserEx, SmartAssembly, Dotfuscator,
          Crypto Obfuscator, Agile.NET, Babel
    - [ ] Stream analysis: #Strings, #US, #Blob, #GUID entropy
    - [ ] TypeDef/MethodDef name analysis (obfuscated names = single chars, Unicode garbage)
- [ ] Macro analysis (Office documents):
    - [ ] Detect OLE2 and OOXML formats
    - [ ] Extract VBA macro source code
    - [ ] Flag suspicious macro patterns: Shell(), CreateObject(), WScript.Shell,
          PowerShell, URLDownloadToFile, AutoOpen, Document_Open
    - [ ] Macro in non-standard location detection
- [x] PE header anomaly detection:
    - [x] Timestamp analysis:
        - [x] Compilation timestamp in the future -> suspicious (timestomped PE)
        - [x] Compilation timestamp before Windows NT era (pre-1993) -> suspicious
        - [x] Compilation timestamp zeroed out -> deliberate evasion
        - [ ] Compilation timestamp vs file creation time mismatch -> possible re-packaging
    - [x] Checksum validation:
        - [x] Verify PE optional header checksum (CheckSumMappedFile)
        - [x] Mismatched checksum -> file modified after compilation (patched/injected)
        - [ ] Zero checksum -> non-critical for EXEs, suspicious for DLLs/SYS (drivers require valid checksum)
    - [x] Non-standard section names:
        - [ ] Flag section names that deviate from standard (.text, .data, .rdata, .rsrc, .reloc, .bss)
        - [x] Detect known packer section names: UPX0/UPX1, .packed, .themida, .vmp0, .enigma, .aspack, .adata
        - [x] Detect empty section names or names with non-printable characters
        - [x] Detect abnormal number of sections (>10 -> unusual, >20 -> highly suspicious)
    - [x] TLS (Thread Local Storage) callbacks:
        - [x] Detect TLS callback directory entries in PE header
        - [x] TLS callbacks execute before the entry point -> anti-debugging / code injection vector
        - [x] Flag any non-zero TLS callback count as suspicious (legitimate use is rare)
        - [ ] Report TLS callback RVAs for manual review
    - [x] Debug directory / PDB path analysis:
        - [x] Extract debug directory entries (IMAGE_DEBUG_TYPE_CODEVIEW -> PDB path)
        - [x] Flag PDB paths containing usernames or internal paths (OPSEC failure by attacker)
        - [ ] Flag PDB paths pointing to temp directories or non-standard build paths
        - [ ] Flag missing debug directory in debug-build-style binaries (stripped for evasion)
        - [x] Known malware PDB path patterns (e.g., paths containing "payload", "dropper", "loader", "inject")
    - [x] Overlay data detection:
        - [x] Detect data appended after the last PE section (overlay)
        - [x] Calculate overlay size and entropy
        - [x] High-entropy overlay -> possible encrypted/compressed payload
        - [x] Overlay containing MZ header -> embedded PE (dropper pattern)
        - [ ] Overlay size significantly larger than PE sections -> data staging
- [ ] Timestomping detection:
    - [ ] Compare file creation time vs last modification time vs last access time
    - [ ] Creation time newer than modification time -> timestamp manipulation
    - [ ] All three timestamps identical to the second -> batch timestomping tool artifact
    - [ ] Timestamps that predate the OS installation -> impossible, therefore manipulated
    - [ ] Compare NTFS $STANDARD_INFORMATION vs $FILE_NAME timestamps (requires raw NTFS read):
        - [ ] $SI timestamps can be modified by user-mode tools (SetFileTime)
        - [ ] $FN timestamps are updated by the kernel and harder to manipulate
        - [ ] Mismatch between $SI and $FN -> strong indicator of timestomping
    - [ ] Compilation timestamp (PE header) vs file system timestamp correlation
- [x] NTFS Alternate Data Streams (ADS) detection:
    - [x] Enumerate all named streams on each scanned file (FindFirstStreamW / FindNextStreamW)
    - [x] Flag files with non-default streams (anything beyond ::$DATA)
    - [ ] Calculate size and entropy of each alternate stream
    - [x] Check for executable content in ADS (MZ header, script signatures)
    - [x] Common abuse patterns: Zone.Identifier removal (MOTW bypass), hidden payload storage
    - [ ] Report: file path, stream name, stream size, stream entropy
- [x] Script-specific analysis (for .ps1, .vbs, .js, .bat, .cmd, .hta, .wsf):
    - [x] Obfuscation scoring:
        - [x] Character frequency analysis (excessive backticks, carets, special chars)
        - [x] String concatenation density (many small concatenated strings -> obfuscation)
        - [x] Variable name entropy (random/high-entropy names vs readable names)
        - [x] Ratio of alphanumeric to non-alphanumeric characters
        - [x] Base64-encoded blob detection (regex + entropy threshold)
        - [x] Encoded command detection: -EncodedCommand, -enc, -e (PowerShell)
        - [x] Char code obfuscation: [char]0x41, Chr(65), String.fromCharCode() patterns
    - [x] Suspicious command patterns:
        - [x] PowerShell: Invoke-Expression (IEX), Invoke-WebRequest, Net.WebClient,
              DownloadString, DownloadFile, Start-Process, New-Object, -NoProfile, -WindowStyle Hidden,
              -ExecutionPolicy Bypass, Add-Type, [Reflection.Assembly]::Load
        - [x] VBScript: WScript.Shell, Shell.Application, XMLHTTP, ADODB.Stream, Scripting.FileSystemObject
        - [x] Batch/CMD: certutil -decode, bitsadmin /transfer, mshta, regsvr32 /s /n /u,
              powershell -nop, rundll32, wmic process call create
        - [x] JScript: ActiveXObject, WScript.Shell, eval(), new Function()
    - [x] Encoded payload detection:
        - [x] Base64-encoded blocks (min length 100 chars, high entropy)
        - [x] Hex-encoded strings (long sequences of [0-9a-fA-F])
        - [x] Decimal-encoded byte arrays (e.g., 72,101,108,108,111)
        - [x] Gzip/deflate compressed payloads (magic bytes after decoding)
    - [x] Composite script risk score contributing to overall malware score
- [ ] PE manifest analysis:
    - [ ] Extract application manifest from PE resources (RT_MANIFEST)
    - [ ] requestedExecutionLevel parsing:
        - [ ] "asInvoker" -> normal (no flag)
        - [ ] "highestAvailable" -> informational note
        - [ ] "requireAdministrator" -> flag for review (legitimate for installers, suspicious for others)
    - [ ] uiAccess attribute:
        - [ ] uiAccess="true" -> can interact with elevated UI (accessibility feature, abused for priv-esc)
        - [ ] Must be in trusted location (Program Files, Windows) - flag if uiAccess=true outside these paths
    - [ ] DPI awareness, compatibility flags (informational metadata)
    - [ ] Missing manifest in modern PE -> unusual (most post-Vista binaries have one)
- [x] Fuzzy hashing (similarity-based detection):
    - [x] ssdeep (context-triggered piecewise hashing):
        - [x] Compute ssdeep hash for every scanned file
        - [x] Compare ssdeep hashes between files: similarity score 0-100
        - [ ] Cluster similar files together (possible variants of the same malware family)
        - [ ] Compare against known malware ssdeep hashes (IOC feed integration)
    - [ ] TLSH (Trend Micro Locality Sensitive Hash):
        - [ ] Compute TLSH for files > 50 bytes (TLSH minimum)
        - [ ] TLSH distance metric for file similarity (lower = more similar)
        - [ ] Better than ssdeep for small differences (code reuse detection)
    - [x] Import hash (imphash):
        - [x] Already available from PE import table - compute MD5 of ordered import list
        - [ ] Files with identical imphash share the same import table -> likely same family/toolkit
        - [ ] Cross-reference imphash against known malware imphash databases
    - [x] Fuzzy hash in baseline comparison:
        - [x] If file hash changed but fuzzy hash is similar -> minor modification (patch, config change)
        - [x] If file hash changed and fuzzy hash is very different -> replaced entirely (suspicious)
- [ ] Icon masquerading detection (resource analysis enhancement):
    - [ ] Extract icon resource from PE files (RT_ICON / RT_GROUP_ICON)
    - [ ] Compute icon hash (dhash or phash - perceptual hash)
    - [ ] Compare against known legitimate application icons:
        - [ ] Document icons (Word, Excel, PDF) on an executable -> masquerading as document
        - [ ] Folder icons on an executable -> masquerading as folder
        - [ ] Image icons (JPEG, PNG) on an executable -> masquerading as photo
    - [ ] Flag executables whose icon mimics a non-executable file type
    - [ ] Flag executables with no icon at all (unusual for user-facing apps)
    - [x] RLO (Right-to-Left Override) character detection in filenames (Unicode masquerading)
- [ ] String extraction enhancements:
    - [ ] C2 framework string detection:
        - [ ] Cobalt Strike beacon config markers (sleeptime, jitter, publickey, C2Server, UserAgent)
        - [ ] Meterpreter / Metasploit stage markers (MZ reflective loader patterns)
        - [ ] Sliver implant markers (protobuf-based C2 config strings)
        - [ ] Mythic agent markers (agent-specific config patterns)
        - [ ] Empire / Covenant / Havoc / Brute Ratel string patterns
        - [ ] Generic C2 indicators: hardcoded User-Agent strings, sleep intervals, named pipes
    - [ ] Hardcoded credential detection:
        - [ ] Patterns: "password=", "passwd=", "api_key=", "secret=", "token=", "authorization:"
        - [ ] AWS access key format (AKIA...), Azure client secrets, GCP service account keys
        - [ ] SSH private key headers (-----BEGIN RSA PRIVATE KEY-----)
        - [ ] Certificate private key material (-----BEGIN PRIVATE KEY-----)
        - [ ] Database connection strings with embedded credentials
    - [ ] URL and network indicator extraction:
        - [ ] Full URL extraction (http/https/ftp with path and query parameters)
        - [ ] IP address extraction with port numbers (IPv4 and IPv6)
        - [ ] Domain extraction from strings (heuristic: TLD validation)
        - [ ] Email address extraction
        - [ ] Named pipe paths (\\.\pipe\...) - often used by C2 for lateral movement
    - [ ] Suspicious path references:
        - [ ] References to %TEMP%, %APPDATA%, %USERPROFILE% (common malware staging dirs)
        - [ ] References to system directories: \System32\, \SysWOW64\, \drivers\
        - [ ] References to SAM, SECURITY, SYSTEM hive paths (credential theft)
        - [ ] References to shadow copy paths (vssadmin, wmic shadowcopy)

### 4.8 Dynamic / Behavioral Indicators
- [ ] Sandbox integration:
    - [ ] Submit files scoring above threshold to a sandbox for detonation
    - [ ] Supported sandboxes: Cuckoo/CAPE (open source), Any.Run (API), Joe Sandbox (API),
          Windows Sandbox (local, limited)
    - [ ] Receive behavior report: processes created, files written, registry changes,
          network connections, DNS queries
    - [ ] Integrate sandbox verdict into malware score
    - [ ] Enterprise: sandbox submission controlled by server policy
- [ ] Process and thread enumeration (runtime snapshot):
    - [ ] Enumerate all running processes (CreateToolhelp32Snapshot + Process32First/Next):
        - [ ] For each process: PID, parent PID, image path, command line, start time, user context
        - [ ] Detect processes running from suspicious paths (temp, downloads, AppData, recycle bin)
        - [ ] Detect processes with no image path on disk (deleted-after-launch or memory-only)
        - [ ] Detect processes running from network paths (UNC paths: \\server\share\)
        - [ ] Process name vs image path mismatch (svchost.exe from non-System32 = masquerading)
    - [ ] Enumerate all threads per process (Thread32First/Next):
        - [ ] Thread ID, owning process, creation time, priority, start address
        - [ ] Thread start address resolution: which module does it belong to?
        - [ ] Flag threads whose start address doesn't resolve to any loaded module (injected code)
        - [ ] Flag threads with start address in RWX memory regions (shellcode execution)
    - [ ] Cross-reference running processes against baseline:
        - [ ] For each process image path: look up in baseline via FindEntry()
        - [ ] Process image NOT in baseline -> NEW process (unknown binary running)
        - [ ] Process image in baseline but CHANGED (hash mismatch) -> modified binary running live
        - [ ] Process image in baseline and MATCH -> known-good, report as clean
        - [ ] Report: "X of Y running processes are in baseline, Z are unknown, W are modified"
    - [ ] Process tree construction:
        - [ ] Build full parent-child tree from PID/PPID relationships
        - [ ] Detect orphaned processes (parent no longer exists - possible parent PID spoofing)
        - [ ] Flag unusual ancestry chains:
            - [ ] explorer.exe -> cmd.exe -> powershell.exe -> net.exe (recon chain)
            - [ ] winword.exe / excel.exe -> cmd.exe / powershell.exe (macro execution)
            - [ ] svchost.exe -> cmd.exe / powershell.exe (service abuse)
            - [ ] wmiprvse.exe -> powershell.exe (WMI lateral movement)
            - [ ] w3wp.exe -> cmd.exe (webshell)
            - [ ] mshta.exe -> powershell.exe (HTA-based execution)
        - [ ] Flag processes whose parent PID doesn't match expected parent (PID spoofing indicator)
        - [ ] Flag processes with PPID=0 or PPID=4 that aren't system-level (direct kernel spawn spoofing)
- [ ] Memory-backed code detection (reflective injection / fileless malware):
    - [ ] Module enumeration per process (EnumProcessModules / Module32First/Next):
        - [ ] For each loaded module: base address, size, image path on disk
        - [ ] Verify every loaded DLL has a corresponding file on disk
        - [ ] Module present in memory but NOT on disk -> reflective DLL loading or manual mapping
        - [ ] Module path on disk doesn't match PE headers in memory -> hollowed or replaced
    - [ ] Memory region analysis (VirtualQueryEx walk):
        - [ ] Enumerate all committed memory regions per process
        - [ ] Identify executable regions (PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE)
        - [ ] For each executable region: is it backed by a mapped file (MEM_IMAGE/MEM_MAPPED)?
        - [ ] Executable MEM_PRIVATE regions -> code allocated at runtime (not from a file)
        - [ ] MEM_PRIVATE + PAGE_EXECUTE_READWRITE -> highest suspicion (writable + executable + unbacked)
        - [ ] MEM_PRIVATE + PAGE_EXECUTE_READ -> suspicious (executable + unbacked, but not writable)
        - [ ] MEM_IMAGE region with modified memory protection (originally RX, now RWX) -> code patching
    - [ ] Reflective DLL injection detection:
        - [ ] Executable MEM_PRIVATE region containing MZ/PE header -> manually mapped PE
        - [ ] Walk PE headers in memory: parse IMAGE_DOS_HEADER -> IMAGE_NT_HEADERS
        - [ ] If valid PE structure found in unbacked memory -> reflective DLL confirmed
        - [ ] Extract in-memory PE: dump headers, section table, import table if resolvable
        - [ ] Compute hash of in-memory PE for IOC matching (even without disk file)
        - [ ] Report: process name, PID, memory address, in-memory PE size, extracted hash
    - [ ] Process hollowing detection:
        - [ ] Process image on disk doesn't match PE headers loaded in memory at base address
        - [ ] Compare: disk file hash vs hash of in-memory image at process base address
        - [ ] If PEB.ImageBaseAddress points to a PE with different headers than the disk file -> hollowed
        - [ ] Check SizeOfImage in memory vs on disk (hollowed processes often have different sizes)
        - [ ] Flag: "Process claims to be svchost.exe but memory contents don't match disk file"
    - [ ] Thread injection detection:
        - [ ] Threads whose start address falls within MEM_PRIVATE executable regions -> injected
        - [ ] Threads whose start address is in a different process's module -> cross-process injection
        - [ ] APC injection artifacts: threads in alertable wait state with unusual APC queue
        - [ ] SetThreadContext artifacts: thread context pointing to shellcode regions
    - [ ] Unbacked executable memory scoring:
        - [ ] Count of MEM_PRIVATE executable regions per process
        - [ ] Total size of unbacked executable memory per process
        - [ ] Legitimate exceptions: JIT compilers (.NET CLR, V8, Java HotSpot) allocate RWX
        - [ ] JIT detection heuristic: if process loads clr.dll/clrjit.dll/jscript9.dll -> reduce suspicion
        - [ ] Scoring: unbacked RWX in non-JIT process -> +3.0 to process risk score
        - [ ] Scoring: valid PE structure in unbacked memory -> +5.0 (near-certain injection)
- [ ] Mark of the Web (MOTW) and file origin tracking:
    - [ ] Zone.Identifier ADS check on every scanned file:
        - [ ] Read :Zone.Identifier alternate data stream (FindFirstStreamW or direct open)
        - [ ] Parse ZoneId value:
            - [ ] ZoneId=0 -> Local Machine (most trusted)
            - [ ] ZoneId=1 -> Local Intranet
            - [ ] ZoneId=2 -> Trusted Sites
            - [ ] ZoneId=3 -> Internet (downloaded from web - flagged)
            - [ ] ZoneId=4 -> Restricted Sites (highest risk)
        - [ ] Parse ReferrerUrl field (which URL/site the file was downloaded from)
        - [ ] Parse HostUrl field (direct download URL)
        - [ ] Parse HostIpAddress field (IP of download source, if present)
    - [ ] MOTW risk assessment:
        - [ ] Executable with ZoneId=3 (Internet) -> flag as "downloaded from internet"
        - [ ] Executable with ZoneId=3 + no valid signature -> high risk (+2.0 to malware score)
        - [ ] Executable with ZoneId=4 (Restricted) -> very high risk (+3.0)
        - [ ] Executable with ZoneId=3 + ReferrerUrl to known suspicious domain -> critical
        - [ ] Executable with NO Zone.Identifier but in Downloads/Desktop -> MOTW stripped (evasion)
        - [ ] MOTW stripping detection: file in user download location + no ADS + recently created
    - [ ] Network drive source detection:
        - [ ] Detect files running from UNC paths (\\server\share\...)
        - [ ] Detect files running from mapped network drives (resolve drive letter -> UNC path)
        - [ ] GetDriveTypeW on drive letter: DRIVE_REMOTE = network source
        - [ ] Flag executables on network drives: laterally transferred or shared malware staging
        - [ ] Cross-reference network path against known internal file servers (whitelist)
    - [ ] Download origin correlation:
        - [ ] Cross-reference MOTW HostUrl against IOC URL feeds
        - [ ] Cross-reference MOTW HostIpAddress against IOC IP feeds
        - [ ] Flag files downloaded from Tor exit nodes, known C2 infrastructure, paste sites
        - [ ] Extract download timestamp from Zone.Identifier (if browser wrote it)
    - [ ] Origin in baseline comparison:
        - [ ] Store MOTW zone and source URL in BaselineEntry
        - [ ] On comparison: flag if a file's MOTW changed (zone stripped = evasion attempt)
        - [ ] Flag if a baseline file's MOTW was removed between scans
    - [ ] Running process origin analysis:
        - [ ] For each running process: check MOTW on its image file
        - [ ] "3 processes running from internet-downloaded executables"
        - [ ] "1 process running from a network drive"
        - [ ] "2 processes running from executables with stripped MOTW"
        - [ ] Combine with baseline cross-reference: "unknown internet-sourced process not in baseline"
- [ ] Process ancestry analysis:
    - [ ] Hook process creation (ETW provider: Microsoft-Windows-Kernel-Process):
        - [ ] Real-time notification of new process creation
        - [ ] Capture: image path, command line, parent PID, parent image, token/user
        - [ ] Log creation events for post-incident timeline reconstruction
    - [ ] ETW thread creation monitoring (Microsoft-Windows-Kernel-Thread):
        - [ ] Detect new thread creation in existing processes
        - [ ] Flag remote thread creation (thread in process A created by process B)
        - [ ] Flag threads created by processes with high malware scores
    - [ ] Build process tree: parent -> child relationships
    - [ ] Flag unusual chains:
        - [ ] explorer.exe -> cmd.exe -> powershell.exe -> net.exe (recon chain)
        - [ ] winword.exe / excel.exe -> cmd.exe / powershell.exe (macro execution)
        - [ ] svchost.exe -> cmd.exe (service abuse)
        - [ ] wmiprvse.exe -> powershell.exe (WMI lateral movement)
    - [ ] Flag unusual parents: svchost.exe spawning cmd.exe
    - [ ] Cross-reference spawned processes against scan results
    - [ ] Command line argument analysis:
        - [ ] Log full command line for every process (GetCommandLineW via PEB read or ETW)
        - [ ] Flag encoded PowerShell commands (-EncodedCommand, -e, -enc)
        - [ ] Flag living-off-the-land binaries (LOLBins) with suspicious arguments:
            - [ ] certutil.exe -urlcache -decode
            - [ ] mshta.exe http://...
            - [ ] rundll32.exe javascript:...
            - [ ] regsvr32.exe /s /n /u /i:http://...
            - [ ] bitsadmin.exe /transfer
            - [ ] wmic.exe process call create
            - [ ] cmstp.exe /ni /s
        - [ ] Flag commands targeting security tools (taskkill /im defender, sc stop ...)
- [ ] Network behavior indicators (requires live monitoring, future):
    - [ ] DNS query logging (ETW provider: Microsoft-Windows-DNS-Client)
    - [ ] Flag queries to known-bad domains (IOC feed match)
    - [ ] Beaconing detection: regular-interval connections to the same destination
    - [ ] DGA (Domain Generation Algorithm) detection: high-entropy domain names
    - [ ] Data exfiltration indicators: large outbound transfers to unusual destinations
    - [ ] Per-process network activity (ETW: Microsoft-Windows-Kernel-Network):
        - [ ] Which process is making which connections
        - [ ] Map process -> destination IP/port -> domain (reverse DNS or SNI)
        - [ ] Flag processes making outbound connections that aren't expected to (notepad.exe connecting out)
        - [ ] Flag connections to non-standard ports (high ports, uncommon service ports)
        - [ ] Cross-reference connecting process against baseline (unknown process + network activity = high risk)

---

## Phase 5 - Detection Validation & Compliance `MOSTLY NOT BUILT`

Status 1.0.0: the CIS mapping and the ATT&CK Navigator layer for findings are done (ticked
below). Detection validation (5.1, 5.2) is not planned for the standalone tool, and the
compliance frameworks other than CIS are not built.

### 5.1 Detection Validation
- [ ] Shared event timeline:
    - [ ] The validation harness logs each benign test artifact it creates, with timestamps
    - [ ] Phantom Recon logs its detections with timestamps
    - [ ] Correlation engine: match each planted test artifact to its detection (or gap)
    - [ ] "Benign test file written at 14:32. Phantom Recon detected it at 14:35 (3min gap)"
    - [ ] "Benign autorun key written at 14:40. Phantom Recon: NOT DETECTED"
- [ ] Detection gap analysis:
    - [ ] For each test technique exercised: did Phantom Recon detect it?
    - [ ] Gap report: list of undetected techniques with ATT&CK mapping
    - [ ] Recommendation engine: "To detect T1055, enable YARA rule pack 'injection_detection'"
    - [ ] Track gap closure over time (were gaps from last exercise addressed?)
- [ ] Automated validation runs:
    - [ ] The harness plants a predefined set of benign test artifacts
    - [ ] Phantom Recon runs concurrent scans
    - [ ] Automated comparison: what was planted vs what was detected
    - [ ] Report card: detection coverage percentage per ATT&CK tactic
- [ ] Coverage dashboard:
    - [ ] Unified view of planted test artifacts and resulting detections
    - [ ] ATT&CK matrix with dual coloring: planted + detected + gap (white)
    - [ ] Exercise history and trend tracking

### 5.2 Detection Validation Library
- [ ] Pre-built test scenarios:
    - [ ] Atomic-style benign test cases mapped to ATT&CK
    - [ ] Each test: writes a benign marker that a real technique would leave behind
    - [ ] Run test -> scan -> verify detection -> cleanup
    - [ ] Categories: persistence, privilege escalation, defense evasion, credential access,
          lateral movement, collection, exfiltration
- [ ] Custom scenario builder:
    - [ ] Analyst defines: "drop file X to path Y, create registry key Z, schedule task W"
    - [ ] Execute scenario on selected agents
    - [ ] Verify Phantom Recon detects all artifacts
    - [ ] Score the detection coverage

### 5.3 Reporting & Compliance

#### Detection Coverage Reports
- [ ] Executive summary: overall detection coverage score (% of techniques detected)
- [ ] Technique-by-technique breakdown with detect/miss/partial status
- [ ] Time-to-detect metrics: "average 4.2 minutes from execution to detection"
- [ ] Recommendations prioritized by risk (CVSS-like scoring) and implementation effort
- [ ] Trend over time: "detection coverage improved from 62% to 78% since last quarter"
- [ ] ATT&CK Navigator layer export with exercise results overlaid
- [ ] Planted-vs-detected timeline visualization

#### MITRE ATT&CK Compliance
- [ ] ATT&CK-based detection coverage assessment:
    - [ ] Catalog every technique Phantom Recon can detect (from API mappings, security checks, etc.)
    - [ ] Coverage score: "Phantom Recon detects indicators for X of Y Enterprise ATT&CK techniques"
    - [ ] Breakdown by tactic: Initial Access, Execution, Persistence, Privilege Escalation,
          Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection,
          Command and Control, Exfiltration, Impact
    - [ ] Per-technique confidence: "high" (direct detection), "medium" (heuristic), "low" (indirect indicator)
- [ ] ATT&CK Evaluations alignment:
    - [ ] Map Phantom Recon detection capabilities against public MITRE Engenuity ATT&CK
          Evaluations test scenarios (APT3, APT29, Carbanak/FIN7, Wizard Spider, Turla, etc.)
    - [ ] "If Phantom Recon had been present during the APT29 evaluation, it would have
          detected X of Y test steps"
    - [ ] Gap analysis per threat group: which APT techniques are we blind to?
- [ ] ATT&CK Navigator integration:
    - [ ] Auto-generate Navigator JSON layers for: capabilities, findings, gaps
          - findings only (Reports > Save ATT&CK Navigator Layer, `--navigator`)
    - [x] Layers importable into MITRE's ATT&CK Navigator web tool
    - [ ] Color schemes: green=detected, yellow=partial, red=gap, gray=not applicable

#### MITRE D3FEND Compliance
- [ ] D3FEND coverage assessment (see Phase 4.5 for implementation detail):
    - [ ] Score: "X of Y applicable D3FEND digital artifacts are monitored"
    - [ ] Breakdown by D3FEND category: Detect, Isolate, Deceive, Evict, Harden
    - [ ] Gap report with remediation recommendations linked to Phantom Recon features
- [ ] D3FEND -> ATT&CK cross-matrix:
    - [ ] For each ATT&CK technique: list D3FEND countermeasures and their implementation status
    - [ ] Exportable as matrix for security architecture reviews

#### NIST Cybersecurity Framework (CSF 2.0) Mapping
- [ ] Map Phantom Recon capabilities to NIST CSF functions:
    - [ ] **Identify (ID)**:
        - ID.AM - Asset Management: file/software inventory via scan modes
        - ID.RA - Risk Assessment: malware scoring, CVE lookup, security posture audit
    - [ ] **Protect (PR)**:
        - PR.AC - Identity Management: local account audit, permission analysis
        - PR.DS - Data Security: file integrity (baseline comparison)
        - PR.IP - Information Protection: security configuration audit (LLMNR, SMB signing, etc.)
        - PR.PT - Protective Technology: Credential Guard check, firewall status
    - [ ] **Detect (DE)**:
        - DE.AE - Anomalies and Events: baseline deviation detection (NEW/CHANGED/MISSING)
        - DE.CM - Security Continuous Monitoring: scheduled scans, enterprise agent monitoring
        - DE.DP - Detection Processes: malware scoring, import analysis, packing detection
    - [ ] **Respond (RS)**:
        - RS.AN - Analysis: detailed per-file analysis, ATT&CK technique mapping
        - RS.CO - Communications: alert delivery (email, webhook, syslog)
    - [ ] **Recover (RC)**:
        - RC.RP - Recovery Planning: baseline as known-good reference for recovery validation
- [ ] NIST CSF compliance score: percentage of applicable subcategories addressed
- [ ] Exportable NIST CSF profile for auditors

#### NIST 800-53 (Security Controls) Mapping
- [ ] Map security audit checks to specific 800-53 controls:
    - [ ] AC-2 (Account Management) -> local account enumeration, default account check
    - [ ] AC-6 (Least Privilege) -> AlwaysInstallElevated, writable service executables
    - [ ] AU-2 (Audit Events) -> audit policy configuration check
    - [ ] AU-6 (Audit Review) -> PowerShell logging check, event log configuration
    - [ ] CM-6 (Configuration Settings) -> all security posture checks (LLMNR, SMB, WPAD, etc.)
    - [ ] CM-7 (Least Functionality) -> unnecessary service detection, startup program review
    - [ ] IA-5 (Authenticator Management) -> password policy check
    - [ ] SC-7 (Boundary Protection) -> firewall status, VLAN compliance
    - [ ] SC-8 (Transmission Confidentiality) -> SMB signing enforcement
    - [ ] SC-28 (Protection of Information at Rest) -> baseline integrity, DPAPI config check
    - [ ] SI-2 (Flaw Remediation) -> Windows Update status, CVE detection
    - [ ] SI-3 (Malicious Code Protection) -> malware scoring, import analysis, packing detection
    - [ ] SI-4 (Information System Monitoring) -> continuous scan monitoring, baseline comparison
    - [ ] SI-7 (Software, Firmware, and Information Integrity) -> baseline integrity monitoring,
          signature verification, hash comparison
- [ ] 800-53 compliance report:
    - [ ] Per-control status: implemented / partial / not implemented / not applicable
    - [ ] Evidence mapping: which Phantom Recon feature provides evidence for each control
    - [ ] Exportable for POA&M (Plan of Action and Milestones) documentation

#### NIST 800-171 (CUI Protection) Mapping
- [ ] Relevant for contractors handling Controlled Unclassified Information (CUI):
    - [ ] 3.1 Access Control -> account audit, permission analysis
    - [ ] 3.3 Audit and Accountability -> audit policy checks, logging verification
    - [ ] 3.4 Configuration Management -> security hardening checks, baseline management
    - [ ] 3.11 Risk Assessment -> malware scoring, vulnerability detection
    - [ ] 3.13 System and Communications Protection -> SMB signing, firewall, encryption checks
    - [ ] 3.14 System and Information Integrity -> malware detection, baseline integrity,
          software update status
- [ ] 800-171 self-assessment score (110 practices, scored 1/3/5 per NIST methodology)
- [ ] SPRS (Supplier Performance Risk System) score calculation
- [ ] Exportable for DoD contractor compliance documentation

#### CMMC (Cybersecurity Maturity Model Certification) Mapping
- [ ] CMMC 2.0 level mapping:
    - [ ] **Level 1 (Foundational)** - 17 practices from FAR 52.204-21:
        - [ ] Map Phantom Recon checks to applicable Level 1 practices
        - [ ] AC.L1-3.1.1 (Authorized Access Control) -> permission audit
        - [ ] IA.L1-3.5.1 (Identification) -> account enumeration
        - [ ] SC.L1-3.13.1 (Boundary Protection) -> firewall check
        - [ ] SI.L1-3.14.1 (Flaw Remediation) -> update status
        - [ ] SI.L1-3.14.2 (Malicious Code Protection) -> malware scanning
    - [ ] **Level 2 (Advanced)** - 110 practices from NIST 800-171:
        - [ ] Full 800-171 mapping (see above) covers Level 2
        - [ ] Assessment readiness report: "ready for Level 2 assessment on X of 110 practices"
    - [ ] **Level 3 (Expert)** - 800-172 enhanced requirements:
        - [ ] Advanced threat detection capabilities (YARA, behavioral analysis)
        - [ ] Threat intelligence integration (IOC feeds, VT)
        - [ ] Automated incident response indicators
- [ ] CMMC assessment preparation report
- [ ] Gap analysis: "To achieve CMMC Level 2, address these N gaps"

#### CIS Controls (v8) Mapping

Status 1.0.0: every check lists the CIS Controls v8 safeguards it relates to, and the CIS
Windows Benchmark recommendation by title where one matches (titles, because benchmark
numbers change between versions). They appear in the findings window, the reports and
docs/FINDINGS.md. The safeguards per check are chosen check by check, so they do not follow
the grouping below exactly. No compliance score is computed: a PC-level tool cannot
honestly score an organization's CIS implementation.

- [x] Map security checks to CIS Controls and Safeguards:
    - [ ] **CIS Control 1 - Inventory of Enterprise Assets**:
        - 1.1 -> file/software inventory from scan results
        - 1.2 -> unauthorized software detection (NEW files not in baseline)
    - [ ] **CIS Control 2 - Inventory of Software Assets**:
        - 2.1 -> installed software enumeration (Fast Scan registry)
        - 2.2 -> unauthorized software detection
        - 2.3 -> authorized software allowlisting (baseline = allowlist)
        - 2.5 -> software asset management via baseline
    - [ ] **CIS Control 3 - Data Protection**:
        - 3.6 -> file integrity monitoring via baseline comparison
    - [ ] **CIS Control 4 - Secure Configuration**:
        - 4.1 -> security configuration audit (all security posture checks)
        - 4.2 -> GPO compliance (LLMNR, SMB signing, WPAD, NBT-NS, mDNS)
        - 4.8 -> uninstall/disable unnecessary services
    - [ ] **CIS Control 5 - Account Management**:
        - 5.1 -> local account inventory
        - 5.2 -> default account detection (Guest, DefaultAccount)
        - 5.4 -> password policy audit
    - [ ] **CIS Control 7 - Continuous Vulnerability Management**:
        - 7.1 -> vulnerability scanning via CVE lookup
        - 7.3 -> patch management verification (Windows Update status)
        - 7.4 -> automated scanning (enterprise scheduled scans)
    - [ ] **CIS Control 8 - Audit Log Management**:
        - 8.2 -> audit policy configuration check
        - 8.5 -> PowerShell/event logging verification
    - [ ] **CIS Control 9 - Email and Web Browser Protections**:
        - 9.2 -> WPAD/proxy configuration audit
    - [ ] **CIS Control 10 - Malware Defenses**:
        - 10.1 -> malware scanning (core Phantom Recon function)
        - 10.2 -> signature-based detection (YARA, IOC feeds)
        - 10.4 -> auto-quarantine recommendations for high-score files
        - 10.7 -> portable executable analysis (import scanning, packing detection)
    - [ ] **CIS Control 13 - Network Monitoring and Defense**:
        - 13.3 -> network security configuration (SMB signing, LLMNR, VLAN compliance)
    - [ ] **CIS Control 18 - Penetration Testing**:
        - 18.1 -> detection validation exercise support
        - 18.2 -> detection gap analysis
        - 18.5 -> remediation validation via re-scan
- [ ] CIS Controls compliance score:
    - [ ] Implementation Group 1 (IG1) score: basic cyber hygiene (43 Safeguards)
    - [ ] Implementation Group 2 (IG2) score: IG1 + 74 additional Safeguards
    - [ ] Implementation Group 3 (IG3) score: IG2 + 36 additional Safeguards
    - [ ] Score per Control (0-100% of applicable Safeguards addressed)
- [x] CIS Benchmark integration (Windows-specific), partly:
    - [x] Map security audit checks to CIS Microsoft Windows Benchmark items (by title)
    - [x] Account policies, audit policies, security options, firewall rules
    - [ ] Level 1 (basic) and Level 2 (defense-in-depth) benchmark profiles
    - [ ] Exportable comparison report

#### DISA STIG (Security Technical Implementation Guide) Mapping
- [ ] Map security checks to Windows STIG finding IDs:
    - [ ] V-220697 - Unquoted service paths
    - [ ] V-220702 - SMB signing
    - [ ] V-220708 - LLMNR disabled
    - [ ] V-220726 - Credential Guard enabled
    - [ ] V-220739 - AlwaysInstallElevated
    - [ ] V-220748 - Password complexity
    - [ ] V-220752 - Account lockout threshold
    - [ ] V-220770 - Audit policy configuration
    - [ ] V-220784 - PowerShell script block logging
    - [ ] V-220788 - Windows Firewall enabled
    - [ ] (Extend as more security checks are implemented)
- [ ] STIG compliance reporting:
    - [ ] Per-finding status: Not a Finding / Open / Not Applicable / Not Reviewed
    - [ ] CAT I (Critical) / CAT II (High) / CAT III (Medium) severity breakdown
    - [ ] STIG Viewer-compatible XML export (XCCDF format)
    - [ ] Checklist (.ckl) file generation for upload to eMASS or STIG Viewer
- [ ] SCAP (Security Content Automation Protocol) integration:
    - [ ] OVAL (Open Vulnerability and Assessment Language) definition support
    - [ ] XCCDF (Extensible Configuration Checklist Description Format) output
    - [ ] ARF (Assessment Results Format) export
    - [ ] Compatible with DISA SCC (SCAP Compliance Checker) reporting format

#### FedRAMP Mapping
- [ ] Relevant for cloud service providers seeking government authorization:
    - [ ] Map to FedRAMP controls (based on NIST 800-53, tailored baselines)
    - [ ] FedRAMP Low / Moderate / High baseline coverage assessment
    - [ ] Continuous monitoring support:
        - [ ] Monthly vulnerability scanning evidence (scan results)
        - [ ] Annual assessment evidence (compliance reports)
        - [ ] Configuration management evidence (baseline comparison)
    - [ ] POA&M evidence generation: link each finding to a specific FedRAMP control
    - [ ] ConMon (Continuous Monitoring) report generation

#### ISO 27001 / 27002 Mapping
- [ ] Map capabilities to ISO 27001 Annex A controls:
    - [ ] A.8.1 - Asset Management: software inventory
    - [ ] A.8.8 - Management of Technical Vulnerabilities: CVE detection, update status
    - [ ] A.8.9 - Configuration Management: security hardening audit
    - [ ] A.8.15 - Logging: audit policy and logging checks
    - [ ] A.8.16 - Monitoring Activities: continuous scanning, baseline comparison
    - [ ] A.8.23 - Web Filtering: WPAD/proxy audit
    - [ ] A.8.24 - Use of Cryptography: signature verification, encryption analysis
    - [ ] A.8.25 - SDLC: code signing verification, integrity checks
    - [ ] A.8.28 - Secure Coding: import analysis (detects insecure API usage patterns)
- [ ] ISO 27001 Statement of Applicability (SoA) evidence mapping
- [ ] Exportable for ISO certification audits

#### Cross-Framework Compliance Dashboard (Enterprise Server)
- [ ] Unified compliance view:
    - [ ] Select framework(s): ATT&CK, D3FEND, NIST CSF, 800-53, 800-171, CMMC, CIS, STIG,
          FedRAMP, ISO 27001
    - [ ] Single dashboard showing compliance score per selected framework
    - [ ] Drill-down: framework -> control -> finding -> agent -> file
    - [ ] Side-by-side comparison: "how does addressing this STIG finding also improve our
          CIS Controls score?"
- [ ] Control overlap analysis:
    - [ ] Many controls overlap across frameworks (800-53 SI-3 ≈ CIS 10.1 ≈ STIG V-XXXXX)
    - [ ] Show: "Fixing this one finding satisfies requirements in 4 frameworks"
    - [ ] Prioritize fixes by: number of frameworks impacted × severity
- [ ] Automated evidence collection:
    - [ ] Each scan result and security audit finding tagged with applicable framework controls
    - [ ] Evidence package generation: "Generate all evidence for CMMC Level 2 assessment"
    - [ ] Timestamp and hash each evidence artifact for integrity
    - [ ] Evidence retention policy: keep for N years (configurable, default 3 for federal)
- [ ] Compliance trending:
    - [ ] Track compliance score per framework over time
    - [ ] Alert on compliance regression (score dropped since last assessment)
    - [ ] Scheduled compliance reports (monthly/quarterly for management review)
    - [ ] Board-ready executive summary: "We are X% compliant with Y framework"

---

## Phase 6 - Global Trust Authority (Master Server) `NOT PLANNED`

Not planned: a hosted service with subscriptions contradicts the noncommercial license and
the offline scope (see Direction at the top). The local known-good list
(`known_good_sha256.txt`) covers the offline part of the idea. Kept for history.

A cloud-hosted master server operated by us, serving as a curated trust authority across
all Phantom Recon enterprise deployments. Unlike the fleet approval database (Phase 3.9)
which is per-organization and admin-curated, the Global Trust Authority is a vetted,
vendor-maintained database of known-good binaries that no single customer admin can poison.

### 6.1 Architecture & Trust Model
- [ ] Trust hierarchy (three tiers):
    - [ ] **Tier 1 - Global Trust Authority (GTA)**: our master server on the internet.
          Curated exclusively by us. Contains only verified known-good binaries.
          No customer admin can write to this tier. Read-only for all enterprise servers.
    - [ ] **Tier 2 - Enterprise Server**: customer's on-prem/private server (Phase 3).
          Contains fleet approval database (Phase 3.9) managed by their admins.
          Can be poisoned by a careless admin - scoped to that organization only.
    - [ ] **Tier 3 - Agent Baseline**: per-machine ground truth (Phase 1.4).
          Reflects what was on that specific machine at baseline time.
    - [ ] Lookup priority on NEW file detection:
        - [ ] 1. Agent baseline (local, O(1)) -> MATCH = known on this machine
        - [ ] 2. Enterprise fleet approval DB (local cache, O(1)) -> APPROVED = org admin said ok
        - [ ] 3. Global Trust Authority (enterprise server queries GTA) -> TRUSTED = vendor-verified
        - [ ] 4. None of the above -> UNKNOWN, enters review queue
    - [ ] Trust scores: GTA TRUSTED > fleet APPROVED > baseline MATCH
          (GTA is most authoritative because it can't be poisoned by a single org)
- [ ] Poison prevention - why GTA can't be compromised by a bad admin:
    - [ ] Customer admins have ZERO write access to GTA
    - [ ] GTA entries are added exclusively through our internal vetting pipeline (see 6.2)
    - [ ] Enterprise servers query GTA as read-only consumers (pull model)
    - [ ] Even if a customer's fleet approval DB is poisoned (admin approves malware),
          the GTA remains clean - other customers are unaffected
    - [ ] GTA does NOT aggregate customer approval decisions (no crowd-sourcing of trust)
    - [ ] A compromised customer cannot submit "approved" verdicts upstream to GTA
- [ ] Communication model:
    - [ ] Enterprise server -> GTA: TLS 1.3, certificate-pinned connection
    - [ ] Authentication: enterprise server presents its license key + server certificate
    - [ ] GTA verifies license validity, subscription tier, and rate limits
    - [ ] Protocol: REST API (JSON) for hash lookups, binary downloads for database syncs
    - [ ] Standalone agents (no enterprise server): can optionally query GTA directly
          (requires license key configured locally, rate-limited)

### 6.2 Known-Good Binary Database
- [ ] Curated binary catalog:
    - [ ] We maintain a database of verified known-good executables
    - [ ] Each entry: SHA-256 hash, file size, vendor, product name, version, signer thumbprint,
          original filename, PE compilation timestamp, import hash (imphash)
    - [ ] Source of truth: official vendor downloads, verified distribution channels only
    - [ ] NO entries from customer submissions, community uploads, or automated crawling
- [ ] Vendor coverage (initial target list):
    - [ ] **Microsoft**: Windows OS binaries (System32, SysWOW64, WinSxS), Office, .NET,
          Visual C++ runtimes, Edge, PowerShell, Windows Defender, RSAT tools
    - [ ] **Major software vendors**: Adobe (Reader, Creative Cloud), Google (Chrome),
          Mozilla (Firefox, Thunderbird), Oracle (Java), Apple (iTunes, iCloud),
          Zoom, Slack, Teams, 7-Zip, Notepad++, PuTTY, WinSCP, FileZilla
    - [ ] **Security tools**: CrowdStrike, SentinelOne, Carbon Black, Sophos, Symantec,
          McAfee/Trellix, ESET, Kaspersky, Malwarebytes, Trend Micro
    - [ ] **Development tools**: Visual Studio, VS Code, Git, Node.js, Python, JDK,
          Docker Desktop, WSL components
    - [ ] **Enterprise infrastructure**: VMware Tools, Citrix, SQL Server, IIS,
          SCCM/Intune agent, Splunk forwarder, SIEM agents
    - [ ] Expand coverage over time based on customer demand and market share data
- [ ] Version tracking:
    - [ ] Every version of every tracked product cataloged separately
    - [ ] Version X.Y.Z of Product P has hash H - explicitly tracked
    - [ ] Older versions remain in database (legitimate systems may run older versions)
    - [ ] Versions with known critical CVEs: marked as TRUSTED_BUT_VULNERABLE
          (known-good binary, but outdated - informational flag, not blocked)
    - [ ] Retracted versions: if vendor retracts a build (e.g., buggy update pulled),
          marked as RETRACTED (still known-good, but noted)
- [ ] Vetting pipeline (our internal process):
    - [ ] Download from official vendor source (vendor website, CDN, WSUS catalog)
    - [ ] Verify vendor's own code signature (Authenticode chain to trusted root)
    - [ ] Verify hash matches vendor's published hash (if available)
    - [ ] Run through our own malware analysis pipeline (score must be <1.0)
    - [ ] Cross-reference with VirusTotal (0 detections required)
    - [ ] Cross-reference with multiple AV engines (at least 5 independent engines, all clean)
    - [ ] Human review for first-time vendor additions
    - [ ] Automated pipeline for version updates of already-vetted vendors
    - [ ] Any vetting failure -> binary does NOT enter GTA, flagged for investigation

### 6.3 OS Baseline Distribution
- [ ] Golden OS baselines:
    - [ ] We build and maintain reference baselines for clean OS installations
    - [ ] Each baseline: OS version + edition + patch level -> full .prbl file
    - [ ] Built from official ISO/WIM images in our controlled environment
    - [ ] Baselines include: every file that ships with that OS version (System32, drivers,
          default apps, WinSxS manifests, boot files)
- [ ] Windows baseline coverage:
    - [ ] Windows 10 (21H2, 22H2) - Home, Pro, Enterprise, LTSC
    - [ ] Windows 11 (22H2, 23H2, 24H2) - Home, Pro, Enterprise
    - [ ] Windows Server 2019, 2022, 2025 - Standard, Datacenter, Core
    - [ ] Each major cumulative update (monthly Patch Tuesday) produces a new baseline version
    - [ ] Baselines versioned: OS_VERSION-EDITION-KB_NUMBER (e.g., Win11_24H2_Pro_KB5034765)
- [ ] Linux baseline coverage (future):
    - [ ] Ubuntu LTS (22.04, 24.04) - Server, Desktop
    - [ ] RHEL / CentOS Stream / Rocky / Alma (8.x, 9.x)
    - [ ] Debian Stable (12 Bookworm, 13 Trixie)
    - [ ] Amazon Linux 2, Amazon Linux 2023
    - [ ] Baselines from official cloud images / ISO installs
    - [ ] Package-manager-aware: baseline tracks installed packages + file hashes
- [ ] Baseline distribution to enterprise servers:
    - [ ] Enterprise server subscribes to OS baseline updates for its relevant OS versions
    - [ ] GTA pushes new baselines after each Patch Tuesday (or on-demand pull)
    - [ ] Enterprise server can use GTA baselines as-is or merge with org-specific additions
    - [ ] Merge workflow: GTA baseline (OS files) + org baseline (org software) = combined baseline
    - [ ] Enterprise server signs the merged baseline with its own key before pushing to agents
- [ ] Baseline diff service:
    - [ ] "What changed between Win11_24H2_Pro_KB5034765 and Win11_24H2_Pro_KB5035853?"
    - [ ] Diff report: added files, removed files, changed files (with old/new hashes)
    - [ ] Helps admins understand what a Windows update changed before pushing new baseline
    - [ ] Reduces "false positive" NEW/CHANGED alerts after Patch Tuesday

### 6.4 GTA Query Protocol
- [ ] Hash lookup (primary use case):
    - [ ] Enterprise server batches unknown hashes from agent reports
    - [ ] POST /v1/lookup with array of SHA-256 hashes (max 1000 per request)
    - [ ] Response per hash: status (TRUSTED / TRUSTED_BUT_VULNERABLE / RETRACTED / UNKNOWN),
          vendor, product, version, signer, first_cataloged_date
    - [ ] Rate limiting by subscription tier:
        - [ ] Free tier: 100 lookups/day (for standalone/eval users)
        - [ ] Standard tier: 10,000 lookups/day (small-medium enterprise)
        - [ ] Premium tier: unlimited lookups (large enterprise)
    - [ ] Response caching: enterprise server caches GTA responses (TTL 7 days for TRUSTED,
          1 day for UNKNOWN - unknown files may be cataloged tomorrow)
- [ ] Baseline subscription:
    - [ ] Enterprise server registers which OS versions it needs baselines for
    - [ ] GTA pushes notification when new baseline available (webhook or poll)
    - [ ] Enterprise server downloads new baseline (binary transfer, integrity-verified)
    - [ ] Delta updates: only download changed entries since last baseline version (bandwidth savings)
- [ ] Catalog sync (optional, premium):
    - [ ] Enterprise server downloads full known-good catalog for offline/air-gapped operation
    - [ ] Catalog = all hashes + metadata, compressed (estimated: 50-200MB depending on coverage)
    - [ ] Delta sync: daily/weekly incremental updates
    - [ ] Air-gapped environments: export catalog to USB/media, import on isolated server

### 6.5 Customer Binary Submission Pipeline
- [ ] Submission workflow (enterprise server -> GTA):
    - [ ] Enterprise admin encounters UNKNOWN binary that they believe is legitimate
    - [ ] Instead of just fleet-approving it locally (Phase 3.9), they can submit it to GTA
          for global vetting: "Please verify this binary so all customers benefit"
    - [ ] Submission payload: the binary itself (uploaded), plus context metadata:
        - [ ] Vendor name (claimed), product name, version, where it was obtained
        - [ ] Admin's justification: "This is Vendor X's monitoring agent v3.2, downloaded from vendor.com"
        - [ ] Enterprise server ID, admin user ID (accountability - who submitted it)
    - [ ] Submission is NOT an approval - it's a request for us to vet the binary
    - [ ] Submitting does NOT change the binary's status in the GTA (remains UNKNOWN until we vet it)
    - [ ] Enterprise admin can still fleet-approve locally (Phase 3.9) while waiting for GTA vetting
- [ ] Isolation and sandboxing (our infrastructure):
    - [ ] Submitted binaries are received into an isolated intake environment:
        - [ ] Air-gapped analysis sandbox (no network access to production GTA systems)
        - [ ] Disposable VM per submission (destroyed after analysis)
        - [ ] No submitted binary ever touches the GTA database until fully vetted
    - [ ] Automated analysis pipeline (runs before any human review):
        - [ ] AV scan: multiple engines (at least 5 - ClamAV, YARA rules, commercial engines)
        - [ ] VirusTotal submission: must return 0 detections across all engines
        - [ ] Sandbox detonation: run in instrumented Windows sandbox (Cuckoo/CAPE):
            - [ ] Monitor: process creation, file writes, registry changes, network connections
            - [ ] Flag any outbound network activity (legitimate installer might phone home - noted)
            - [ ] Flag persistence mechanisms (reg keys, scheduled tasks, services)
            - [ ] Flag privilege escalation attempts
            - [ ] Sandbox verdict: clean / suspicious / malicious
        - [ ] Static analysis: run through our own Phantom Recon scan engine (must score <1.0)
        - [ ] PE analysis: import table, packing, entropy, signature verification
        - [ ] String extraction: check for C2 indicators, hardcoded IPs, suspicious patterns
    - [ ] Automated gate: if ANY automated check fails -> submission REJECTED (never reaches human review)
    - [ ] If all automated checks pass -> queued for human review
- [ ] Human review (our team):
    - [ ] Reviewer verifies: is this actually from the claimed vendor?
    - [ ] Cross-reference with vendor's official distribution channel (download from vendor site, compare hash)
    - [ ] Verify code signature matches known vendor signing certificate
    - [ ] Review sandbox behavior report for anything unusual (even if it passed automated checks)
    - [ ] Reviewer decision: APPROVE (add to GTA) or REJECT (with reason)
    - [ ] Four-eyes principle: critical/large submissions require two independent reviewers
- [ ] Post-vetting:
    - [ ] If APPROVED: binary added to GTA known-good catalog, submitting enterprise notified
    - [ ] If REJECTED: submitting enterprise notified with reason, binary purged from intake
    - [ ] Turnaround time SLA: standard tier = 5 business days, premium = 24 hours
    - [ ] Submission tracking: enterprise admin can check status ("pending analysis", "in review",
          "approved", "rejected") via API or dashboard
- [ ] Anti-abuse on submissions:
    - [ ] Rate limit submissions per enterprise license (standard: 10/month, premium: 100/month)
    - [ ] Size limit per submission (max 100MB - larger binaries require manual arrangement)
    - [ ] Reject submissions of known-malicious hashes immediately (hash matches IOC feeds)
    - [ ] Flag enterprise accounts that repeatedly submit malicious binaries (compromised admin
          or social engineering attempt) - escalate to our security team
    - [ ] Submitted binaries are NEVER shared with other customers (privacy: only the hash and
          verdict enter the GTA, not the binary itself - unless it's a public vendor binary)

### 6.6 Database Integrity & Anti-Abuse
- [ ] GTA database integrity:
    - [ ] All catalog entries signed with our master signing key (Ed25519)
    - [ ] Enterprise server verifies signature on every entry before trusting it
    - [ ] Catalog database has Merkle tree root hash - any tampering is detectable
    - [ ] Master signing key: HSM-stored (hardware security module), never on general-purpose server
- [ ] Abuse prevention:
    - [ ] Enterprise servers are authenticated consumers only - cannot submit entries
    - [ ] No API endpoint for submitting new binaries to GTA (write path is internal-only)
    - [ ] License key revocation: if a customer's key is compromised, revoke without affecting others
    - [ ] Anomaly detection: if one enterprise server makes unusual query patterns
          (e.g., querying millions of random hashes), rate-limit and flag for review
- [ ] Transparency:
    - [ ] Changelog: public log of all additions/removals from GTA catalog
    - [ ] "Why was binary X added?" - each entry has a provenance record (source, vetting date, method)
    - [ ] "Why was binary X removed?" - retraction notices with reason (vendor retraction, discovered vuln)
    - [ ] Customer-accessible audit: enterprise admins can verify any GTA entry's provenance
- [ ] Incident response (if GTA is ever compromised):
    - [ ] If a binary is discovered to be malicious after being cataloged as TRUSTED:
        - [ ] Immediate retraction: status changed to RETRACTED with reason
        - [ ] Emergency push notification to all enterprise servers
        - [ ] Enterprise servers propagate alert to all agents that have the binary
        - [ ] Post-incident: root cause analysis of how it passed vetting, update pipeline
    - [ ] If GTA signing key is compromised:
        - [ ] Revoke old key, issue new key
        - [ ] Enterprise servers have key rotation mechanism (backup public key pre-distributed)
        - [ ] All catalog entries re-signed with new key
        - [ ] Agents/servers reject old-key-signed data after rotation date

### 6.7 Subscription & Licensing
- [ ] Tiers:
    - [ ] **Community** (free): standalone agent only, 100 GTA lookups/day,
          no enterprise server, no OS baselines, no binary submissions
    - [ ] **Professional**: enterprise server + up to 100 agents, 10K GTA lookups/day,
          Windows baselines for 2 OS versions, 10 binary submissions/month
    - [ ] **Enterprise**: unlimited agents, unlimited GTA lookups, all OS baselines,
          catalog sync for air-gapped environments, 100 binary submissions/month,
          24h submission vetting SLA, priority support
    - [ ] **Government/SLED**: Enterprise tier + FIPS 140-2 compliant cryptography,
          FedRAMP-aligned GTA hosting (US-only data residency),
          STIG/CIS baseline profiles pre-loaded, SCAP export included
- [ ] License key mechanics:
    - [ ] Key encodes: customer ID, tier, agent count limit, expiry date, features enabled
    - [ ] Enterprise server validates license with GTA on startup and periodically
    - [ ] Grace period: 30 days after expiry (full functionality, warning banners)
    - [ ] After grace: enterprise server reverts to standalone-equivalent (local-only, no GTA)

---

## Version History

| Version | Date | Milestone |
|---------|------|-----------|
| 0.1 | 2024 | Initial ThreatScan prototype - basic drive scan, MD5, CSV output |
| 0.5 | 2025 | Renamed to Phantom Recon. Added signature analysis, malware scoring, PE analysis, packing detection, security audit, thread safety |
| 0.6 | 2026-03 | Scan modes (Baseline/Full/Fast) with comparison engine, 28 executable extension types, PRBL baseline format v1, registry enumeration for Fast Scan |
| 0.7 | 2026-03 | SHA-256 dual hashing (baseline format v2), configurable scoring weights (INI), 6 additional security checks, results ListView + progress bar + baseline import/export UI, AI triage sidebar with OpenAI-compatible LLM client, settings dialog, dark mode |
| 0.8 | 2026-10-25 | Open-sourced under PolyForm Noncommercial. Architecture refactor: one AppState, joined worker threads, message-only UI updates |
| 1.0.0 | 2026-10-26 | **Current.** Standalone release, Phase 1 complete. Engine library, console program and tests; 51-check audit with catalog, score, fixes and undo; baseline v3 with catalog signatures, revocation, MOTW, streams, header anomalies, scripts, imphash and ssdeep; HTML, JSON and Navigator reports; findings and detail windows, sortable and filterable results, light and dark themes, sample pack, weekly scan, portable mode; CI and tagged releases |
| 2.0 | - | Not planned: enterprise agent (see Direction) |
| 3.0 | - | Not planned: centralized server (see Direction) |
| 4.0 | - | Partly in 1.0.0 (ATT&CK, static analysis); the online parts stay out |
| 5.0 | - | Partly in 1.0.0 (CIS mapping, Navigator layer) |
| 6.0 | - | Not planned: hosted trust service with subscriptions (see Direction) |
