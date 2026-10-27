# Ideas: what is built and what is left

The idea list was written on 2026-10-25, after the architecture refactor. Version 1.0.0
(2026-10-26) built nearly all of it, and version 1.1.0 (2026-10-27) added section 7. Each
item below says what shipped, and for anything not built, why.

The tool stays defensive, offline-first and portable. Nothing here acts on another
machine, reads another program's memory, or sends data anywhere without asking.

Status words: **Done**, **Partly** (what is missing is named), **Not doing** (with the
reason).

---

## 1. Make the results useful to a normal person

| # | Idea | Status |
|---|------|--------|
| 1.1 | Plain-English HTML report | **Done.** Reports > Save HTML Report, or `--report`. One self-contained page, light and dark, prints well. |
| 1.2 | Fix guidance per finding | **Done.** Every check carries the fix and the undo. Copy buttons in the HTML report and in the findings window (F6). The tool never runs a fix itself. |
| 1.3 | Built-in explanations, no AI needed | **Done.** Double-click a result row for every field and a plain explanation of each finding code. |
| 1.4 | Guided first run | **Done.** Getting Started window with a "show at startup" box and a Create Sample Pack button. |
| 1.5 | Hardening score | **Done.** 0 to 100, shown large on the main window. Weights: Critical 10, High 6, Medium 3, Low 1; a warning earns half. |
| 1.6 | Weekly drift check | **Done.** Scans > Weekly Fast Scan, or `--schedule-weekly`. One visible user-level task, removable the same way, with a desktop notification. |
| 1.7 | Portable mode | **Done.** USB drive, `--portable` or `portable.flag`. |

## 2. See more (checks and analysis)

| # | Idea | Status |
|---|------|--------|
| 2.1 | Microsoft Defender state | **Done.** Eight checks, exclusions included. Steps aside correctly when another antivirus is active. |
| 2.2 | Persistence sweep | **Done.** 13 kinds of autostart location, a snapshot so new entries stand out, and a cross-check with the baseline for folders it covers. |
| 2.3 | Core hardening checks | **Done.** BitLocker, TPM, Secure Boot, UAC, LSA protection, RDP and NLA, SMBv1, WinRM, Remote Registry, Guest, AutoPlay, Windows Script Host, PowerShell 2.0, Print Spooler, Office macros. |
| 2.4 | Local accounts and password policy | **Done.** |
| 2.5 | Scheduled tasks through the Task Scheduler API | **Done.** Nested folders, actions, run-as, missing programs, user-writable paths. |
| 2.6 | Real audit policy | **Done.** `AuditQuerySystemPolicy` per subcategory. |
| 2.7 | Mark of the Web and alternate data streams | **Done.** |
| 2.8 | Program header anomalies | **Done.** Timestamps, checksum, TLS callbacks, appended data and its entropy, debug paths, section oddities. Reproducible builds are recognised so their hash-like timestamps are not flagged. |
| 2.9 | Script analysis | **Done.** PowerShell, batch, VBScript, JScript, HTA and WSF, with per-language rules. |
| 2.10 | Running programs against the baseline | **Done** for what can be seen from outside a process: name and folder mismatches, wrong parent, Office starting a shell, drop folders, signatures, baseline hash. **Not doing:** looking inside other processes' memory. Phantom Recon never reads another program's memory. |
| 2.11 | Network exposure snapshot | **Done.** Listening ports with the owning program and its signature, plus the firewall state. |
| 2.12 | Trusted root certificates | **Done.** Compared with Microsoft's root program list that Windows keeps up to date. Roots pushed by Group Policy are listed, not flagged. |
| 2.13 | DNS and hosts hygiene | **Done.** |
| 2.14 | Outdated software table | **Done.** A reviewed built-in table, plus your own rules in a text file. Offline. |
| 2.15 | Revocation checking | **Done.** Off, Windows cache only (default), or online; answers cached for a day. Never online in portable mode. |
| 2.16 | Known-good lists | **Done.** Windows catalog signatures, UPDATED for Microsoft-signed changes, KNOWN for hashes in `known_good_sha256.txt` (any hash list works, an NSRL subset included). |
| 2.17 | Baseline diff | **Done.** File > Compare Two Baselines, or `--diff`. |
| 2.18 | Fuzzy hashes | **Partly.** Import hash and ssdeep are done and feed CHANGED details ("small patch" against "replaced"). TLSH is not: its value is comparing with hashes other tools made, and without the reference implementation to test against, matching output cannot be proven here. |
| 2.19 | DLL search order | **Done.** The first folder Windows searches is the program's own: service folders, the folders of programs running right now as SYSTEM or administrator (with the DLLs each loads that a copy there would replace, KnownDLLs excluded), and system PATH folders that normal users can write to. Reads the program file and the process's rights, never its memory. |
| 2.20 | Group Policy Preference passwords | **Done.** Reports the file location only. |

## 3. Output and interoperability

| # | Idea | Status |
|---|------|--------|
| 3.1 | JSON export | **Done.** Schema `phantomrecon.report/1`. |
| 3.2 | MITRE ATT&CK tags and a Navigator layer | **Done.** On checks, imports, packing, header, origin and script findings. |
| 3.3 | CIS mapping | **Done** for CIS Controls v8, plus the CIS Windows Benchmark recommendation title where one matches. The tool does not claim a full benchmark. |
| 3.4 | Signed releases | **Partly.** GitHub Actions builds, tests and publishes the zip with its SHA-256; `tools/make_winget_manifest.py` writes a winget manifest that passes `winget validate`. Code signing is not done: it needs a certificate this project does not have. |

## 4. Ways to run it

| # | Idea | Status |
|---|------|--------|
| 4.1 | Headless command line | **Done.** `PhantomReconCli.exe`, exit codes 0, 1 and 2. |
| 4.2 | Determinate progress | **Done.** Files are counted first; the bar and the label show the percentage and the time left. |
| 4.3 | Results list: sort, filter, detail | **Done.** Click a header to sort, a filter list, a search box, a detail window, a right-click menu. Handles any number of rows. |
| 4.4 | Scan settings | **Done.** Exclusions, default folders, baseline file, reports folder, revocation, Fast Scan depth, fuzzy hashing. A baseline or Full Scan can cover several folders at once. |
| 4.5 | Light theme and system theme | **Done.** Follow Windows, dark or light; follows Windows live when it changes. |

## 5. Engineering

| # | Idea | Status |
|---|------|--------|
| 5.1 | Test harness | **Done.** `PhantomReconTests.exe`, no framework. Builds its fixtures at run time. |
| 5.2 | GitHub Actions | **Done.** Build with warnings as errors, tests, a command-line smoke test, release on tags. |
| 5.3 | Self-describing checks | **Done.** One catalog row per check feeds the audit text, the HTML report, the findings window, the score and `docs/FINDINGS.md`. Tests make sure every row has a check and every check has a row. |
| 5.4 | Long path support | **Done.** |
| 5.5 | Redaction before sending to the AI | **Done.** User, computer and domain names are hidden; long text is sent in parts. |

## 6. For the video and the community

| # | Idea | Status |
|---|------|--------|
| 6.1 | Sample data pack | **Done.** Help > Create Sample Pack, `--make-samples`, or `PhantomRecon.exe --samples <folder>`. Tiny programs whose only code is "return". It contains no packed or malware-like programs on purpose; `odd_headers.exe` shows the header findings instead. |
| 6.2 | Demo baseline | **Done differently.** The demo baseline belongs to the sample pack. A baseline of one person's Program Files would be wrong on every other PC. |
| 6.3 | One page of what the findings mean | **Done.** [FINDINGS.md](FINDINGS.md), generated from the catalog. |

## 7. Added in version 1.1.0

| # | Idea | Status |
|---|------|--------|
| 7.1 | More platform checks | **Done.** Memory integrity, the vulnerable driver block list, Smart App Control, system exploit protection, screen lock, System Restore, saved open Wi-Fi networks that connect on their own. |
| 7.2 | Recent activity from this PC's own event logs | **Done.** Cleared logs, newly installed services, new accounts and administrators, failed sign-ins, Microsoft Defender detections. Not scored: they report events, not settings. The Security log needs administrator rights; without it those parts are N/A, never a false PASS. |
| 7.3 | Sharing, sign-in and driver checks | **Done.** Shared folders anyone can change, SMB guest access, inbound firewall rules open on public networks (WARNING only for programs in folders normal users can change, or rules that open everything), automatic sign-in (whether a stored password exists, never its value), NTLM and LM settings, driver files. |
| 7.4 | Hygiene checks | **Done.** WDigest, paused or long-deferred updates, Remote Assistance, cached domain sign-ins, Windows sudo in inline mode, DNS over HTTPS (information only). |
| 7.5 | Fix plan | **Done.** Reports > Save Fix Script, the findings window, or `--fix-script`. A PowerShell script the user reads and runs: every step asks first, `-ListOnly` changes nothing, values from the PC only ever appear as single-quoted text. Before a registry step it saves the earlier values, so the matching undo script puts back exactly what was there. The program still never runs a fix. |
| 7.6 | Audit history | **Done.** What changed since the last audit (fixed, new problems, worse, better), a score chart in the HTML report, `--history`, a switch to turn it off. Only check ids and results are kept, no names or paths. |
| 7.7 | Biggest wins | **Done.** The five fixes that raise the score most, in the reports and the findings window. |

---

## Left to do, in order

1. Code-sign the releases if a free signing service for open-source projects accepts a
   noncommercial license (rest of 3.4).
2. TLSH, once the output can be tested against the reference implementation (rest of 2.18).
3. Exact undo for fix-plan steps that are not registry values (`Set-MpPreference`,
   `net accounts`, `wevtutil`, SMB and firewall cmdlets): today they undo to the Windows
   default, and the undo script says so (rest of 7.5).
4. A lock around the audit history file, so two audits finishing at the same moment (the
   window program and the console program) cannot drop one record. The file itself can
   never be half written (rest of 7.6).
5. Anything people ask for in issues, inside the defensive scope.
