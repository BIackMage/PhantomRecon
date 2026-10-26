# Ideas: what Phantom Recon could do next

Written 2026-10-25, after the architecture refactor. Nothing here is built yet. Each item
says who it helps, what it would take, and roughly how big it is (S: an evening, M: a
weekend, L: a week or more). The tool stays defensive, offline-first and single-exe. Nothing
in this list acts on another machine or sends data anywhere without asking.

The five I would do first are marked with a star.

---

## 1. Make the results useful to a normal person

**1.1 Plain-English HTML report** (star, M)
After the audit and after a scan, write `phantom_recon_report.html` next to the CSV. One
page. A traffic-light summary at the top (how many FAIL, WARN, PASS), then one card per
finding in plain words: what it is, why it matters, what to do. Sortable tables for the
scan rows. Embedded CSS, no external files, opens in any browser, prints to PDF. This is
the thing a home user or a small-business owner can actually read, and the thing a
consultant hands to a client.

**1.2 Fix guidance per finding** (star, M)
Every FAIL or WARN gets a "how to fix" block: the exact PowerShell or registry command,
what it changes, and the command to undo it. Copy button in the HTML report. The tool does
not run the fix itself. People learn more when they run it, and the tool stays safe to
hand to anyone. Fix text lives in a table next to the check (see 5.3) so docs and report
come from one source.

**1.3 Built-in explanations, no AI needed** (star, S)
Most users will not have a local LLM running. Add an "Explain" action on a results row and
on each audit finding that shows a fixed, written explanation from a table in the code.
The AI sidebar stays as the optional deeper layer.

**1.4 Guided first run** (S)
On first launch, a short panel: "1. Run the audit (already done). 2. Take a baseline of
Program Files on a day you trust the machine. 3. Come back next week and run Fast Scan."
Three buttons. Hide it once a baseline exists.

**1.5 Hardening score** (S)
Turn the audit into a 0 to 100 score with a short label. Show it big on the left panel.
Run audit, fix two things, run again, watch it go up. This is the hook for the video.

**1.6 Weekly drift check** (M)
A menu item that registers a Task Scheduler entry (user-level, visible, removable from the
same menu) to run a Fast Scan once a week and write the HTML report. Toast on NEW or
CHANGED. Everything stays local. Needs the headless mode in 4.1.

**1.7 Portable mode** (S)
Flag or auto-detect "running from removable media": write every output next to the exe,
touch nothing on the host. For auditing a machine you do not own and do not want to leave
traces on.

---

## 2. See more (new checks and analysis)

These are the parts of the roadmap that most help ordinary Windows users, ordered by
value for effort.

**2.1 Windows Defender state** (star, M)
Real-time protection on, tamper protection on, cloud-delivered protection on, SmartScreen
on, Controlled Folder Access, Attack Surface Reduction rule state, and most important the
exclusion list. Attackers add exclusions; nobody looks at them. Read through WMI
`root\Microsoft\Windows\Defender` or the policy registry keys. Huge value, every PC has it.

**2.2 Persistence sweep** (star, L)
The Autoruns idea done as checks: Run and RunOnce (have), Winlogon Shell and Userinit,
Image File Execution Options debuggers, AppInit_DLLs, WMI event subscriptions, LSA
authentication and notification packages, print monitors, Explorer shell extensions,
Office add-ins, browser extensions, services whose binary is unsigned or outside Program
Files and Windows. Every hit shows the binary with its signature and score, and gets
compared to the baseline so a new persistence entry shows as NEW.

**2.3 Core hardening checks that are missing** (M)
BitLocker per volume, TPM present, Secure Boot on, UAC level, LSA protection (RunAsPPL),
RDP enabled and whether NLA is required, SMBv1 enabled, WinRM listeners, Remote Registry
running, Guest account enabled, AutoPlay, Windows Script Host enabled, PowerShell v2
engine present, Print Spooler on a machine that has no printer, macro settings. Each one
is a few registry reads or one API call. Together they are what a CIS Level 1 pass looks
like for a home or small business PC.

**2.4 Local accounts and password policy** (M)
NetUserEnum for accounts, enabled state, last logon, password age; NetUserModalsGet for
minimum length, lockout threshold, maximum age; whether the built-in Administrator was
renamed and whether Guest and DefaultAccount are disabled. On the roadmap already (1.5).

**2.5 Scheduled tasks done properly** (M)
Use the Task Scheduler COM API instead of reading the Tasks folder. Walk nested folders,
read actions, triggers and run-as. Flag actions in temp or user-writable paths, tasks that
run as SYSTEM but were created by a user, and tasks pointing at missing binaries.

**2.6 Real audit policy** (S)
`AuditQuerySystemPolicy` per subcategory instead of the registry proxies. Say which of
logon, process creation, object access and privilege use are actually auditing.

**2.7 Mark of the Web and alternate data streams** (S)
Read `Zone.Identifier` on every executable: zone, referrer, host URL. Flag internet-sourced
unsigned executables. Flag an executable in Downloads with no MOTW at all (stripped).
Enumerate other named streams and flag executable content inside them.

**2.8 PE header anomalies** (M)
Compile timestamp in the future or zeroed, checksum mismatch, TLS callbacks present,
overlay data after the last section with its entropy, PDB path with a user name or words
like payload or inject. All static, all cheap, all already parsed halfway in
MalwareScoring.

**2.9 Script analysis** (M)
For .ps1, .bat, .cmd, .vbs, .js, .hta: encoded command flags, Invoke-Expression, download
cradles, base64 blobs over 100 chars, char-code building, certutil decode, bitsadmin
transfer, mshta and regsvr32 patterns. Produces a script risk score that feeds the composite.

**2.10 Running processes against the baseline** (L)
Snapshot running processes. For each image: is it in the baseline, did its hash change, is
it running from a user-writable or network path, does its name match a system binary but
its path does not. Then per process: any executable private memory region (RWX, no file
behind it) in a process that is not a known JIT host. This is the single most useful live
check and it needs no driver.

**2.11 Network exposure snapshot** (M)
Listening TCP and UDP ports mapped to owning process, with that binary's signature and
score, plus the firewall rules that allow inbound to it. "Unsigned binary listening on
port 4444" is a finding anyone understands.

**2.12 Certificate store audit** (S)
Enumerate trusted root CAs on the machine and compare to the known-good list the tool
already carries. Corporate proxies and some malware install their own roots. Flag anything
unexpected with its thumbprint and install date.

**2.13 DNS and hosts hygiene** (S)
Hosts file entries that redirect well-known domains, DNS servers set statically that differ
from DHCP, DNS over HTTPS state. Cheap and catches real tampering.

**2.14 Outdated software table** (M)
Ship a small, hand-curated table of "known vulnerable below version X" for the twenty most
installed desktop apps (browsers, Java, 7-Zip, Adobe Reader, VLC, Zoom, Notepad++). Fast
Scan already has the versions. Offline. Optional online NVD lookup later, opt-in.

**2.15 Revocation checking** (M)
CRL and OCSP for signed binaries, cached per thumbprint, "unknown" when offline. Roadmap 1.1.

**2.16 Known-good lists to kill false NEWs** (L)
After Patch Tuesday a Full Scan lights up with hundreds of NEW and CHANGED system files.
Check Windows files against the catalog store (CatRoot) membership and an optional local
NSRL subset. Mark "changed by a Microsoft catalog-signed update" separately from "changed
by something else".

**2.17 Baseline diff tool** (S)
File > Compare Two Baselines: open two .prbl files, show added, removed and changed
entries. Answers "what did that update change" without rescanning.

**2.18 Fuzzy hashes** (M)
Import hash now (it is just MD5 of the ordered import list). ssdeep and TLSH later. Lets
CHANGED be split into "small patch" versus "replaced with something else", and lets a
local list of bad hashes match variants.

**2.19 DLL search order hijack check** (M)
For every service and every running process, walk the DLL search order and flag a
user-writable directory that comes before the real DLL. Roadmap 1.5.

**2.20 GPP cpassword** (S)
Domain-joined only. Search SYSVOL for the six XML files with cpassword attributes and
report the file path. The key is public (MS14-025) so decrypting is fine, but reporting the
location is enough for a defender.

---

## 3. Output and interoperability

**3.1 JSON export** (S)
Versioned schema. One file per run: host facts, audit findings, scan rows. This is what
lets other people build on the tool without parsing CSV.

**3.2 MITRE ATT&CK tags on every finding** (M)
Add a technique id field to `SecurityCheckResult`, `SuspiciousImport` and the packing
result. Carry it into the CSV, JSON and HTML. Export an ATT&CK Navigator layer. The
roadmap has the full mapping table written out already (4.4).

**3.3 CIS Benchmark mapping for the checks we have** (M)
Only the controls the tool actually tests, mapped to the Windows 11 Level 1 benchmark ids.
Honest coverage number in the report. Do not claim a full benchmark.

**3.4 Signed releases** (S)
Build in GitHub Actions, sign with a free open-source code-signing service, publish the
SHA-256 in the release notes, add a winget manifest. A security tool that is itself
unsigned looks wrong in its own results list.

---

## 4. Ways to run it

**4.1 Headless command line** (star, M)
`PhantomRecon.exe --audit --report out.html`, `--baseline C:\ --out base.prbl`,
`--fast --baseline base.prbl --report out.html`. No window. Exit code reflects findings.
This is what makes 1.6 (scheduled check) possible, what an MSP can push through an RMM,
and what a CI job can run against a golden image. The engine is already separate from the
UI after the refactor, so this is mostly a second entry point.

**4.2 Determinate progress** (S)
Pre-count files on the chosen root (fast, directory metadata only), set the progress range,
show percent and files per second. Roadmap 1.6.

**4.3 Results list: sort, filter, detail** (M)
Click a header to sort. A filter strip: show only NEW, CHANGED, MISSING, score above N.
Double-click a row for a detail window with every field and the explanation from 1.3.

**4.4 Scan settings** (S)
Exclusions (paths and extensions), default scan root, active baseline path, output folder.
Settings dialog grows a second tab.

**4.5 Light theme and system theme** (S)
Follow the Windows app theme setting. The palette is already in one place.

---

## 5. Engineering

**5.1 Test harness** (star, M)
A second project, `PhantomRecon.Tests`, console exe, no framework needed. Build fixture
binaries at test time (a tiny PE with known imports via the compiler, a UPX-packed copy, an
unsigned copy, a self-signed copy). Assert scores, packer detection, CSV round trip, PRBL
round trip, comparison statuses, `IsExecutableExtension`, `IsLoopbackEndpoint`. The GUI
stays untested; the engine stops being untested.

**5.2 GitHub Actions** (S)
`windows-latest`, build Debug and Release, run 5.1, upload the exe as an artifact on every
push. A green badge on the README is worth a lot of trust for a security tool.

**5.3 Self-describing checks** (M)
Each check carries id, title, severity, ATT&CK id, CIS id, plain explanation, fix text and
undo text in one struct. The report, the docs page and the explanations in 1.3 all generate
from that table. Adding a check becomes adding one row and one function.

**5.4 Long path support** (S)
`\\?\` prefix on every file open so paths past 260 characters hash and sign-check instead
of silently failing. Common in node_modules and build trees.

**5.5 Redaction before sending to the AI** (S)
Replace `C:\Users\<name>` with `C:\Users\<user>` and the hostname with `<host>` before a
prompt leaves the process, even to localhost. Cap prompt size and chunk the audit text.

---

## 6. For the video and the community

**6.1 Sample data pack** (S)
A folder of harmless fixture files that trigger each finding type (an unsigned exe, a
UPX-packed exe, a .bat with an encoded PowerShell line, a file with a Zone.Identifier
stream) so viewers can see every row colour without touching anything dangerous.

**6.2 Demo baseline** (S)
A `.prbl` of a clean Windows 11 Program Files tree so a new user can run Fast Scan on
minute one and see MATCH rows before they make their own baseline.

**6.3 One-page "what the findings mean"** (S)
`docs/FINDINGS.md`: every audit check in plain words with the fix. Doubles as the script
source for the video and the content for 1.2.

---

## Suggested order

1. 5.1 test harness and 5.2 CI, because everything after this changes scoring code.
2. 5.3 self-describing checks, because 1.1, 1.2, 1.3 and 3.2 all read from it.
3. 2.1 Defender state and 2.3 core hardening checks, because they are the findings a home
   user cares about most and they are cheap.
4. 1.1 HTML report with 1.2 fix guidance and 1.5 score. This is the video.
5. 4.1 headless mode, then 1.6 weekly check.
6. 2.2 persistence sweep and 2.10 running processes. The big detection wins.
7. Everything else as demand shows up in issues.
