# Video outline: "Find out what changed on your Windows PC"

Target: 9 to 11 minutes. Audience: people who are careful but not security professionals.
Goal: by the end they have run the audit, fixed one thing, watched the score go up, and
taken their first baseline.

## Before recording

- Record in a fresh Windows 11 virtual machine with a user account named `demo`. The
  tool shows full file paths and the computer name, so your real names would appear on
  screen. Also turn on **Reports > Hide Names in Reports** before saving any report.
- Install two or three ordinary programs so Fast Scan has something to list.
- Download the release zip, check its SHA-256, unzip to `C:\Tools\PhantomRecon\`.
- Have a small program installer ready to install mid-video (7-Zip is fine).
- OBS at 1080p, 30 fps. Windows display scaling at 125 percent so the list text is
  readable.
- Keep the AI panel closed unless a local model is running. If you show it, say out loud
  that it is optional and local.

## Script beats

**0:00 Hook (20 s)**
"Is there anything on your PC today that was not there a month ago? Is Windows set up
safely? Most people cannot answer either question. This free tool answers both."

**0:20 What it is and is not (40 s)**
Not antivirus. Two jobs: check Windows settings for well-known weak spots and show the
fix, and take a photo of your programs so it can tell you later exactly what changed.
Runs offline. No account, no install. Source is public under a license that says nobody
can ever sell it.

**1:00 Get it (40 s)**
GitHub page, Releases, the zip. Show the SHA-256 on the release page and check it:
`Get-FileHash .\PhantomRecon-1.1.0-x64.zip`. Explain in one line why: the program is not
code-signed, so the hash is how you know it is the real one. Unzip.

**1:40 First launch: the score (2 min)**
Start `PhantomRecon.exe`. The Getting Started window explains the two jobs; close it.
Point at the hardening score filling in on the right. Press **F6**. The findings window
lists problems worst first, and marks the five "biggest wins": the fixes that raise the
score most. Pick three common on a home PC and explain each in one sentence:
- LLMNR on: your PC asks the whole network "who is this name" and believes anyone who
  answers.
- PowerShell logging off: if something runs a script, there is no record.
- A service program normal users can change: a program could swap it out and run as the
  system.
Click **Copy the Fix** on LLMNR, paste it into an administrator PowerShell, run it. Point
at **How to undo** so people see it is reversible. Back in Phantom Recon press **F5**.
The check turns PASS, the score goes up, and the line under it says "+N since" the last
audit: the program remembers results (only check names and results, no files or names).
Then **Reports > Save Fix Script**. Open it in Notepad for five seconds: every step says
why, asks "Apply this step? [y/N]" before changing anything, and a matching undo script
puts back exactly what was there. Say it twice: the program never runs it, you do, and
`-ListOnly` shows the steps without changing anything.

**3:40 See it work on harmless samples (1 min)**
Help > Create Sample Pack. Pick a folder. Say what is in it: tiny programs that do
nothing, one with odd headers, one marked as downloaded, one with a hidden data stream.
It scans right away: 1 NEW, 1 CHANGED, 1 MISSING, the rest MATCH. Double-click
`odd_headers.exe` and read one finding's explanation out loud.

**4:40 Your real baseline (1.5 min)**
Scans > Take Baseline. Read the message out loud: only on a day you trust the PC. Pick
`C:\Program Files`, accept the CSV location. Point at the progress bar with a real
percentage, the counters, the rows filling in, the colours. Say what the score column
means: how much a file looks like something that hides or tampers, from zero to ten. A
reason to look, not proof.

**6:10 Change something (30 s)**
Install the small program you prepared. A normal install.

**6:40 Full Scan (1.5 min)**
Scans > Full Scan of the same folder. Choose "Needs review" in the Show list. The new
program's files are NEW. Double-click one: signed by its vendor, what changed, where it
came from. Explain MISSING in one line: it was here before and now it is gone. Explain
UPDATED in one line: Windows or Office updated it with a Microsoft-signed file.

**8:10 Reports and the weekly habit (50 s)**
Reports > Save HTML Report; it opens in the browser. Scroll: score, "Since your last
audit" with the score chart, the biggest wins, findings with copy buttons, the Recent
activity section (cleared logs, new services, Defender detections from this PC's own
event logs; run as administrator to include the Security log), the scan table. Then Scans > Weekly Fast Scan: one visible task every Sunday,
removable from the same menu. It runs the scan and the audit, and it only shows a
notification when something got worse ("2 new problems since 20 Oct"). "If Sunday is
quiet, you are done."

**9:00 The optional AI panel (30 s)**
Click the AI tab on the right edge. It talks to a model on your own PC if you have one,
hides your names before sending, and asks first if you ever point it somewhere else.

**9:30 For the technical viewers (30 s)**
`PhantomReconCli.exe --help`. One line: the same engine for scripts and scheduled jobs,
exit code 1 when something needs attention. JSON report and an ATT&CK Navigator layer.

**10:00 Where to go (30 s)**
The repo, the README, `docs/FINDINGS.md`, the issues tab. Ask people to report what
confused them. One sentence on the license.

**10:30 Close (20 s)**
"Take your baseline tonight. Next month you will know."

## Things to avoid saying

- Do not call it an antivirus or say it "detects malware". Say it shows weak settings,
  scores how suspicious a file looks, and tells you what changed.
- Do not promise it catches everything. It looks at files on disk, settings and which
  programs are running. It does not look inside other programs' memory, on purpose, and
  it does not watch network traffic.
- Do not show your real user name, computer name or network addresses anywhere on screen.

## Companion files to publish with the video

- [FINDINGS.md](FINDINGS.md): every check in plain words with the fix, so viewers can
  pause and read.
- The release zip and its SHA-256.
