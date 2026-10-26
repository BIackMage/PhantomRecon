# Video outline: "Find out what changed on your Windows PC"

Target: 8 to 10 minutes. Audience: people who are careful but not security professionals.
Goal: by the end they have run the audit, fixed one thing, and taken their first baseline.

## Before recording

- Record in a fresh Windows 11 virtual machine with a user account named `demo`. The
  tool shows full file paths, so your real user name would appear on screen.
- Install two or three ordinary programs so Fast Scan has something to list.
- Build Release x64 once and copy the exe to `C:\Tools\PhantomRecon\` in the VM.
- Have a second small program installer ready to install mid-video (7-Zip is fine).
- OBS at 1080p, 30 fps. Zoom the UI with Windows display scaling at 125 percent so the
  list view text is readable.
- Keep the AI sidebar closed unless you have a local model running. If you show it, say
  out loud that it is optional and local.

## Script beats

**0:00 Hook (20 s)**
"Is there anything on your PC today that was not there a month ago? Most people have no
way to answer that. This free, open-source tool gives you the answer in two scans."

**0:20 What it is and is not (40 s)**
Not antivirus. It does three things: takes a photo of your executables, checks your
Windows settings for well-known weak spots, and later tells you exactly what changed.
Runs offline. One file. No account. Source is public under a license that says nobody can
ever sell it.

**1:00 Get it (40 s)**
Show the GitHub page. Download the release, or build from the solution in Visual Studio.
Show the folder with the exe and nothing else.

**1:40 First launch: the audit (2 min)**
Start it. The left panel fills in on its own. Explain the three statuses. Open
`security_audit_report.txt` in Notepad. Pick three findings that are common on a home PC
and explain each in one sentence:
- LLMNR enabled: your PC asks the whole network "who is this name" and will believe anyone
  who answers.
- PowerShell script block logging off: if something runs a script, there is no record.
- A service running from a folder you can write to: a program could swap it out.
Fix one live (LLMNR via the registry key the report names). Restart the tool. Show it
turn to PASS.

**3:40 Baseline (1.5 min)**
Scans > Get Baseline. Read the warning out loud: only do this on a day you trust the
machine. Pick `C:\Program Files`. Pick where to save the CSV. Let it run. Point at the
counters, the current file line, the rows filling in, the colours. Say what the score
column means in one sentence: how much this file looks like something that hides and
injects, from zero to ten.

**5:10 Change something (30 s)**
Install the small program you prepared. Nothing scary. Just a normal install.

**5:40 Full Scan (1.5 min)**
Scans > Full Binary Scan on the same folder. Show the new rows marked NEW. Open the CSV
in Excel or Notepad, point at the Baseline Status column and the Change Details column.
Explain MISSING in one line: it was here before and now it is gone.

**7:10 The weekly habit (40 s)**
Scans > Fast Binary Scan. Explain it only checks installed programs, so it finishes in a
minute. "Do this on Sunday. If everything says MATCH, you are done."

**7:50 The optional AI panel (30 s)**
Click the AI tab. Say: this talks to a model running on your own PC if you have one. It
is off by default in the sense that nothing is sent until you press a button, and if you
point it at a server that is not your PC, it asks first and tells you what will leave.

**8:20 Where to go (30 s)**
The repo, the README, the issues tab. Ask people to report what confused them. Mention
the license in one sentence.

**8:50 Close (20 s)**
"Take your baseline tonight. Next month you will know."

## Things to avoid saying

- Do not call it an antivirus or say it "detects malware". Say it scores how suspicious a
  file looks and tells you what changed.
- Do not promise it catches everything. It sees files on disk and settings. It does not
  see memory or network traffic yet.
- Do not show your real user name, host name or network addresses anywhere on screen.

## Companion files to publish with the video

- `docs/FINDINGS.md` once it exists (see IDEAS.md 6.3): each finding in plain words with
  the fix, so viewers can pause and read.
- The sample data pack (IDEAS.md 6.1) so viewers can see a red row without doing
  anything risky.
