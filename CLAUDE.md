# Phantom Recon: rules for anyone (human or AI) changing this code

Read this before writing a line. These rules exist because the GUI file once grew into a
single 1,400-line switch statement with 16 globals and 9 fire-and-forget threads. The
2026-10 refactor undid that. Keep it undone.

## Scope: defensive only

Phantom Recon looks at the PC it runs on, reports what it finds, and shows fixes for the
user to run. It never:

- reads another process's memory, or asks for the debug privilege to do so;
- acts on, scans or connects to another machine;
- runs a fix itself, disables a security product, or hides from one;
- sends data off the PC without the user turning it on and confirming.

Describe findings as misconfigurations and their risk, never as a path to exploit. A
change that drifts from this is rejected, however useful it looks.

## Architecture invariants

1. **One owner for state.** All application state lives in `AppState` (`AppState.h`),
   created once in `wWinMain` and reached through `GetAppState(hWnd)`. No new file-scope
   variables. No variables defined in headers. A module may keep `static const` tables.

   *The one exception:* process-wide caches of facts that cannot change while the program
   runs live in a function-local `static` behind a mutex: the revocation cache, the
   signature summary cache, the Defender snapshot, the optional-feature cache, the
   known-good list, the theme palette (UI thread only). Each is documented where it is
   defined. Do not add one for anything the user can change.

2. **Background threads never touch a window.** No `SetWindowText`, `SendMessage`,
   `ListView_*`, `MessageBox`, `GetWindowText` or any other HWND call from a worker. A
   worker does its work, then `PostMessage`s one of the `WM_APP_*` messages in
   `AppMessages.h` with a heap payload. The UI handler owns and deletes the payload. Use
   `PostPayload()` so a failed post frees it.

3. **No detached threads.** Every thread starts through `BackgroundWorker::Run` on
   `AppState::worker`. `wWinMain` joins the worker after the message loop ends.

4. **Typed data, named fields.** A scan fact is a named field on `BaselineEntry`
   (`ScanTypes.h`). A finding is a `SecurityCheckResult` with a catalog id. Never pass
   results around as string arrays. The results list asks `ResultsModel` for cell text.

5. **The window procedure dispatches, it does not do.** `MainWndProc` is a switch that
   calls one handler per message. Commands go through `DispatchCommand`, one function per
   command id. A handler past about 40 lines gets its own function or module.

6. **The engine has no UI.** Everything in `PhantomRecon.Core` must work from the console
   program and the tests. If it needs a window, it belongs in the app project.

7. **One module per concern.** New check: a function in `SecurityChecks<Topic>.cpp`, a
   row in `CheckCatalog.cpp`, an entry in `AuditRunner.cpp`. The tests fail if any of the
   three is missing. New UI: its own `.cpp` with a small header.

8. **Defaults have one home.** LLM defaults: `LLMConfig`. Scan defaults: `ScanOptions`.
   Scoring weights: `ScoringConfig.cpp`. `AppSettings` copies from those.

9. **Evidence stays readable.** A check caps its own long lists (`CappedList`), and
   `LimitDetail` cuts any detail over 20,000 characters. A report that is mostly one
   check helps nobody.

## Threading model

The UI thread owns every HWND. A scan runs on one worker: `ScanEngine.cpp` calls
`RunScan` (`ScanCore.cpp`) with callbacks that update `AppState::progress` (atomics and
mutex-guarded strings), queue rows in `progress.pendingRows`, and post
`WM_APP_SCAN_ROWS` and `WM_APP_SCAN_PROGRESS`, each at most once in flight. At the end
it posts `WM_APP_SCAN_FINISHED` with the `ScanSummary`. The audit runs the same way from
`AuditController.cpp` (`WM_APP_AUDIT_PROGRESS`, `WM_APP_AUDIT_FINISHED`). AI requests post
`WM_APP_AI_RESPONSE` to the panel. The settings test posts `WM_APP_STATUS_TEXT` to the
dialog. `WM_CLOSE` sets both cancel flags; `wWinMain` joins the worker.

## Module map

Engine (`PhantomRecon.Core.vcxproj`, static library):

| File | Owns |
|------|------|
| `ScanCore.cpp` | `AnalyzeFile`, exclusions, `RunScan` (walk, compare, CSV, MISSING sweep) |
| `Baseline.cpp` | `.prbl` format v1 to v3, lookup, comparison, `DiffBaselines` |
| `FileAnalysis.cpp` | Signatures (embedded and catalog), chain, revocation, version, attributes, DACL, entropy |
| `PeFile.cpp`, `MalwareScoring.cpp` | PE parsing, imphash, header findings, import and packing analysis, score |
| `FileOrigin.cpp`, `ScriptAnalysis.cpp`, `FuzzyHash.cpp` | Mark of the Web and streams, script rules, ssdeep |
| `KnownGood.cpp`, `ScoringConfig.cpp` | Known-good hash list, scoring weights |
| `ScanCsv.cpp`, `ResultsModel.cpp` | CSV read and write; rows with filter, search and sort |
| `CheckCatalog.cpp` | Every check's title, severity, mappings, explanation, fix and undo |
| `AuditRunner.cpp`, `SecurityChecks*.cpp` | The audit and its checks |
| `CheckHelpers.cpp` | Pure decision logic behind the checks (testable) |
| `HardeningScore.cpp`, `AttackMapping.cpp` | Score; ATT&CK names, finding codes, Navigator |
| `ReportHtml.cpp`, `ReportJson.cpp`, `DetailText.cpp` | Reports; plain-text explanations for windows and AI |
| `Redactor.cpp`, `LLMClient.cpp` | Name hiding; the optional AI client |
| `SampleData.cpp`, `ScheduledScan.cpp`, `CliRunner.cpp` | Sample pack, weekly task, the console program's logic |
| `StartupRequest.cpp` | The window program's command line |
| `AppPaths.cpp`, `FileIO.cpp`, `RegUtil.cpp`, `ServiceUtil.cpp`, `WmiQuery.cpp`, `SystemInfo.cpp`, `HashUtils.cpp`, `TextUtils.h` | Shared helpers |

Window app (`PhantomRecon.vcxproj`):

| File | Owns |
|------|------|
| `PhantomRecon.cpp` | `wWinMain`, window class, `MainWndProc`, per-message handlers |
| `MainLayout.cpp` | Controls, resize layout, score display, operation label |
| `MainCommands.cpp`, `ReportCommands.cpp`, `ResultsCommands.cpp` | One function per command |
| `ScanEngine.cpp`, `AuditController.cpp` | Background scan and audit, posting back |
| `CommandHelpers.cpp`, `StartupArgs.cpp` | Shared command pieces; command line and dropped files |
| `GuiComponents.cpp`, `Theme.cpp` | List, progress bar, dialogs, clipboard; light and dark |
| `FindingsWindow.cpp`, `DetailWindow.cpp`, `AppDialogs.cpp`, `SettingsDialog.cpp` | Secondary windows |
| `AiSidebar.cpp` | The optional AI panel |
| `AppState.h`, `AppMessages.h`, `BackgroundWorker.cpp` | State, messages, threads |

Console program: `cli/CliMain.cpp`. Tests: `tests/`.

## Build, test, verify

```powershell
msbuild PhantomRecon.sln /p:Configuration=Release /p:Platform=x64 /m /v:minimal
.\x64\Release\PhantomReconTests.exe
```

A change is done when the build has no warnings (CI builds with warnings as errors), every
test passes, and you have run the program and exercised the path you touched. Engine
changes get a test. The window code has no automated tests; say in the commit message
what you ran by hand.

Set `PHANTOMRECON_TRACE=1` to print engine trace lines (`Trace()` in `DebugTrace.cpp`) to
stderr. Every module also writes `OutputDebugStringW` lines with a `[Module]` prefix,
visible in DebugView or the debugger. Leave existing debug lines in place.

## Style

- Win32 and the C++17 standard library only. No third-party dependencies.
- `std::wstring` for anything that touches the file system or the UI. UTF-8
  `std::string` only at the JSON boundary of the AI client. Convert with `StringConv.h`.
- ASCII in source and docs: no typographic dashes or quotes (they break PowerShell on the
  maintainer's machine), and no accented letters in comments.
- No stubs, no TODO comments. Finish the function or do not add it.
