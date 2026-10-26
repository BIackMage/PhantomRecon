# Phantom Recon: rules for anyone (human or AI) changing this code

Read this before writing a line. These rules exist because the GUI file was growing into a
single 1,400-line switch statement with 16 globals and 9 fire-and-forget threads. The 2026-10
refactor undid that. Keep it undone.

## Architecture invariants

1. **One owner for state.** All application state lives in the `AppState` struct
   (`AppState.h`), created once in `wWinMain` and reached from window procedures through
   `GetAppState(hWnd)`. No new file-scope variables. No variables defined in headers. A
   module may keep `static const` tables and brushes, nothing mutable.

2. **Background threads never touch a window.** No `SetWindowText`, `SendMessage`,
   `ListView_*`, `MessageBox`, `GetWindowText` or any other HWND call from a worker. A worker
   does its work, then `PostMessage`s one of the `WM_APP_*` messages in `AppMessages.h` to
   the UI thread with a heap payload. The handler on the UI thread owns and deletes the
   payload. Use `PostPayload()` so a failed post frees the payload.

3. **No detached threads.** Every thread starts through `BackgroundWorker::Run` on
   `AppState::worker`. `wWinMain` joins the worker after the message loop ends. If you need
   a thread that outlives the window, you are wrong.

4. **Typed data, named fields.** A scan fact is a named field on `BaselineEntry`
   (`ScanTypes.h`). A security finding is a `SecurityCheckResult`. Never pass results around
   as string arrays or index into a row by column number outside `GuiComponents.cpp`.

5. **The window procedure dispatches, it does not do.** `MainWndProc` in `PhantomRecon.cpp`
   is a switch that calls one handler per message. Menu and button commands go through
   `DispatchCommand` in `MainCommands.cpp`, one function per command id. A handler that grows
   past about 40 lines gets its own function or its own module.

6. **One module per concern.** New security checks go in `SecurityChecksExtra.cpp` or a new
   `SecurityChecks<Topic>.cpp`, then get registered in `RunAllSecurityChecks()`. New file
   analysis goes in `FileAnalysis.cpp` or `MalwareScoring.cpp`. New UI goes in its own
   `.cpp` with a small header. Nothing new goes into `PhantomRecon.cpp`.

7. **Defaults have one home.** The LLM endpoint default is `LLMConfig` in `LLMClient.h`.
   Scoring defaults are in `ScoringConfig.cpp`. If a value is defined twice, delete one.

8. **Scope.** This is a defensive, offline, single-executable Windows auditing tool. It does
   not get an agent mode, a server, a cloud account, telemetry or any capability that acts
   on another machine. Features that send data off the host are opt-in and prompt first.

## Threading model, in one paragraph

The UI thread owns every HWND. A scan runs on one worker thread. It updates the atomic
counters and the mutex-guarded strings in `AppState::progress`, appends finished rows to
`progress.pendingRows`, and posts `WM_APP_SCAN_ROWS` and `WM_APP_SCAN_PROGRESS`, each at
most once in flight (the `rowsPosted` / `progressPosted` flags). When it is done it posts
`WM_APP_SCAN_FINISHED` with a payload that says what the final label is and whether to show
a dialog. The security audit posts `WM_APP_AUDIT_FINISHED` with the finished panel text.
LLM calls post `WM_APP_AI_RESPONSE` to the sidebar panel window. The settings dialog's
connection test posts `WM_APP_STATUS_TEXT` to itself. Cancel is `progress.cancelRequested`;
the scan loop checks it per file. `WM_CLOSE` sets it, then `wWinMain` joins all workers.

## Module map

| File | Owns |
|------|------|
| `PhantomRecon.cpp` | `wWinMain`, window class, `MainWndProc` dispatcher, per-message handlers, control creation |
| `MainCommands.cpp` | One function per menu / button command |
| `ScanEngine.cpp` | `AnalyzeFile`, directory and file-list walkers, CSV writers, scan threads |
| `AppState.h` | The single state struct |
| `AppMessages.h` | `WM_APP_*` ids and their payload structs |
| `BackgroundWorker.cpp` | Joinable thread pool |
| `SystemInfo.cpp` | Computer, CPU, RAM, disk text |
| `FileAnalysis.cpp` | Signatures, certificate chain, version info, attributes, DACL, entropy, size |
| `MalwareScoring.cpp` | PE imports, packer detection, composite score |
| `ScoringConfig.cpp` | INI load and save of every weight |
| `HashUtils.cpp` | MD5 and SHA-256 |
| `Baseline.cpp` | `.prbl` read and write, lookup, comparison |
| `RegistryEnumerator.cpp` | Installed-program discovery |
| `SecurityChecks.cpp`, `SecurityChecksExtra.cpp` | Host posture checks and the text report |
| `GuiComponents.cpp` | Progress bar, results list view, file dialogs, CSV parser |
| `AiSidebar.cpp`, `LLMClient.cpp` | Optional triage panel and its HTTP client |
| `SettingsDialog.cpp`, `DarkMode.cpp` | Settings window, dark palette and handlers |

## Build and verify

```powershell
msbuild PhantomRecon.sln /p:Configuration=Release /p:Platform=x64 /m /v:minimal
```

A change is not done until that command exits 0 with no new warnings, and until you have
run the exe once and exercised the path you touched. There is no automated test harness for
the GUI; say so in the commit message when a change could not be exercised.

## Style

- Win32 and the C++ standard library only. No third-party dependencies.
- `std::wstring` for anything that touches the file system or the UI. UTF-8 `std::string`
  only at the JSON boundary in `LLMClient.cpp`. Convert with `StringConv.h`.
- Debug output goes through `OutputDebugStringW` with a `[Module]` prefix. Leave existing
  debug lines in place.
- ASCII punctuation in source and docs. No typographic dashes or quotes; they break
  PowerShell on the maintainer's machine.
- No stubs, no TODO comments left behind. Finish the function or do not add it.
