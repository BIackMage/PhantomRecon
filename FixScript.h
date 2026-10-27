#pragma once

#include <string>
#include <vector>

#include "CheckCatalog.h"
#include "SecurityChecks.h"

// ---------------------------------------------------------------------------
// FixScript: the fix plan. Turns an audit's FAIL and WARNING results into a
// PowerShell script the user reads and runs, one confirmed step at a time, and a
// matching undo script. Phantom Recon never runs either of them.
//
// Pure: results in, text out (SaveFixScripts is the only function that writes).
//
// Rules the scripts keep:
//   - param([switch]$ListOnly): with -ListOnly every step is printed, nothing runs.
//   - Each command step asks "Apply this step? [y/N]"; anything but y skips it.
//     Each runs inside try/catch, so one failure does not stop the rest, and the
//     run ends with how many steps were applied, skipped and failed.
//   - A step without an exact command prints what to do and waits for Enter.
//   - Steps come in catalog order, Critical first. The undo script holds the undo
//     commands in the reverse order.
//   - Nothing restarts the PC; the end of the run says which steps need a restart.
//   - A value read from this PC (a Wi-Fi profile name, a path) enters the script only
//     as a PowerShell single-quoted literal with every quote character doubled,
//     never inside double quotes and never unquoted. A value that cannot be carried
//     exactly that way (control characters, a double quote a native program would
//     lose) turns its step into a manual one.
//   - With names hidden, every step that names something on this PC is manual (a
//     redacted name would make a broken command) and the header says so.
//   - Steps that need administrator rights make the script refuse to apply anything
//     from a normal PowerShell. -ListOnly works without them.
//   - Exact undo for registry steps (FixScriptBackup.h): a step whose commands set or
//     remove registry values (CheckInfo::scriptRegistry) first saves their state to
//     <fix script name>-backup.json, only after the user answered y. The undo step
//     puts back exactly that state when the backup has the step, and otherwise runs
//     the catalog's undo commands (the Windows default) or, when there are none,
//     becomes a step done by hand. It says which one it used.
// ---------------------------------------------------------------------------

struct FixScriptOptions {
    std::wstring generatedAt;      // shown in the header; empty: the local time now
    std::wstring scriptName;       // file name of the fix script, for the how-to lines
    std::wstring undoScriptName;   // file name of the matching undo script
    bool         redacted = false; // names were hidden in the results given
};

enum class FixStepKind { Command, Manual };

struct FixStep {
    std::wstring checkId;
    std::wstring title;
    std::wstring severity;          // "Critical" ... "Low"
    std::wstring status;            // FAIL or WARNING
    std::wstring why;               // first sentence of the explanation
    std::wstring note;              // fixScriptNote or undoScriptNote
    FixStepKind  kind = FixStepKind::Manual;
    std::vector<std::wstring> commands;      // Command: PowerShell statements, values already quoted
    std::vector<std::wstring> instructions;  // Manual: the fix (or undo) text, one entry per line
    std::vector<std::wstring> evidence;      // Manual: what the audit found, capped
    std::wstring manualReason;               // Manual: why there is no command, may be empty
    // Command steps that change registry values: backed up before the fix commands run,
    // restored exactly by the undo step. In an undo step, commands are the fallback for
    // a step without a backup, and instructions the fallback when there are no commands.
    std::vector<RegistryValueRef> registryValues;
    bool         needsAdmin = false;
    bool         needsRestart = false;
};

// The steps for the FAIL and WARNING results. undo: the undo commands, reverse order.
std::vector<FixStep> BuildFixSteps(const std::vector<SecurityCheckResult>& results, bool undo, bool redacted,
                                   const std::vector<CheckInfo>& catalog = GetCheckCatalog());

// The script text, CRLF line ends, no BOM (SaveFixScripts adds it).
std::wstring BuildFixScript(const std::vector<SecurityCheckResult>& results, const FixScriptOptions& options,
                            const std::vector<CheckInfo>& catalog = GetCheckCatalog());
std::wstring BuildUndoScript(const std::vector<SecurityCheckResult>& results, const FixScriptOptions& options,
                             const std::vector<CheckInfo>& catalog = GetCheckCatalog());

// 'value' with every single quote (ASCII and the four Unicode ones PowerShell also
// accepts) doubled.
std::wstring PowerShellQuote(const std::wstring& value);

// True when a value from this PC can go into a command exactly: not empty, at most
// 2,048 characters, no control or line-break character, no unpaired surrogate, no
// double quote (Windows PowerShell 5.1 drops those when it starts a native program),
// and no backslash at the end (5.1 quotes an argument with a space without escaping
// it, so the program would read it as an escape of the closing quote).
bool IsScriptSafeValue(const std::wstring& value);

// C:\x\plan.ps1 -> C:\x\plan-undo.ps1. A path without .ps1 gets -undo.ps1 appended.
std::wstring UndoScriptPathFor(const std::wstring& fixScriptPath);

// True when the path ends in .ps1 (any case). PowerShell's -File runs nothing else.
bool HasPs1Extension(const std::wstring& path);

// Write both scripts as UTF-8 with BOM (Windows PowerShell 5.1 reads UTF-8 without a
// BOM as ANSI). The undo script goes to UndoScriptPathFor(fixScriptPath); the backup
// file the scripts use is BackupPathFor(fixScriptPath), written only when the fix
// script runs a registry step (Phantom Recon writes no backup itself). Fills the
// file names in the options from the paths. False with error set when a file could
// not be written.
bool SaveFixScripts(const std::wstring& fixScriptPath, const std::vector<SecurityCheckResult>& results,
                    const FixScriptOptions& options, std::wstring& undoScriptPath, std::wstring& error);
