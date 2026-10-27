#pragma once

#include <string>
#include <vector>

#include "CheckCatalog.h"

// ---------------------------------------------------------------------------
// FixScriptBackup: exact undo for the fix plan's registry steps.
//
// The PowerShell that FixScript.cpp puts into both scripts when a step changes
// registry values (CheckInfo::scriptRegistry):
//   - The fix script, after the user answers y and before the step's commands run,
//     saves the state of every declared value (existed or not, type, data) and the
//     keys on its path that do not exist yet, as one entry per step in
//     <fix script name>-backup.json next to the script (ConvertTo-Json, UTF-8).
//     An entry that was not undone yet is kept, so running the fix twice still
//     remembers the values from before the first run. -ListOnly writes nothing.
//   - The undo script, for a step with an entry, puts back exactly that state: the
//     old value with its old type (DWORD, QWORD, String, ExpandString, MultiString,
//     Binary, None), or removes the value when it did not exist, then removes the
//     keys the fix created when they are empty. It marks the entry as restored. A
//     step without an entry runs the catalog's undo commands (the Windows default).
//   - The undo script only writes values and keys its own step declares: an entry
//     that names anything else stops the step before anything is written. So does an
//     entry with a value it cannot read back (an edited file: data that is not
//     base64, a list count larger than the list, an unknown type): every value is
//     read out of the entry before the first one is written.
//   - For a value in each subkey (EachSubkey), a subkey that is gone at undo time (a
//     network adapter removed after the fix) is not created again; a subkey added
//     after the fix was never changed by it and is left alone.
//   - A value marked neverSaved (a stored password, or a setting whose old value
//     would expose passwords again) is never read into the backup nor restored; a
//     step with only such values keeps the catalog's undo.
// Values are read and written through Microsoft.Win32.RegistryKey, so the type and
// the data are exact (no environment expansion, no provider type guessing). Data is
// stored as text that survives JSON exactly: numbers in decimal, strings and bytes
// as base64 of their UTF-16 or raw bytes.
//
// Every line is constant text: nothing read from this PC enters the scripts here.
// Paths and names in the declared lists come from the catalog and are single-quoted.
// ---------------------------------------------------------------------------

// plan.ps1 -> plan-backup.json (any case of .ps1). Empty: phantom-recon-fix-backup.json.
std::wstring BackupFileNameFor(const std::wstring& fixScriptName);

// C:\x\plan.ps1 -> C:\x\plan-backup.json.
std::wstring BackupPathFor(const std::wstring& fixScriptPath);

// The helper functions a script defines once, before its first step, and the line that
// sets $backupPath to backupFileName in the script's own folder. undo picks the restore
// helpers instead of the save helpers. No line holds a double quote.
std::vector<std::wstring> BackupHelperLines(const std::wstring& backupFileName, bool undo);

// "$registryValues = @(", one hashtable per value, ")". Each line has no indent.
// Values marked neverSaved (a stored password) are left out: the backup never holds them.
std::vector<std::wstring> RegistryValuesLines(const std::vector<RegistryValueRef>& values);

// True when at least one value is backed up (not neverSaved).
bool HasSavedRegistryValues(const std::vector<RegistryValueRef>& values);

// "HKLM:\...\System  EnableLUA", "HKLM:\...\Interfaces\<each subkey>  NetbiosOptions".
std::wstring RegistryValueShown(const RegistryValueRef& value);
