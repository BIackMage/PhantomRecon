#pragma once

#include <string>
#include <vector>

#include "CheckCatalog.h"

// ---------------------------------------------------------------------------
// CheckScripts: the PowerShell behind the fix plan, one entry per check whose
// fix is an exact command that does not depend on this PC's evidence (or, with
// perTarget, one command per exact target the check reports as data).
//
// Every line is copied from the check's fix or undo text in CheckCatalog.cpp and
// is one complete PowerShell statement. Checks whose fix is a settings page, a
// firmware switch, a choice between options, or depends on evidence the check
// only has as text have no entry: the plan shows them as steps done by hand.
// ---------------------------------------------------------------------------

struct CheckScript {
    const wchar_t* id;
    const wchar_t* fixScript;     // lines separated by \n
    const wchar_t* undoScript;    // may be empty
    bool           perTarget;
    bool           needsAdmin;
    bool           needsRestart;
    const wchar_t* fixNote;       // may be empty
    const wchar_t* undoNote;      // may be empty
    // Every registry value the fixScript lines set or remove (key as the lines write it).
    // The fix plan backs these up before the step runs and the undo plan restores them
    // exactly. Empty for steps that change no registry value directly (cmdlets such as
    // Set-MpPreference, net accounts, wevtutil). A test matches these against the lines.
    std::vector<RegistryValueRef> registry;
};

// Every entry, in no particular order. Tests check each id is in the catalog.
const std::vector<CheckScript>& GetCheckScripts();

// Copy the entries into the catalog rows with the same id. Called once by
// GetCheckCatalog; rows without an entry keep empty scripts.
void AttachCheckScripts(std::vector<CheckInfo>& catalog);
